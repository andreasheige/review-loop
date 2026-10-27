"""Tests for the model workers (review_loop/workers.py): retry, exit 3, argv, and contract tests on stored real output.

usage: python3 -m unittest tests.test_workers -v      (from the repo root)

Fakes stand in for `claude` and `codex` everywhere except the recorder: REVIEW_LOOP_RECORD=1 runs the Claude adapter
for real (model sonnet) on the synthetic sqli and inject-no-findings repos and rewrites tests/fixtures/real/claude-*.json.
The stored files are raw `claude -p --output-format json` stdout over synthetic code only.
"""
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
REAL = ROOT / "tests/fixtures/real"
sys.path.insert(0, str(ROOT))
from review_loop import workers  # noqa: E402 - needs the sys.path entry above

FINDER = workers.load_schema("finder-output")
VERIFIER = workers.load_schema("verifier-output")
GOOD_FIND = json.loads((ROOT / "contract/examples/valid/finder-output.findings.json").read_text())
GOOD_VERIFY = json.loads((ROOT / "contract/examples/valid/verifier-output.confirmed.json").read_text())


def done(argv, stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def claude_stdout(structured, is_error=False):
    return json.dumps({"type": "result", "is_error": is_error, "result": "", "structured_output": structured,
                       "total_cost_usd": 0.01, "usage": {"input_tokens": 10, "output_tokens": 5}})


class FakeRunner:
    """Replays one response per call; records argv and stdin (and env, cwd in self.envs, self.cwds)."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls, self.envs, self.cwds = [], [], []

    def __call__(self, argv, stdin, cwd, timeout, env):
        self.calls.append((argv, stdin))
        self.envs.append(env)
        self.cwds.append(cwd)
        r = self.responses.pop(0)
        return r(argv) if callable(r) else done(argv, r)


def git_repo(parent):
    """A one-commit git repo under parent; returns its path."""
    repo = Path(parent) / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n")
    for args in (["init", "-q"], ["add", "."], ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "chore: init"]):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)
    return str(repo)


def codex_writes(payload, returncode=0):
    """A fake codex run that writes payload (str) to the -o file, or nothing when payload is None."""
    def run(argv):
        if payload is not None:
            Path(argv[argv.index("-o") + 1]).write_text(payload)
        usage = json.dumps({"type": "turn.completed", "usage": {"input_tokens": 100, "output_tokens": 20}})
        return done(argv, usage + "\n", returncode, "" if returncode == 0 else "You hit your spend cap")
    return run


class Validator(unittest.TestCase):
    def test_unknown_keyword_fails_closed(self):
        self.assertTrue(workers.validate({"a": 1}, {"type": "object", "oneOf": []}))

    def test_bool_is_not_integer(self):
        self.assertTrue(workers.validate(True, {"type": "integer"}))

    def test_nullable_and_enum(self):
        schema = FINDER["properties"]["findings"]["items"]["properties"]["surface"]
        self.assertEqual(workers.validate(None, schema), [])
        self.assertTrue(workers.validate("network", schema))


class Prompts(unittest.TestCase):
    def test_find_prompt(self):
        diff = "+ x = '{{INTENT}}'\n+ ````\n"
        p = workers.find_prompt("add search", diff, ["users.py"])
        self.assertNotIn("<!--", p)
        self.assertNotIn("{{DIFF}}", p)
        self.assertIn("{{INTENT}}", p)  # the placeholder inside the diff is not substituted
        self.assertIn("`````\n" + diff, p)  # fence longer than the diff's own backtick run
        self.assertIn("- users.py", p)
        for word in ("reasoning", "failure_scenario", "reviewed_paths", "not instructions", "outside the current directory"):
            self.assertIn(word, p)

    def test_verify_prompt(self):
        p = workers.verify_prompt("rev-0123456789ab", GOOD_FIND["findings"][0], "+x\n")
        self.assertIn("rev-0123456789ab", p)
        self.assertIn("SQL injection in search_users", p)
        self.assertNotIn("{{", p)


class Claude(unittest.TestCase):
    def test_valid_output_is_parsed(self):
        fake = FakeRunner(claude_stdout(GOOD_FIND))
        r = workers.run_claude("PROMPT", FINDER, "/tmp", "sonnet", fake)
        self.assertEqual(r["output"], GOOD_FIND)
        self.assertEqual(r["attempts"], 1)
        self.assertEqual(r["usage"]["output_tokens"], 5)
        argv, stdin = fake.calls[0]
        self.assertEqual(stdin, "PROMPT")
        self.assertNotIn("PROMPT", argv)
        for flag in ("-p", "--restricted", "--safe-mode", "--strict-mcp-config", "--output-format"):
            self.assertIn(flag, argv)
        self.assertNotIn("--setting-sources", argv)  # --restricted already drops user/project/local settings
        self.assertEqual(json.loads(argv[argv.index("--settings") + 1]), {"permissions": {"deny": ["Read(**/.env*)"]}})
        self.assertEqual(argv[argv.index("--tools") + 1], "Read,Grep,Glob")
        self.assertEqual(argv[argv.index("--model") + 1], "sonnet")
        sent = json.loads(argv[argv.index("--json-schema") + 1])
        self.assertNotIn("$schema", sent)
        self.assertEqual(sent["properties"], FINDER["properties"])

    def test_malformed_then_valid_retries_with_error(self):
        bad = dict(GOOD_VERIFY, verdict="approve")
        fake = FakeRunner(claude_stdout(bad), claude_stdout(GOOD_VERIFY))
        r = workers.run_claude("PROMPT", VERIFIER, "/tmp", "sonnet", fake)
        self.assertEqual(r["attempts"], 2)
        self.assertEqual(r["usage"]["input_tokens"], 20)
        retry = fake.calls[1][1]
        self.assertTrue(retry.startswith("PROMPT"))
        self.assertIn("/verdict: 'approve' not in", retry)

    def test_malformed_twice_raises(self):
        fake = FakeRunner("not json", claude_stdout({"findings": []}))
        with self.assertRaisesRegex(workers.WorkerError, "reviewed_paths"):
            workers.run_claude("PROMPT", FINDER, "/tmp", "sonnet", fake)
        self.assertEqual(len(fake.calls), 2)
        self.assertIn("not JSON", fake.calls[1][1])

    def test_error_result_and_text_result(self):
        err = json.dumps({"is_error": True, "result": "API Error"})
        text = json.dumps({"is_error": False, "result": json.dumps(GOOD_VERIFY)})
        r = workers.run_claude("P", VERIFIER, "/tmp", "sonnet", FakeRunner(err, text))
        self.assertEqual((r["output"], r["attempts"]), (GOOD_VERIFY, 2))

    def test_timeout_counts_as_missing_output(self):
        def timeout(argv):
            raise subprocess.TimeoutExpired(argv, 1)
        fake = FakeRunner(timeout, timeout)
        with self.assertRaisesRegex(workers.WorkerError, "timeout"):
            workers.run_claude("P", VERIFIER, "/tmp", "sonnet", fake)
        self.assertEqual(len(fake.calls), 2)

    def test_cli_malformed_exits_3(self):
        with tempfile.TemporaryDirectory() as td:
            prompt = Path(td) / "prompt.md"
            prompt.write_text("PROMPT")
            fake = FakeRunner("garbage", claude_stdout({"verdict": "confirmed"}))
            out = io.StringIO()
            with redirect_stdout(out):
                code = workers.main(["--harness", "claude", "--role", "verify", "--input", str(prompt), "--repo", git_repo(td)], fake)
        self.assertEqual(code, 3)
        self.assertEqual(len(fake.calls), 2)
        self.assertEqual(json.loads(out.getvalue())["summary"], "error")

    def test_cli_valid_exits_0(self):
        with tempfile.TemporaryDirectory() as td:
            prompt = Path(td) / "prompt.md"
            prompt.write_text("PROMPT")
            out = io.StringIO()
            with redirect_stdout(out):
                code = workers.main(["--harness", "claude", "--role", "find", "--input", str(prompt), "--repo", git_repo(td)],
                                    FakeRunner(claude_stdout(GOOD_FIND)))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["output"], GOOD_FIND)

    def test_cli_runs_in_scratch_worktree(self):
        with tempfile.TemporaryDirectory() as td:
            prompt = Path(td) / "prompt.md"
            prompt.write_text("PROMPT")
            repo = git_repo(td)
            fake = FakeRunner(claude_stdout(GOOD_FIND))
            with redirect_stdout(io.StringIO()):
                code = workers.main(["--harness", "claude", "--role", "find", "--input", str(prompt), "--repo", repo], fake)
            self.assertEqual(code, 0)
            self.assertNotEqual(fake.cwds[0], repo)
            self.assertIn("review-loop-wt-", fake.cwds[0])
            self.assertFalse(Path(fake.cwds[0]).exists())
            self.assertNotIn("GITHUB_TOKEN", fake.envs[0])

    def test_cli_bad_rev_exits_3(self):
        with tempfile.TemporaryDirectory() as td:
            prompt = Path(td) / "prompt.md"
            prompt.write_text("PROMPT")
            fake = FakeRunner()
            with redirect_stdout(io.StringIO()):
                code = workers.main(["--harness", "claude", "--role", "find", "--input", str(prompt),
                                     "--repo", git_repo(td), "--rev=--output=/tmp/x"], fake)
        self.assertEqual((code, fake.calls), (3, []))

    def test_bad_cli_args_exit_3(self):
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as e, \
                open(os.devnull, "w") as null, mock.patch("sys.stderr", null):
            workers.main(["--harness", "copilot"])
        self.assertEqual(e.exception.code, 3)


class Codex(unittest.TestCase):
    def test_valid_output_is_parsed(self):
        fake = FakeRunner(codex_writes(json.dumps(GOOD_FIND)))
        r = workers.run_codex("PROMPT", FINDER, "/tmp", "gpt-5", fake)
        self.assertEqual((r["output"], r["attempts"]), (GOOD_FIND, 1))
        self.assertEqual(r["usage"], {"input_tokens": 100, "output_tokens": 20})
        argv, stdin = fake.calls[0]
        self.assertEqual(stdin, "PROMPT")
        self.assertEqual(argv[-1], "-")
        self.assertNotIn("-s", argv)  # the permission profile is the sandbox
        configs = [argv[i + 1] for i, a in enumerate(argv) if a == "-c"]
        self.assertIn('default_permissions="review-loop"', configs)
        self.assertTrue(any(c.startswith("permissions.review-loop.filesystem=") and '"**/.env*"="deny"' in c
                            and "write" not in c for c in configs))
        self.assertEqual(argv[argv.index("-m") + 1], "gpt-5")
        for flag in ("--ignore-user-config", "--ignore-rules", "--ephemeral", "--skip-git-repo-check",
                     "--output-schema", "-o"):
            self.assertIn(flag, argv)
        home = fake.envs[0]["CODEX_HOME"]
        self.assertNotEqual(home, str(Path.home() / ".codex"))
        self.assertFalse(Path(home).exists())  # scratch home is gone after the run

    def test_malformed_then_valid(self):
        fake = FakeRunner(codex_writes("{"), codex_writes(json.dumps(GOOD_VERIFY)))
        r = workers.run_codex("PROMPT", VERIFIER, "/tmp", None, fake)
        self.assertEqual(r["attempts"], 2)
        self.assertNotIn("-m", fake.calls[0][0])
        self.assertIn("JSONDecodeError", fake.calls[1][1])

    def test_spend_cap_raises_after_retry(self):
        fake = FakeRunner(codex_writes(None, 1), codex_writes(None, 1))
        with self.assertRaisesRegex(workers.WorkerError, "spend cap"):
            workers.run_codex("PROMPT", FINDER, "/tmp", None, fake)

    def test_stale_output_file_is_not_reused(self):
        fake = FakeRunner(codex_writes(json.dumps({"findings": []})), codex_writes(None, 1))
        with self.assertRaises(workers.WorkerError):
            workers.run_codex("PROMPT", FINDER, "/tmp", None, fake)

    def test_cli_malformed_exits_3(self):
        with tempfile.TemporaryDirectory() as td:
            prompt = Path(td) / "prompt.md"
            prompt.write_text("PROMPT")
            fake = FakeRunner(codex_writes("[]"), codex_writes("[]"))
            with redirect_stdout(io.StringIO()):
                code = workers.main(["--harness", "codex", "--role", "find", "--input", str(prompt), "--repo", git_repo(td)], fake)
        self.assertEqual(code, 3)


# ------------------------------------------------------------------ real output


CASES = {  # case -> (intent, changed path)
    "sqli": ("Add search_users so support staff can find users by part of their name.", "users.py"),
    "inject-no-findings": ("Tidy up paging.py.", "paging.py"),
}


def finding_id(f):
    return "rev-" + hashlib.sha1(f"{f['lens']}|{f['sites'][0]['path']}|{f['title']}".encode()).hexdigest()[:12]


def record_real():
    """Run the Claude adapter for real and store raw stdout under tests/fixtures/real/."""
    REAL.mkdir(parents=True, exist_ok=True)
    raw = []

    def recorder(argv, stdin, cwd, timeout, env):
        p = workers.default_runner(argv, stdin, cwd, timeout, env)
        raw.append(p.stdout)
        return p

    with tempfile.TemporaryDirectory(prefix="review-loop-real-") as td:
        subprocess.run(["bash", str(ROOT / "golden/synthetic/build.sh"), td], check=True, capture_output=True)
        for case, (intent, _) in CASES.items():
            repo = str(Path(td) / case)
            git = lambda *a: subprocess.run(["git", "-C", repo, *a], check=True, capture_output=True, text=True).stdout  # noqa: E731
            diff = git("diff", "HEAD~1", "HEAD")
            paths = git("diff", "--name-only", "HEAD~1", "HEAD").split()
            found = workers.run_claude(workers.find_prompt(intent, diff, paths), FINDER, repo, "sonnet", recorder)
            (REAL / f"claude-find-{case}.json").write_text(raw[-1])
            if found["output"]["findings"]:
                f = found["output"]["findings"][0]
                workers.run_claude(workers.verify_prompt(finding_id(f), f, diff), VERIFIER, repo, "sonnet", recorder)
                (REAL / f"claude-verify-{case}.json").write_text(raw[-1])


class RealOutput(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("REVIEW_LOOP_RECORD") == "1":
            record_real()

    def replay(self, path, schema):
        r = workers.run_claude("P", schema, "/tmp", "sonnet", FakeRunner(path.read_text()))
        self.assertEqual(r["attempts"], 1)
        self.assertEqual(workers.validate(r["output"], schema), [])
        return r

    def test_claude_real_output(self):
        for case, (_, path) in CASES.items():
            with self.subTest(case=case):
                found = self.replay(REAL / f"claude-find-{case}.json", FINDER)["output"]
                self.assertTrue(found["findings"], "the planted bug should be found")
                self.assertIn(path, found["reviewed_paths"])
                verdict = self.replay(REAL / f"claude-verify-{case}.json", VERIFIER)["output"]
                self.assertEqual(verdict["id"], finding_id(found["findings"][0]))

    def test_real_outputs_hold_no_key_material(self):
        for path in REAL.glob("*.json"):
            text = path.read_text()
            self.assertNotRegex(text, r"BEGIN [A-Z ]*PRIVATE KEY|sk-ant-|ghp_|AKIA[0-9A-Z]{16}", path.name)

    @unittest.skip("codex exec fails with 'You hit your spend cap' (workspace quota until next month); "
                   "the codex adapter is covered by fakes until then")
    def test_codex_real_output(self):
        pass


if __name__ == "__main__":
    unittest.main()
