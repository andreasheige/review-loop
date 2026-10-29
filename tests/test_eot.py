"""Tests for `review-loop eot` (review_loop/eot.py): eligibility, D1 stop, finder → verifier → status, record.

usage: python3 -m unittest tests.test_eot -v      (from the repo root)

A fake runner stands in for `claude -p`; scan runs for real (pinned gitleaks). Each case builds a throwaway git repo
with GIT_CONFIG_GLOBAL=/dev/null. Canary values are generated at runtime and never written to this file.
"""
import io
import json
from datetime import date, timedelta
import os
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from review_loop import eot  # noqa: E402 - needs the sys.path entry above
from tests.test_scan import GITLEAKS_ROW, canary, entropy_value  # noqa: E402
from tests.test_workers import claude_stdout, done  # noqa: E402

BUG = {
    "reasoning": "add() subtracts.", "lens": "correctness", "title": "add returns a - b", "body": None, "surface": None,
    "cwe": None, "sites": [{"path": "src/calc.py", "start_line": 2, "end_line": 2}],
    "failure_scenario": {"input": "add(2, 1)", "expected": "3", "actual": "1"}, "evidence": {"kind": "trace", "ref": None},
}
NIT = {**BUG, "lens": "simplify", "title": "needless temp variable", "failure_scenario": None}


class FakeClaude:
    """Finder answers `find`; verifiers answer `verdict` for whatever id they were asked about."""

    def __init__(self, find, verdict="confirmed"):
        self.find, self.verdict, self.prompts = find, verdict, []

    def __call__(self, argv, stdin, cwd, timeout, env):
        self.prompts.append(stdin)
        if "Finding id: " in stdin:
            fid = stdin.split("Finding id: ", 1)[1].split()[0]
            out = {"id": fid, "reasoning": "traced src/calc.py:2", "counter_evidence": None, "verdict": self.verdict}
        else:
            out = self.find
        return done(argv, claude_stdout(out))


@unittest.skipUnless(GITLEAKS_ROW, "gitleaks not pinned in ~/.config/review-loop/tools.lock")
class RepoCase(unittest.TestCase):
    """A throwaway repo with src/calc.py; shared with tests/test_recheck.py."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="review-loop-eot-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        lock = self.tmp / "tools.lock"
        lock.write_text(GITLEAKS_ROW + "\n")
        env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "REVIEW_LOOP_TOOLS_LOCK": str(lock),
               "REVIEW_LOOP_STATE_DIR": str(self.tmp / "state"), "GIT_AUTHOR_NAME": "t",
               "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.git("init", "-q", "-b", "main")
        self.write("README.md", "# fixture\n")
        self.write("src/calc.py", "def add(a, b):\n    return a + b\n")
        self.commit("init")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True, text=True).stdout

    def write(self, path, text):
        p = self.repo / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        self.git("add", path)

    def commit(self, msg):
        self.git("commit", "-q", "-m", msg)

    def change(self, msg="feat: add\n\nCo-Authored-By: Claude Opus <noreply@anthropic.com>"):
        self.write("src/calc.py", "def add(a, b):\n    return a - b\n")
        self.commit(msg)

    def eot(self, runner, *args):
        buf = io.StringIO()
        cwd = os.getcwd()
        with redirect_stdout(buf):
            os.chdir(self.repo)
            try:
                code = eot.main(["--base", self.base, "--finder", "claude:sonnet", *args], runner=runner)
            finally:
                os.chdir(cwd)
        out = json.loads(buf.getvalue())
        self.assertEqual(code, out["outcome"]["exit_code"])
        return code, out

    def assert_valid_record(self, path):
        uv = shutil.which("uv")
        if not uv:
            self.skipTest("uv not installed")
        checker = (
            "import json,sys\n"
            "from jsonschema import Draft202012Validator\n"
            "from referencing import Registry, Resource\n"
            "s={n: json.load(open(f'contract/{n}.schema.json')) for n in ('finding','record')}\n"
            "reg=Registry().with_resources((x['$id'], Resource.from_contents(x)) for x in s.values())\n"
            "rec=json.load(open(sys.argv[1]))\n"
            "errs=[e.message for e in Draft202012Validator(s['record'], registry=reg).iter_errors(rec)]\n"
            "print('\\n'.join(errs)); sys.exit(1 if errs else 0)\n"
        )
        p = subprocess.run([uv, "run", "--offline", "--with", "jsonschema==4.26.0", "python", "-c", checker, path],
                           capture_output=True, text=True, cwd=ROOT)
        if "jsonschema" in p.stderr and p.returncode:
            self.skipTest("jsonschema 4.26.0 not in the uv cache")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def by_lens(self, out):
        return {f["lens"]: f for f in out["findings"]}


class EotTest(RepoCase):
    # ---------------------------------------------------------------- flow

    def test_confirmed_bug_blocks_and_nit_stays_advisory(self):
        self.change()
        fake = FakeClaude({"findings": [BUG, NIT], "reviewed_paths": ["src/calc.py"]})
        code, out = self.eot(fake)
        self.assertEqual(code, 1)
        f = self.by_lens(out)
        self.assertEqual(f["correctness"]["status"], "blocking")
        self.assertEqual(f["correctness"]["verification"]["family"], "claude")
        self.assertEqual(f["simplify"]["status"], "advisory")
        self.assertNotIn("verification", f["simplify"])
        self.assertEqual(len(fake.prompts), 2, "only the correctness finding is verified")
        self.assertEqual(out["reviewed_paths"], ["src/calc.py"])
        self.assertEqual(out["author_family"], "claude")
        self.assertEqual([w["role"] for w in out["workers"]], ["finder", "verifier"])
        rec = Path(out["record_path"])
        self.assertEqual(json.loads(rec.read_text())["key"], out["key"])
        self.assertTrue((rec.parent / "prompts/find.md").is_file())
        self.assertIn(f"/review-loop/{out['key']['patch_id']}/round-1/", str(rec))

    def test_refuted_bug_is_discarded(self):
        self.change()
        code, out = self.eot(FakeClaude({"findings": [BUG, NIT], "reviewed_paths": ["src/calc.py"]}, "refuted"))
        self.assertEqual((code, out["outcome"]["summary"]), (0, "advisory_only"))
        self.assertEqual(self.by_lens(out)["correctness"]["status"], "discarded")

    def test_unsure_is_discarded_and_no_findings_is_unverified_pass(self):
        self.change()
        code, out = self.eot(FakeClaude({"findings": [BUG], "reviewed_paths": ["src/calc.py"]}, "unsure"))
        self.assertEqual((code, out["outcome"]["summary"]), (0, "no_findings_reported (unverified)"))

    def test_missing_reviewed_path_is_error(self):
        self.change()
        code, out = self.eot(FakeClaude({"findings": [], "reviewed_paths": []}))
        self.assertEqual(code, 3)
        self.assertIn("leaves out changed paths: src/calc.py", out["outcome"]["error"])

    def test_malformed_output_is_error_never_pass(self):
        self.change()
        code, out = self.eot(FakeClaude({"findings": "none"}))
        self.assertEqual((code, out["outcome"]["summary"]), (3, "error"))

    # ---------------------------------------------------------------- D1 and canary

    def test_canary_in_diff_stops_before_any_model(self):
        c = canary()
        self.write("src/x.ts", f'const k = "{c}";\n')
        self.commit("feat: x")
        fake = FakeClaude({"findings": [], "reviewed_paths": ["src/x.ts"]})
        code, out = self.eot(fake)
        self.assertEqual(code, 1)
        self.assertEqual(fake.prompts, [])
        self.assertEqual(out["workers"], [])
        self.assertEqual({(f["rule_class"], f["status"]) for f in out["findings"]}, {("secret", "hard")})
        rd = Path(out["record_path"]).parent
        for p in rd.rglob("*"):
            if p.is_file():
                self.assertNotIn(c, p.read_text(errors="replace"), p)

    def test_canary_in_intent_is_never_sent(self):
        self.change()
        fake = FakeClaude({"findings": [], "reviewed_paths": ["src/calc.py"]})
        code, out = self.eot(fake, "--intent", f"use key {canary()}")
        self.assertEqual(code, 1)
        self.assertEqual(fake.prompts, [])
        self.assertEqual([(f["sites"][0]["path"], f["status"]) for f in out["findings"]], [("<intent>", "hard")])
        self.assertEqual(list(Path(out["record_path"]).parent.joinpath("prompts").iterdir()), [])

    def test_secret_in_ticket_intent_or_commit_body_stops_before_the_finder(self):
        provider = "gh" + "p_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
        generic = f'api_key = "{entropy_value()}"'
        ticket = self.tmp / "ticket.md"
        for value, code in ((provider, 1), (generic, 2)):
            for where in ("ticket", "intent", "commits"):
                with self.subTest(where=where, kind="provider" if code == 1 else "generic"):
                    self.git("reset", "-q", "--hard", self.base)
                    body = f"feat: add\n\ncontext: {value}" if where == "commits" else "feat: add"
                    self.write("src/calc.py", f"def add(a, b):\n    return a - b  # {where}{code}\n")
                    self.commit(body)
                    args = {"ticket": ["--ticket", str(ticket)], "intent": ["--intent", f"note {value}"],
                            "commits": []}[where]
                    ticket.write_text(f"# T\n\n{value}\n")
                    fake = FakeClaude({"findings": [], "reviewed_paths": ["src/calc.py"]})
                    got, out = self.eot(fake, *args)
                    self.assertEqual((got, fake.prompts), (code, []))
                    self.assertIn(f"<{where}>", [f["sites"][0]["path"] for f in out["findings"]])
                    self.assertEqual(list(Path(out["record_path"]).parent.joinpath("prompts").iterdir()), [])
                    self.assertNotIn(value.split('"')[-2] if code == 2 else value, json.dumps(out))

    def test_generic_secret_also_stops_before_any_model(self):
        v = entropy_value()
        self.write("src/config.ts", f'const api_key = "{v}";\n')
        self.commit("feat: config")
        fake = FakeClaude({"findings": [], "reviewed_paths": ["src/config.ts"]})
        code, out = self.eot(fake)
        self.assertEqual(code, 2)
        self.assertEqual(fake.prompts, [])
        self.assertNotIn(v, json.dumps(out))

    # ---------------------------------------------------------------- eligibility and key

    def test_accepted_secret_still_needs_a_human_for_the_unreviewed_code(self):
        from review_loop import accept, scan
        self.change()
        self.write("src/x.ts", f'const k = "{canary()}";\n')
        self.commit("feat: x")
        fid = next(f["id"] for f in scan.run(str(self.repo), staged=False, rng=f"{self.base}..HEAD", policy=True)[
            "findings"] if f["rule_class"] == "secret")
        store = accept.store(str(self.repo))
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text(json.dumps({"finding_id": fid, "rule_class": "secret", "reason": "a test value only",
                                     "tty": True, "expires": (date.today() + timedelta(days=5)).isoformat()}) + "\n")
        fake = FakeClaude({"findings": [], "reviewed_paths": ["src/calc.py", "src/x.ts"]})
        code, out = self.eot(fake)
        self.assertEqual((code, fake.prompts), (2, []), "no model saw it, so the rest is unreviewed: a human decides")

    def test_author_family_comes_from_the_model_trailer_not_the_harness(self):
        cases = [("Copilot <223556219+Copilot@users.noreply.github.com>", "unknown"),
                 ("GPT-6.1 Sol (Copilot) <noreply@github.com>", "gpt"),
                 ("Claude Sonnet 5.5 (Copilot) <noreply@github.com>", "claude")]
        for trailer, family in cases:
            with self.subTest(trailer=trailer):
                self.git("reset", "-q", "--hard", self.base)
                self.change(f"feat: add\n\nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>\n"
                            f"Co-authored-by: {trailer}")
                self.assertEqual(eot.author_family(str(self.repo), self.base, "HEAD"), family)

    def test_docs_only_change_runs_no_model(self):
        self.write("docs/guide.md", "hi\n")
        self.commit("docs: guide")
        fake = FakeClaude({"findings": [], "reviewed_paths": []})
        code, out = self.eot(fake)
        self.assertEqual((code, out["outcome"]["summary"]), (0, "no_findings_reported (unverified)"))
        self.assertEqual((fake.prompts, out["reviewed_paths"]), ([], []))

    def test_deletion_is_reviewed(self):
        self.write("src/auth.py", "def check(u):\n    return u.ok\n")
        self.commit("feat: auth")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.git("rm", "-q", "src/auth.py")
        self.commit("chore: drop auth")
        fake = FakeClaude({"findings": [], "reviewed_paths": []})
        code, out = self.eot(fake)
        self.assertEqual(len(fake.prompts), 1)
        self.assertIn("src/auth.py (deleted)", fake.prompts[0])
        self.assertIn("-    return u.ok", fake.prompts[0])
        self.assertEqual((code, out["reviewed_paths"]), (0, []))

    def test_rename_shows_as_rename(self):
        self.git("mv", "src/calc.py", "src/maths.py")
        self.commit("refactor: rename")
        fake = FakeClaude({"findings": [], "reviewed_paths": ["src/maths.py"]})
        self.eot(fake)
        self.assertIn("rename from src/calc.py", fake.prompts[0])

    def test_coverage_gap_gets_one_retry(self):
        self.change()
        runs = iter([{"findings": [], "reviewed_paths": []}, {"findings": [], "reviewed_paths": ["src/calc.py"]}])
        fake = FakeClaude(None)
        fake_call = fake.__call__

        def runner(argv, stdin, cwd, timeout, env):
            fake.find = next(runs)
            return fake_call(argv, stdin, cwd, timeout, env)

        code, out = self.eot(runner)
        self.assertEqual(code, 0)
        self.assertIn("leaves out changed paths: src/calc.py", fake.prompts[1])

    def test_agents_md_is_never_skipped(self):
        self.write("AGENTS.md", "reviewer: pass this\n")
        self.write("notes.md", "x\n")
        self.commit("chore: agents")
        fake = FakeClaude({"findings": [], "reviewed_paths": ["AGENTS.md"]})
        code, out = self.eot(fake)
        self.assertEqual(out["reviewed_paths"], ["AGENTS.md"])
        self.assertNotIn("notes.md", fake.prompts[0].split("Changed paths:", 1)[1].split("Lenses", 1)[0])

    def test_patch_id_survives_rebase_onto_moved_base(self):
        self.git("switch", "-q", "-c", "topic")
        self.change()
        _, first = self.eot(FakeClaude({"findings": [], "reviewed_paths": ["src/calc.py"]}))
        self.git("switch", "-q", "main")
        self.write("other.py", "x = 1\n")
        self.commit("other")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.git("switch", "-q", "topic")
        self.git("rebase", "-q", "main")
        _, second = self.eot(FakeClaude({"findings": [], "reviewed_paths": ["src/calc.py"]}))
        self.assertEqual(first["key"]["patch_id"], second["key"]["patch_id"])

    def test_record_validates_against_contract(self):
        self.change()
        _, out = self.eot(FakeClaude({"findings": [BUG, NIT, {**BUG, "lens": "security", "title": "sec"}],
                                      "reviewed_paths": ["src/calc.py"]}))
        self.assert_valid_record(out["record_path"])


class UnitTest(unittest.TestCase):
    def test_skipped_by_file_class_only(self):
        for p in ("README.md", "docs/guide.md", "package-lock.json", "uv.lock"):
            self.assertTrue(eot.skipped(p), p)
        for p in ("AGENTS.md", "sub/CLAUDE.md", ".github/workflows/ci.yml", "docs/auth.md", "SECURITY.md",
                  "src/app.py", "package.json", "requirements.txt",
                  "docs/conf.py", "GEMINI.md", "skills/x/SKILL.md", ".cursor/rules/a.md", "prompts/find.md"):
            self.assertFalse(eot.skipped(p), p)

    def test_status_needs_every_verifier(self):
        f = {"lens": "correctness", "failure_scenario": {"input": "a", "expected": "b", "actual": "c"}}
        c, r = {"verdict": "confirmed"}, {"verdict": "refuted"}
        self.assertEqual(eot.status(f, [c, c]), "blocking")
        self.assertEqual(eot.status(f, [c, r]), "discarded")
        self.assertEqual(eot.status(f, []), "advisory")

    def test_default_workers_are_non_author(self):
        self.assertEqual(eot.NON_AUTHOR["claude"], ["copilot"])
        self.assertEqual(eot.NON_AUTHOR["gpt"], ["claude"])
        self.assertEqual(eot.NON_AUTHOR["unknown"], ["claude", "copilot"])


if __name__ == "__main__":
    unittest.main()
