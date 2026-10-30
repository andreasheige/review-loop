"""Fixture tests for `review-loop gate` (the pre-push scan).

usage: python3 -m unittest tests.test_gate -v      (from the repo root)

Each case has a work repo and a bare `origin`, both with GIT_CONFIG_GLOBAL=/dev/null so no global hook runs.
The gate gets the pre-push stdin lines the test builds, as git would hand them to the hook.
"""
import datetime
import io
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock
from pathlib import Path

from review_loop import eot
from tests.test_scan import BIN, GITLEAKS_ROW, canary

ZERO = "0" * 40


@unittest.skipUnless(GITLEAKS_ROW, "gitleaks not pinned in ~/.config/review-loop/tools.lock")
class GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="review-loop-gate-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.lock = self.tmp / "tools.lock"
        self.lock.write_text(GITLEAKS_ROW + "\n")
        self.mode_file = self.tmp / "gate-mode"
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1",
                        REVIEW_LOOP_TOOLS_LOCK=str(self.lock), REVIEW_LOOP_STATE_DIR=str(self.tmp / "state"),
                        REVIEW_LOOP_GATE_MODE_FILE=str(self.mode_file), HOME=str(self.tmp / "home"),
                        GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
        self.secrets = []
        self.origin = self.tmp / "origin.git"
        self.repo = self.tmp / "repo"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.origin)], env=self.env, check=True)
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("remote", "add", "origin", str(self.origin))
        self.commit("README.md", "# fixture\n")
        self.git("push", "-q", "origin", "main")
        self.git("switch", "-q", "-c", "feat")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, env=self.env, check=True, capture_output=True,
                              text=True).stdout.strip()

    def commit(self, path, text):
        p = self.repo / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        self.git("add", path)
        self.git("commit", "-q", "-m", f"add {path}")
        return self.git("rev-parse", "HEAD")

    def add_canary(self):
        c = canary()
        self.secrets.append(c)
        return self.commit("src/x.ts", "".join(f"export const v{i} = {i};\n" for i in range(20)) + f'export const t = "{c}";\n')

    def gate(self, lines, *args, remote="origin", env=None):
        p = subprocess.run([str(BIN), "gate", remote, *args], cwd=self.repo, env={**self.env, **(env or {})},
                           input="".join(f"{l}\n" for l in lines), capture_output=True, text=True)
        for s in self.secrets:
            self.assertNotIn(s, p.stdout + p.stderr, "secret value leaked into output")
        self.assertEqual(p.stdout, "", "the hook's stdout must stay empty")
        return p.returncode, p.stderr

    def log(self):
        return [json.loads(l) for l in (self.tmp / "state/gate.jsonl").read_text().splitlines()]

    def test_clean_new_branch_passes_quietly(self):
        sha = self.commit("src/ok.py", "def add(a, b):\n    return a + b\n")
        self.assertEqual(self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"]), (0, ""))
        self.assertEqual(self.log()[-1]["exit"], 0)
        self.assertIsInstance(self.log()[-1]["ms"], int)

    def test_canary_warns_in_warn_mode_and_refuses_in_block_mode(self):
        sha = self.add_canary()
        line = [f"refs/heads/feat {sha} refs/heads/feat {ZERO}"]
        rc, err = self.gate(line)
        self.assertEqual(rc, 0)
        self.assertIn("warn mode", err)
        self.assertIn("refs/heads/feat", err)
        self.mode_file.write_text("block\n")
        rc, err = self.gate(line)
        self.assertEqual(rc, 1)
        self.assertIn("Push refused", err)
        self.assertEqual([l["mode"] for l in self.log()], ["warn", "block"])
        self.assertIn("secret", self.log()[-1]["classes"])

    def test_block_flag_cannot_be_weakened_by_the_mode_file(self):
        sha = self.add_canary()
        self.mode_file.write_text("warn\n")
        self.assertEqual(self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"], "--block")[0], 1)

    def test_forged_tracking_ref_is_ignored(self):
        sha = self.add_canary()
        # make the canary look already pushed: local tracking refs claim origin has it
        self.git("update-ref", "refs/remotes/origin/main", sha)
        self.git("update-ref", "refs/remotes/origin/feat", sha)
        self.mode_file.write_text("block\n")
        self.assertEqual(self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"])[0], 1)

    def test_only_commits_new_to_the_remote_are_scanned(self):
        old = self.add_canary()
        self.git("push", "-q", "origin", "feat")  # no hooks in the fixture: the canary is on origin already
        new = self.commit("src/ok.py", "x = 1\n")
        self.mode_file.write_text("block\n")
        self.assertEqual(self.gate([f"refs/heads/feat {new} refs/heads/feat {old}"]), (0, ""))

    def test_first_push_to_an_empty_remote_scans_every_commit(self):
        sha = self.add_canary()
        self.commit("src/ok.py", "x = 1\n")
        head = self.git("rev-parse", "HEAD")
        empty = self.tmp / "empty.git"
        subprocess.run(["git", "init", "-q", "--bare", str(empty)], env=self.env, check=True)
        self.mode_file.write_text("block\n")
        rc, err = self.gate([f"refs/heads/main {head} refs/heads/main {ZERO}"], remote=str(empty))
        self.assertEqual(rc, 1)
        self.assertIn("reviewloop-canary", err)
        self.assertNotEqual(sha, head)

    def test_push_url_is_asked_not_the_fetch_url(self):
        sha = self.add_canary()
        self.git("push", "-q", "origin", f"{sha}:refs/heads/main")  # the fetch side already has the canary
        empty = self.tmp / "push-target.git"
        subprocess.run(["git", "init", "-q", "--bare", str(empty)], env=self.env, check=True)
        self.mode_file.write_text("block\n")
        rc, err = self.gate([f"refs/heads/main {sha} refs/heads/main {ZERO}"], str(empty))
        self.assertEqual(rc, 1)
        self.assertIn("reviewloop-canary", err)

    def test_hidden_unicode_added_and_removed_within_the_push_is_found(self):
        base = self.git("rev-parse", "HEAD")
        self.commit("src/a.py", "x = 1  # \u202e\n")
        tip = self.commit("src/a.py", "x = 1\n")
        self.mode_file.write_text("block\n")
        rc, err = self.gate([f"refs/heads/feat {tip} refs/heads/feat {base}"])
        self.assertEqual(rc, 1)
        self.assertIn("unicode", err)

    def test_hidden_unicode_in_a_merge_resolution_is_found(self):
        base = self.git("rev-parse", "HEAD")
        self.commit("src/a.py", "a = 1\n")
        self.git("switch", "-q", "-c", "side", base)
        self.commit("src/b.py", "b = 1\n")
        self.git("switch", "-q", "feat")
        self.git("merge", "-q", "--no-ff", "--no-commit", "side")
        (self.repo / "src/a.py").write_text("a = 1  # \u202e\n", encoding="utf-8")
        self.git("add", "src/a.py")
        self.git("commit", "-q", "-m", "merge side")
        tip = self.commit("src/a.py", "a = 1\n")
        self.mode_file.write_text("block\n")
        rc, err = self.gate([f"refs/heads/feat {tip} refs/heads/feat {base}"])
        self.assertEqual(rc, 1)
        self.assertIn("unicode", err)

    def test_binary_file_with_nul_bytes_in_a_multi_commit_push(self):
        base = self.git("rev-parse", "HEAD")
        (self.repo / "asset.bin").write_bytes(b"A\x00\xff\n@commit " + b"0" * 40 + b"\n")
        self.git("add", "asset.bin")
        self.git("commit", "-q", "-m", "add asset")
        tip = self.commit("src/ok.py", "x = 1\n")
        self.mode_file.write_text("block\n")
        self.assertEqual(self.gate([f"refs/heads/feat {tip} refs/heads/feat {base}"]), (0, ""))

    # review records (review-loop.gate)
    def record(self, sha, findings=(), exit_code=0, rnd=1):
        base = self.git("merge-base", "main", sha)
        pid = eot.patch_id(str(self.repo), base, sha)
        d = self.repo / ".git" / "review-loop" / pid / f"round-{rnd}"
        d.mkdir(parents=True)
        (d / "record.json").write_text(json.dumps({
            "command": "eot" if rnd == 1 else "recheck", "round": rnd, "head": sha, "branch": "feat",
            "created_at": f"2026-10-29T00:00:0{rnd}+00:00", "findings": list(findings),
            "outcome": {"exit_code": exit_code}}))

    def test_review_record_missing_warns_then_refuses(self):
        self.git("config", "review-loop.gate", "true")
        sha = self.commit("src/ok.py", "x = 1\n")
        line = [f"refs/heads/feat {sha} refs/heads/feat {ZERO}"]
        rc, err = self.gate(line)
        self.assertEqual(rc, 0)
        self.assertIn("no review record", err)
        self.mode_file.write_text("block\n")
        self.assertEqual(self.gate(line)[0], 1)
        self.assertEqual(self.log()[-1]["reviews"], ["missing"])

    def test_review_record_passing_round_passes(self):
        self.git("config", "review-loop.gate", "true")
        sha = self.commit("src/ok.py", "x = 1\n")
        blocking = {"id": "rev-aaaaaaaaaaaa", "status": "blocking", "rule_class": None}
        self.record(sha, [blocking], exit_code=1, rnd=1)
        self.record(sha, [{**blocking, "status": "discarded"}], exit_code=0, rnd=2)
        self.mode_file.write_text("block\n")
        self.assertEqual(self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"]), (0, ""))

    def test_review_record_with_open_finding_refuses(self):
        self.git("config", "review-loop.gate", "true")
        sha = self.commit("src/ok.py", "x = 1\n")
        self.record(sha, [{"id": "rev-bbbbbbbbbbbb", "status": "needs_human", "rule_class": "control-weakening"}], exit_code=2)
        self.mode_file.write_text("block\n")
        rc, err = self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"])
        self.assertEqual(rc, 1)
        self.assertIn("1 open finding", err)

    def test_review_skip_needs_a_terminal_and_never_skips_the_scan(self):
        self.git("config", "review-loop.gate", "true")
        clean = self.commit("src/ok.py", "x = 1\n")
        self.mode_file.write_text("block\n")
        skip = {"REVIEW_LOOP_SKIP": "1"}
        # an agent's push has no /dev/tty: the skip is not honoured
        self.assertEqual(self.gate([f"refs/heads/feat {clean} refs/heads/feat {ZERO}"], env=skip)[0], 1)
        base = self.git("merge-base", "main", clean)
        with mock.patch.dict(os.environ, {**self.env, **skip}, clear=True):
            from review_loop import gate
            self.assertEqual(gate.review_state(str(self.repo), base, clean, confirm=lambda q: True)[0], "skipped")
        self.assertIn(clean, (self.tmp / "state/skips.log").read_text())
        dirty = self.add_canary()
        self.assertEqual(self.gate([f"refs/heads/feat {dirty} refs/heads/feat {ZERO}"], env=skip)[0], 1)

    def test_review_record_for_other_content_with_the_same_patch_id_is_not_enough(self):
        self.git("config", "review-loop.gate", "true")
        self.commit("src/auth.py", "def delete(u):\n    if u.admin:\n        log(u)\n")
        self.git("push", "-q", "origin", "HEAD:main")
        base = self.git("rev-parse", "HEAD")
        reviewed = self.commit("src/auth.py", "def delete(u):\n    if u.admin:\n        log(u)\n        delete_all()\n")
        self.record(reviewed)
        self.git("reset", "-q", "--hard", base)
        pushed = self.commit("src/auth.py", "def delete(u):\n    if u.admin:\n        log(u)\n    delete_all()\n")
        self.assertEqual(eot.patch_id(str(self.repo), base, reviewed), eot.patch_id(str(self.repo), base, pushed),
                         "the fixture must be a real patch-id collision")
        self.mode_file.write_text("block\n")
        rc, err = self.gate([f"refs/heads/feat {pushed} refs/heads/feat {ZERO}"])
        self.assertEqual(rc, 1)
        self.assertIn("no review record for this content", err)

    def test_opt_in_cannot_be_switched_off_with_git_c(self):
        self.git("config", "review-loop.gate", "true")
        sha = self.commit("src/ok.py", "x = 1\n")
        self.mode_file.write_text("block\n")
        off = {"GIT_CONFIG_PARAMETERS": "'review-loop.gate'='false'", "GIT_CONFIG_COUNT": "1",
               "GIT_CONFIG_KEY_0": "review-loop.gate", "GIT_CONFIG_VALUE_0": "false"}
        self.assertEqual(self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"], env=off)[0], 1)

    def test_mode_override_cannot_weaken_block_and_garbled_mode_blocks(self):
        sha = self.add_canary()
        home_mode = self.tmp / "home/.config/review-loop/gate-mode"
        home_mode.parent.mkdir(parents=True)
        home_mode.write_text("block\n")
        self.mode_file.write_text("warn\n")
        self.assertEqual(self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"])[0], 1)
        home_mode.write_text("blocc\n")
        self.assertEqual(self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"])[0], 1)

    def test_docs_or_lockfile_only_push_needs_no_review_record(self):
        self.git("config", "review-loop.gate", "true")
        self.mode_file.write_text("block\n")
        sha = self.commit("notes/today.md", "# Today\n\nNotes.\n")
        self.assertEqual(self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"]), (0, ""))
        self.git("switch", "-q", "main")
        self.commit("src/calc.py", "def total(xs):\n    return sum(xs)\n")
        self.git("push", "-q", "origin", "main")
        self.git("switch", "-q", "-c", "renamed")
        (self.repo / "notes").mkdir(exist_ok=True)
        self.git("mv", "src/calc.py", "notes/calc.md")
        self.git("commit", "-q", "-m", "move")
        sha = self.git("rev-parse", "HEAD")  # code on main renamed to a doc: still a code change
        rc, err = self.gate([f"refs/heads/renamed {sha} refs/heads/renamed {ZERO}"])
        self.assertEqual(rc, 1)
        self.assertIn("no review record", err)
        self.git("switch", "-q", "feat")
        sha = self.commit("src/ok.py", "x = 1\n")  # code in the same push: the record is needed again
        rc, err = self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"])
        self.assertEqual(rc, 1)
        self.assertIn("no review record", err)

    def test_review_check_is_off_without_the_config(self):
        sha = self.commit("src/ok.py", "x = 1\n")
        self.mode_file.write_text("block\n")
        self.assertEqual(self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"]), (0, ""))
        self.assertEqual(self.log()[-1]["reviews"], [])

    # UI results (review-loop.ui-required)
    def ui_result(self, sha, findings=(), exit_code=0, **extra):
        base = self.git("merge-base", "main", sha)
        d = self.repo / ".git" / "review-loop" / eot.patch_id(str(self.repo), base, sha)
        d.mkdir(parents=True, exist_ok=True)
        (d / "ui.json").write_text(json.dumps({"head": sha, "base": base, "findings": list(findings),
                                               "outcome": {"exit_code": exit_code}, **extra}))

    def test_ui_touching_push_without_a_ui_result_is_refused_in_block_mode(self):
        self.git("config", "review-loop.ui-required", "true")
        sha = self.commit("src/Button.tsx", "export const B = 1;\n")
        self.mode_file.write_text("block\n")
        rc, err = self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"])
        self.assertEqual(rc, 1)
        self.assertIn("has no UI result", err)
        self.ui_result(sha)
        self.assertEqual(self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"]), (0, ""))

    def test_ui_result_with_an_open_finding_is_refused(self):
        self.git("config", "review-loop.ui-required", "true")
        sha = self.commit("src/Button.tsx", "export const B = 1;\n")
        self.ui_result(sha, [{"id": "sec-reviewloop-aaaaaaaaaaaa", "status": "hard", "rule_class": "a11y"}], 1)
        self.mode_file.write_text("block\n")
        self.assertEqual(self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"])[0], 1)

    def test_accepting_an_intended_visual_change_lets_the_push_through(self):
        self.git("config", "review-loop.ui-required", "true")
        sha = self.commit("src/Button.tsx", "export const B = 1;\n")
        fid = "sec-reviewloop-bbbbbbbbbbbb"
        self.ui_result(sha, [{"id": fid, "status": "needs_human", "rule_class": "ui-visual", "title": "looks different",
                              "lens": "ui", "sites": [{"path": "<story:b>", "start_line": 1, "end_line": 1}]}], 2)
        self.mode_file.write_text("block\n")
        line = [f"refs/heads/feat {sha} refs/heads/feat {ZERO}"]
        self.assertEqual(self.gate(line)[0], 1)
        expires = (datetime.date.today() + datetime.timedelta(days=7)).isoformat()
        with mock.patch.dict(os.environ, self.env, clear=True), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            cwd = os.getcwd()
            os.chdir(self.repo)
            try:
                from review_loop import accept
                code = accept.main([fid, "--rule-class", "ui-visual", "--reason", "new weather card, intended",
                                    "--expires", expires], confirm=lambda q: True)
            finally:
                os.chdir(cwd)
        self.assertEqual(code, 0)
        self.assertEqual(self.gate(line), (0, ""))

    def test_static_ui_result_does_not_count(self):
        self.git("config", "review-loop.ui-required", "true")
        sha = self.commit("src/Button.tsx", "export const B = 1;\n")
        self.ui_result(sha, static=True)
        self.mode_file.write_text("block\n")
        self.assertEqual(self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"])[0], 1)

    def test_non_ui_push_needs_no_ui_result(self):
        self.git("config", "review-loop.ui-required", "true")
        sha = self.commit("src/ok.py", "x = 1\n")
        self.mode_file.write_text("block\n")
        self.assertEqual(self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"]), (0, ""))

    def test_delete_is_skipped(self):
        sha = self.add_canary()
        self.mode_file.write_text("block\n")
        self.assertEqual(self.gate([f"(delete) {ZERO} refs/heads/feat {sha}"]), (0, ""))

    def test_unreachable_remote_is_a_tool_error(self):
        sha = self.commit("src/ok.py", "x = 1\n")
        missing = str(self.tmp / "nowhere.git")
        rc, err = self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"], remote=missing)
        self.assertEqual(rc, 0)
        self.assertIn("no base to compare with", err)
        self.mode_file.write_text("block\n")
        self.assertEqual(self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"], remote=missing)[0], 1)

    def test_garbage_stdin_is_a_tool_error(self):
        self.mode_file.write_text("block\n")
        rc, err = self.gate(["not a ref line"])
        self.assertEqual(rc, 1)
        self.assertIn("unexpected pre-push input", err)

    def test_one_bad_ref_of_two_refuses_the_push(self):
        clean = self.commit("src/ok.py", "x = 1\n")
        self.git("switch", "-q", "-c", "feat2")
        dirty = self.add_canary()
        self.mode_file.write_text("block\n")
        rc, err = self.gate([f"refs/heads/feat {clean} refs/heads/feat {ZERO}",
                             f"refs/heads/feat2 {dirty} refs/heads/feat2 {ZERO}"])
        self.assertEqual(rc, 1)
        self.assertIn("refs/heads/feat2", err)
        self.assertNotIn("refs/heads/feat:", err)

    def test_small_push_is_fast(self):
        sha = self.commit("src/ok.py", "x = 1\n")
        start = time.monotonic()
        self.gate([f"refs/heads/feat {sha} refs/heads/feat {ZERO}"])
        self.assertLess(time.monotonic() - start, 10)


if __name__ == "__main__":
    unittest.main()
