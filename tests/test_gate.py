"""Fixture tests for `review-loop gate` (the pre-push scan).

usage: python3 -m unittest tests.test_gate -v      (from the repo root)

Each case has a work repo and a bare `origin`, both with GIT_CONFIG_GLOBAL=/dev/null so no global hook runs.
The gate gets the pre-push stdin lines the test builds, as git would hand them to the hook.
"""
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

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
                        REVIEW_LOOP_GATE_MODE_FILE=str(self.mode_file),
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

    def gate(self, lines, *args, remote="origin"):
        p = subprocess.run([str(BIN), "gate", remote, *args], cwd=self.repo, env=self.env,
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
