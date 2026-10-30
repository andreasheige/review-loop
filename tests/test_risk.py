"""Fixture tests for `review-loop risk` (plan 8.7: how much review a PR needs, decided in code).

usage: python3 -m unittest tests.test_risk -v      (from the repo root)
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from review_loop import eot, risk


class RiskTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="review-loop-risk-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(self.tmp / "home"),
               "REVIEW_LOOP_STATE_DIR": str(self.tmp / "state"), "GIT_AUTHOR_NAME": "t",
               "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.commit("README.md", "# fixture\n")
        self.git("switch", "-q", "-c", "feat")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, path, text):
        p = self.repo / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        self.git("add", path)
        self.git("commit", "-q", "-m", f"add {path}")
        return self.git("rev-parse", "HEAD")

    def record(self, sha, findings=(), exit_code=0, rnd=1):
        base = self.git("merge-base", "main", sha)
        d = self.repo / ".git" / "review-loop" / eot.patch_id(str(self.repo), base, sha) / f"round-{rnd}"
        d.mkdir(parents=True)
        (d / "record.json").write_text(json.dumps({
            "command": "eot" if rnd == 1 else "recheck", "round": rnd, "head": sha, "branch": "feat",
            "created_at": f"2026-10-30T00:00:0{rnd}+00:00", "findings": list(findings),
            "outcome": {"exit_code": exit_code}}))

    def assess(self):
        return risk.assess(str(self.repo), "main", "HEAD")

    def reviewed(self, path, text, **kw):
        sha = self.commit(path, text)
        self.record(sha, **kw)
        return sha

    def test_small_docs_change_reviewed_clean_in_round_one_is_low(self):
        self.reviewed("docs/guide.md", "# Guide\n\nHow to run it.\n")
        r = self.assess()
        self.assertEqual(r["tier"], "low", r["reasons"])

    def test_tests_only_change_is_low(self):
        self.reviewed("tests/test_add.py", "def test_add():\n    assert 1 + 1 == 2\n")
        self.assertEqual(self.assess()["tier"], "low")

    def test_code_under_docs_is_not_docs(self):
        for path in ("docs/conf.py", "docs/build.sh", "docs/assets/app.js", "AUTHORS", "NOTICE", "LICENSE.sh"):
            with self.subTest(path=path):
                self.git("switch", "-q", "-C", "feat", "main")
                self.reviewed(path, "x = 1\n")
                self.assertNotEqual(self.assess()["tier"], "low")

    def test_no_review_record_is_never_low(self):
        self.commit("docs/guide.md", "# Guide\n")
        r = self.assess()
        self.assertEqual(r["tier"], "medium")
        self.assertTrue(any("review" in x for x in r["reasons"]))

    def test_open_finding_in_the_record_is_never_low(self):
        self.reviewed("docs/guide.md", "# Guide\n", findings=[{"id": "rev-aaaaaaaaaaaa", "status": "blocking",
                                                               "rule_class": None}], exit_code=1)
        self.assertNotEqual(self.assess()["tier"], "low")

    def test_recheck_needed_makes_it_medium(self):
        sha = self.commit("docs/guide.md", "# Guide\n")
        blocking = {"id": "rev-aaaaaaaaaaaa", "status": "blocking", "rule_class": None}
        self.record(sha, [blocking], exit_code=1, rnd=1)
        self.record(sha, [{**blocking, "status": "discarded"}], exit_code=0, rnd=2)
        self.assertEqual(self.assess()["tier"], "medium")

    def test_ordinary_code_is_medium_and_names_the_files_to_read(self):
        self.reviewed("src/add.py", "def add(a, b):\n    return a + b\n")
        r = self.assess()
        self.assertEqual(r["tier"], "medium")
        self.assertIn("src/add.py", r["read"])

    def test_security_paths_are_high(self):
        self.reviewed("src/auth/login.py", "def login(u):\n    return True\n")
        self.assertEqual(self.assess()["tier"], "high")

    def test_infra_ci_migrations_and_agent_config_are_high(self):
        for path in (".github/workflows/ci.yml", "db/migrations/001_init.sql", "infra/main.tf", "CLAUDE.md",
                     ".claude/settings.json", "Dockerfile"):
            with self.subTest(path=path):
                self.git("switch", "-q", "-C", "feat", "main")
                self.reviewed(path, "x\n")
                self.assertEqual(self.assess()["tier"], "high")

    def test_new_dependency_manifest_is_high_lockfile_only_is_medium(self):
        self.reviewed("package.json", '{"dependencies": {"left-pad": "1.3.0"}}\n')
        self.assertEqual(self.assess()["tier"], "high")
        self.git("switch", "-q", "-C", "feat", "main")
        self.reviewed("package-lock.json", '{"lockfileVersion": 3}\n')
        self.assertEqual(self.assess()["tier"], "medium")

    def test_accepted_needs_human_is_high(self):
        f = {"id": "pol-bbbbbbbbbbbb", "status": "needs_human", "rule_class": "control-weakening"}
        self.reviewed("docs/guide.md", "# Guide\n", findings=[f], exit_code=2)
        store = self.repo / ".git" / "review-loop" / "accepts.jsonl"
        store.write_text(json.dumps({"finding_id": f["id"], "rule_class": "control-weakening", "reason": "intended change",
                                     "expires": "2099-01-01", "tty": True}) + "\n")
        r = self.assess()
        self.assertEqual(r["tier"], "high")
        self.assertTrue(any("accepted" in x for x in r["reasons"]))

    def test_large_diff_is_high(self):
        self.reviewed("docs/big.md", "".join(f"line {i}\n" for i in range(500)))
        self.assertEqual(self.assess()["tier"], "high")

    def test_sensitive_repo_is_high(self):
        self.git("config", "review-loop.sensitive", "true")
        self.reviewed("docs/guide.md", "# Guide\n")
        self.assertEqual(self.assess()["tier"], "high")

    def test_ui_change_is_medium_and_a_visual_change_is_high(self):
        sha = self.reviewed("src/Button.tsx", "export const B = () => null;\n")
        self.assertEqual(self.assess()["tier"], "medium")
        base = self.git("merge-base", "main", sha)
        d = self.repo / ".git" / "review-loop" / eot.patch_id(str(self.repo), base, sha)
        (d / "ui.json").write_text(json.dumps({"head": sha, "base": base, "outcome": {"exit_code": 2}, "findings": [
            {"id": "ui-cccccccccccc", "status": "needs_human", "rule_class": "ui-visual"}]}))
        self.assertEqual(self.assess()["tier"], "high")

    def test_markdown_section_names_the_tier(self):
        self.reviewed("src/add.py", "def add(a, b):\n    return a + b\n")
        md = risk.markdown(self.assess())
        self.assertIn("risk:medium", md)
        self.assertIn("src/add.py", md)

    def test_cli_prints_json_and_exits_zero(self):
        self.reviewed("docs/guide.md", "# Guide\n")
        bin_ = Path(__file__).resolve().parent.parent / "bin" / "review-loop"
        p = subprocess.run([str(bin_), "risk", "--base", "main", "--format", "json"], cwd=self.repo,
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["tier"], "low")
        from review_loop import stats
        self.assertEqual(stats.stats(str(self.repo))["risk"], {"low": 1, "medium": 0, "high": 0})


if __name__ == "__main__":
    unittest.main()
