"""Fixture tests for `review-loop sweep` (whole-repo checks, report only).

usage: python3 -m unittest tests.test_sweep -v      (from the repo root)

Repos are throwaway, with GIT_CONFIG_GLOBAL=/dev/null. No test makes a network call: the osv check runs in a
client-origin repo without an offline database (skipped), and the vulnerable-pin case was verified by hand.
"""
import datetime
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from review_loop import sweep
from tests.test_scan import BIN, GITLEAKS_ROW, canary


@unittest.skipUnless(GITLEAKS_ROW, "gitleaks not pinned in ~/.config/review-loop/tools.lock")
class SweepTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="review-loop-sweep-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        lock = self.tmp / "tools.lock"
        lock.write_text(Path.home().joinpath(".config/review-loop/tools.lock").read_text())
        self.allow = self.tmp / "hooks-allow.txt"
        self.claude = self.tmp / "claude"
        (self.tmp / "osvdb").mkdir()
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1",
                        REVIEW_LOOP_TOOLS_LOCK=str(lock), REVIEW_LOOP_STATE_DIR=str(self.tmp / "state"),
                        REVIEW_LOOP_HOOKS_ALLOW=str(self.allow), CLAUDE_CONFIG_DIR=str(self.claude),
                        OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=str(self.tmp / "osvdb"),
                        GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
        self.secrets = []
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("remote", "add", "origin", "https://dev.azure.com/client/project/_git/app")  # a client repo
        self.commit("README.md", "# fixture\n")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, env=self.env, check=True, capture_output=True,
                              text=True).stdout.strip()

    def commit(self, path, text):
        p = self.repo / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        self.git("add", path)
        self.git("commit", "-q", "-m", f"add {path}")

    def sweep(self, *args):
        p = subprocess.run([str(BIN), "sweep", *args], cwd=self.repo, env=self.env, capture_output=True, text=True)
        for s in self.secrets:
            self.assertNotIn(s, p.stdout + p.stderr)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def result(self):
        path = self.repo / ".git/review-loop/sweep.json"
        text = path.read_text()
        for s in self.secrets:
            self.assertNotIn(s, text, "secret value stored in sweep.json")
        return json.loads(text)

    def age(self, days):
        r = self.result()
        r["ts"] = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).isoformat()
        (self.repo / ".git/review-loop/sweep.json").write_text(json.dumps(r))

    def test_gitleaks_covers_history_once_then_only_new_commits(self):
        c = canary()
        self.secrets.append(c)
        self.commit("src/x.ts", "".join(f"export const v{i} = {i};\n" for i in range(20)) + f'export const t = "{c}";\n')
        self.sweep()
        first = self.result()["checks"]["gitleaks"]
        self.assertEqual((first["range"], [h["path"] for h in first["hits"]]), ("all history", ["src/x.ts"]))
        self.commit("src/ok.ts", "export const ok = 1;\n")
        self.sweep()
        second = self.result()["checks"]["gitleaks"]
        self.assertEqual(second["hits"], [])
        self.assertNotEqual(second["range"], "all history")

    def test_failed_gitleaks_run_is_covered_by_the_next_sweep(self):
        c = canary()
        self.secrets.append(c)
        self.commit("src/x.ts", "".join(f"export const v{i} = {i};\n" for i in range(20)) + f'export const t = "{c}";\n')
        lock = Path(self.env["REVIEW_LOOP_TOOLS_LOCK"])
        good = lock.read_text()
        lock.write_text("")  # gitleaks unpinned: the check errors
        self.sweep()
        self.assertEqual(self.result()["checks"]["gitleaks"]["status"], "error")
        lock.write_text(good)
        self.sweep()
        g = self.result()["checks"]["gitleaks"]
        self.assertEqual(([h["path"] for h in g["hits"]], g["range"]), (["src/x.ts"], "all history"))

    def test_client_repo_without_offline_db_skips_osv(self):
        self.sweep()
        self.assertEqual(self.result()["checks"]["osv"]["status"], "skipped")

    def test_unknown_hook_and_local_hooks_path_are_reported(self):
        hook = self.repo / ".git/hooks/post-commit"
        hook.write_text("#!/bin/sh\nexit 0\n")
        hook.chmod(0o755)
        self.git("config", "core.hooksPath", ".githooks")
        self.sweep()
        hooks = self.result()["checks"]["hooks"]
        self.assertEqual([h["name"] for h in hooks["unknown"]], ["post-commit"])
        self.assertEqual(hooks["local_hooks_path"], ".githooks")
        self.allow.write_text(f"{hooks['unknown'][0]['sha256']} post-commit  known hook\n")
        self.git("config", "--unset", "core.hooksPath")
        self.sweep()
        self.assertEqual(self.result()["checks"]["hooks"], {"status": "ok", "unknown": [], "local_hooks_path": None})

    def test_if_due_runs_only_when_due_and_usage_is_fine(self):
        self.sweep("--if-due")
        self.assertEqual(self.sweep("--if-due"), "")  # swept just now: not due
        self.age(8)
        aged = self.result()["ts"]
        snap = self.claude / "hooks/usage-guard/.state/usage.json"
        snap.parent.mkdir(parents=True)
        later = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)).isoformat()
        snap.write_text(json.dumps({"five_hour": {"used_percentage": 95, "resets_at": later}}))
        self.assertEqual(self.sweep("--if-due"), "")  # due, but usage-guard is over its 5h limit
        snap.unlink()
        self.assertIn("review-loop sweep", self.sweep("--if-due"))
        self.assertGreater(self.result()["ts"], aged)

    def test_running_sweep_lock_skips_a_second_one(self):
        (self.repo / ".git/review-loop").mkdir(parents=True)
        (self.repo / ".git/review-loop/sweep.lock").touch()
        self.assertEqual(self.sweep("--if-due"), "")
        self.assertFalse((self.repo / ".git/review-loop/sweep.json").exists())

    def test_image_not_applicable_without_dockerfile(self):
        self.sweep()
        self.assertEqual(self.result()["checks"]["image"]["status"], "not_applicable")

    def test_image_skipped_for_an_unknown_ci_host(self):
        self.git("remote", "set-url", "origin", "https://git.example.invalid/x/app.git")
        self.commit("svc/Dockerfile", "FROM scratch\n")
        self.sweep()
        image = self.result()["checks"]["image"]
        self.assertEqual((image["status"], image["dockerfiles"]), ("skipped", ["svc/Dockerfile"]))

    def test_trivy_report_parsed_and_deduped_with_osv(self):
        report = {"Results": [{"Target": "app (alpine 3.19)", "Vulnerabilities": [
            {"PkgName": "openssl", "InstalledVersion": "3.1.0", "VulnerabilityID": "CVE-2026-0001", "Severity": "HIGH",
             "FixedVersion": "3.1.1"},
            {"PkgName": "lodash", "InstalledVersion": "4.17.15", "VulnerabilityID": "CVE-2020-8203", "Severity": "HIGH"}]}]}
        osv = [{"package": "lodash", "ids": ["GHSA-p6mc-m468-83gw"], "aliases": ["CVE-2020-8203"]}]
        got = sweep.parse_trivy(json.dumps(report).encode(), osv)
        self.assertEqual((got["status"], got["deduped"], got["by_severity"]), ("findings", 1, {"HIGH": 1}))
        self.assertEqual(got["vulns"][0]["id"], "CVE-2026-0001")
        self.assertEqual(sweep.parse_trivy(b"", [])["status"], "error")
        self.assertEqual(sweep.parse_trivy(b'{"Results": []}', [])["status"], "ok")

    def test_digest_lists_last_sweep_dates(self):
        other = self.tmp / "other"
        subprocess.run(["git", "init", "-q", str(other)], env=self.env, check=True)
        self.sweep()
        p = subprocess.run([str(BIN), "sweep", "--digest", str(self.tmp)], env=self.env, capture_output=True, text=True)
        rows = {line.split("\t")[0]: line.split("\t")[1] for line in p.stdout.splitlines()[1:]}
        self.assertEqual(rows[str(other)], "never")
        self.assertEqual(rows[str(self.repo)], datetime.date.today().isoformat())


if __name__ == "__main__":
    unittest.main()
