"""Fixture tests for `review-loop land` (an agent merges only a risk:low PR, recomputed from its head).

usage: python3 -m unittest tests.test_land -v      (from the repo root)

GitHub is a fake: `gh` calls go to a recorder that answers `pr view` from a dict and records `pr merge`.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from review_loop import eot, land
from tests.test_scan import GITLEAKS_ROW, canary


class FakeGh:
    def __init__(self, pr):
        self.pr, self.calls = pr, []

    def __call__(self, args, cwd):
        self.calls.append(args)
        if args[:2] == ["pr", "view"]:
            return 0, json.dumps(self.pr)
        if args[:2] == ["pr", "merge"]:
            return 0, ""
        return 1, "unexpected"

    def merged(self):
        return [c for c in self.calls if c[:2] == ["pr", "merge"]]


class LandTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="review-loop-land-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(self.tmp / "home"),
               "REVIEW_LOOP_STATE_DIR": str(self.tmp / "state"), "GIT_AUTHOR_NAME": "t",
               "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.origin, self.repo = self.tmp / "origin.git", self.tmp / "repo"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.origin)], check=True)
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", f"url.{self.origin}.insteadOf", "https://github.com/o/r")
        self.git("remote", "add", "origin", "https://github.com/o/r")
        self.commit("README.md", "# fixture\n")
        self.git("push", "-q", "origin", "main")
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

    def record(self, sha, findings=(), exit_code=0):
        base = self.git("merge-base", "main", sha)
        d = self.repo / ".git" / "review-loop" / eot.patch_id(str(self.repo), base, sha) / "round-1"
        d.mkdir(parents=True)
        (d / "record.json").write_text(json.dumps({
            "command": "eot", "round": 1, "head": sha, "branch": "feat", "created_at": "2026-10-30T00:00:01+00:00",
            "findings": list(findings), "outcome": {"exit_code": exit_code}}))

    FINISHED = {"journey": {"status": "not_applicable"}, "threat_model": {"status": "not_applicable"},
                "ui": {"status": "not_applicable"}, "image": {"status": "informational"}}

    def epic_record(self, sha, base_ref="main", findings=(), exit_code=0, checks=None, head=None):
        mb = self.git("merge-base", base_ref, sha)
        pid = eot.patch_id(str(self.repo), mb, sha)
        d = self.repo / ".git" / "review-loop" / pid / f"epic-{mb}"
        d.mkdir(parents=True)
        (d / "record.json").write_text(json.dumps({
            "command": "epic", "head": head or sha, "branch": "epic/x", "key": {"patch_id": pid, "merge_base": mb},
            "created_at": "2026-11-01T00:00:01+00:00", "findings": list(findings), "outcome": {"exit_code": exit_code},
            "epic": {"checks": {**self.FINISHED, **(checks or {})}}}))

    def epic_pr(self, path="docs/guide.md", text="# Guide\n", epic_reviewed=True):
        """A low-risk-looking change on epic/x (eot-reviewed, so only the epic check can refuse it)."""
        sha = self.pushed(path, text)
        if epic_reviewed:
            self.epic_record(sha)
        self.git("push", "-q", "origin", "feat:refs/heads/epic/x")
        return sha

    def pushed(self, path, text, reviewed=True):
        sha = self.commit(path, text)
        if reviewed:
            self.record(sha)
        self.git("push", "-q", "origin", "feat")
        return sha

    def pr(self, sha, **kw):
        return {"number": 7, "url": "https://github.com/o/r/pull/7", "isCrossRepository": False,
                "state": "OPEN", "isDraft": False, "mergeable": "MERGEABLE", "baseRefName": "main",
                "headRefName": "feat", "headRefOid": sha, "statusCheckRollup": [], "labels": [], **kw}

    def land(self, gh, scan=None):
        return land.run(str(self.repo), "7", gh=gh, scan_fn=scan or (lambda repo, rng: {"exit_code": 0, "findings": []}))

    def test_low_risk_pr_lands_pinned_to_its_head(self):
        sha = self.pushed("docs/guide.md", "# Guide\n")
        gh = FakeGh(self.pr(sha))
        code, msg = self.land(gh)
        self.assertEqual(code, 0, msg)
        merge = gh.merged()[0]
        self.assertIn("--rebase", merge)
        self.assertEqual(merge[merge.index("--match-head-commit") + 1], sha)
        log = [json.loads(l) for l in (self.tmp / "state" / "land.jsonl").read_text().splitlines()]
        self.assertEqual((log[-1]["pr"], log[-1]["tier"], log[-1]["merged"]), ("7", "low", True))

    def test_medium_and_high_are_refused_and_wait_for_the_user(self):
        for path, tier in (("src/add.py", "medium"), ("src/auth/login.py", "high")):
            with self.subTest(path=path):
                self.git("switch", "-q", "-C", "feat", "main")
                sha = self.commit(path, "x = 1\n")
                self.record(sha)
                self.git("push", "-q", "-f", "origin", "feat")
                gh = FakeGh(self.pr(sha))
                code, msg = self.land(gh)
                self.assertEqual(code, 1)
                self.assertIn(f"risk:{tier}", msg)
                self.assertIn("waiting for a human", msg)
                self.assertEqual(gh.merged(), [])

    def test_a_risk_low_label_does_not_count(self):
        sha = self.pushed("src/auth/login.py", "x = 1\n")
        gh = FakeGh(self.pr(sha, labels=[{"name": "risk:low"}]))
        self.assertEqual(self.land(gh)[0], 1)
        self.assertEqual(gh.merged(), [])

    def test_unreviewed_low_looking_change_is_refused(self):
        sha = self.pushed("docs/guide.md", "# Guide\n", reviewed=False)
        gh = FakeGh(self.pr(sha))
        code, msg = self.land(gh)
        self.assertEqual(code, 1)
        self.assertIn("review", msg)
        self.assertEqual(gh.merged(), [])

    # epic PRs (head branch epic/<slug>): a current review-loop epic record is required, whatever the tier
    def test_epic_pr_without_an_epic_record_is_refused(self):
        sha = self.epic_pr(epic_reviewed=False)
        gh = FakeGh(self.pr(sha, headRefName="epic/x"))
        code, msg = self.land(gh)
        self.assertEqual(code, 1, msg)
        self.assertIn("review-loop epic x", msg)
        self.assertEqual(gh.merged(), [])

    def test_epic_pr_with_a_current_clean_epic_record_lands(self):
        sha = self.epic_pr()
        gh = FakeGh(self.pr(sha, headRefName="epic/x"))
        code, msg = self.land(gh)
        self.assertEqual(code, 0, msg)
        self.assertEqual(len(gh.merged()), 1)

    def test_epic_record_from_before_main_moved_forces_a_rerun(self):
        old = self.epic_pr()
        self.git("switch", "-q", "main")
        self.commit("CHANGELOG.md", "moved\n")
        self.git("push", "-q", "origin", "main")
        self.git("switch", "-q", "feat")
        self.git("rebase", "-q", "main")
        sha = self.git("rev-parse", "HEAD")
        self.assertNotEqual(old, sha)
        # same content, so the same patch-id and eot record; only the merge-base moved
        self.git("push", "-q", "-f", "origin", "feat:refs/heads/epic/x")
        gh = FakeGh(self.pr(sha, headRefName="epic/x"))
        code, msg = self.land(gh)
        self.assertEqual(code, 1, msg)
        self.assertIn("review-loop epic x", msg)
        self.assertEqual(gh.merged(), [])

    def test_epic_record_with_an_open_finding_or_an_error_is_refused(self):
        for kw in ({"findings": [{"id": "rev-1", "status": "blocking", "rule_class": None}], "exit_code": 1},
                   {"exit_code": 3},
                   {"exit_code": 2, "checks": {"threat_model": {"status": "needs_human"}}},
                   {"exit_code": 1, "checks": {"journey": {"status": "failed"}}},
                   {"exit_code": 0, "checks": {"ui": {"status": "something-new"}}}):
            with self.subTest(**{k: str(v)[:30] for k, v in kw.items()}):
                self.git("switch", "-q", "-C", "feat", "main")
                sha = self.commit("docs/guide.md", "# Guide\n" + str(kw))
                self.record(sha)
                self.epic_record(sha, **kw)
                self.git("push", "-q", "-f", "origin", "feat:refs/heads/epic/x")
                gh = FakeGh(self.pr(sha, headRefName="epic/x"))
                code, msg = self.land(gh)
                self.assertEqual(code, 1, msg)
                self.assertIn("epic review", msg)
                self.assertEqual(gh.merged(), [])

    def test_epic_review_that_stopped_before_its_checks_is_refused(self):
        sha = self.commit("docs/guide.md", "# Guide\n")
        self.record(sha)
        self.epic_record(sha)
        mb = self.git("merge-base", "main", sha)
        path = next((self.repo / ".git" / "review-loop").glob(f"*/epic-{mb}/record.json"))
        rec = json.loads(path.read_text())
        rec["epic"]["checks"] = {}
        path.write_text(json.dumps(rec))
        self.git("push", "-q", "-f", "origin", "feat:refs/heads/epic/x")
        code, msg = self.land(FakeGh(self.pr(sha, headRefName="epic/x")))
        self.assertEqual(code, 1, msg)
        self.assertIn("did not finish", msg)

    def test_epic_record_for_another_tree_with_the_same_patch_id_is_refused(self):
        sha = self.commit("docs/guide.md", "# Guide\n")
        self.record(sha)
        other = self.git("commit-tree", self.git("rev-parse", "main^{tree}"), "-p", "main", "-m", "other")
        self.epic_record(sha, head=other)
        self.git("push", "-q", "-f", "origin", "feat:refs/heads/epic/x")
        gh = FakeGh(self.pr(sha, headRefName="epic/x"))
        code, msg = self.land(gh)
        self.assertEqual(code, 1, msg)
        self.assertIn("epic review", msg)

    def test_epic_check_cli_reports_whether_the_record_is_current(self):
        from review_loop import epic
        sha = self.commit("docs/guide.md", "# Guide\n")
        self.git("branch", "epic/x", sha)
        cwd = os.getcwd()
        os.chdir(self.repo)
        self.addCleanup(os.chdir, cwd)
        self.assertEqual(epic.main(["x", "--check", "--base", "main"]), 1)
        self.epic_record(sha)
        self.assertEqual(epic.main(["x", "--check", "--base", "main"]), 0)
        self.assertEqual(epic.main(["nope", "--check", "--base", "main"]), 3)

    def test_pending_or_failing_checks_are_refused(self):
        sha = self.pushed("docs/guide.md", "# Guide\n")
        for checks, word in (([{"name": "ci", "status": "IN_PROGRESS", "conclusion": ""}], "pending"),
                             ([{"name": "ci", "status": "COMPLETED", "conclusion": "FAILURE"}], "failing")):
            with self.subTest(word=word):
                gh = FakeGh(self.pr(sha, statusCheckRollup=checks))
                code, msg = self.land(gh)
                self.assertEqual(code, 1)
                self.assertIn(word, msg)
                self.assertEqual(gh.merged(), [])
        gh = FakeGh(self.pr(sha, statusCheckRollup=[{"name": "ci", "status": "COMPLETED", "conclusion": "SUCCESS"},
                                                    {"context": "lint", "state": "SUCCESS"}]))
        self.assertEqual(self.land(gh)[0], 0)

    def test_draft_closed_or_conflicting_pr_is_refused(self):
        sha = self.pushed("docs/guide.md", "# Guide\n")
        for extra in ({"isDraft": True}, {"state": "CLOSED"}, {"mergeable": "CONFLICTING"}):
            with self.subTest(extra=extra):
                gh = FakeGh(self.pr(sha, **extra))
                self.assertEqual(self.land(gh)[0], 1)
                self.assertEqual(gh.merged(), [])

    def test_assessed_on_the_pr_head_not_the_local_checkout(self):
        sha = self.pushed("src/auth/login.py", "x = 1\n")
        self.git("switch", "-q", "-C", "other", "main")
        self.commit("docs/x.md", "# x\n")  # the checkout now looks harmless
        gh = FakeGh(self.pr(sha))
        code, msg = self.land(gh)
        self.assertEqual(code, 1)
        self.assertIn("risk:high", msg)

    def test_head_ahead_of_origin_is_an_error(self):
        self.pushed("docs/guide.md", "# Guide\n")
        sha = self.commit("docs/more.md", "# More\n")  # committed and reviewed, but origin's feat is behind
        self.record(sha)
        gh = FakeGh(self.pr(sha))
        code, msg = self.land(gh)
        self.assertEqual(code, 3)
        self.assertIn("push it first", msg)
        self.assertEqual(gh.merged(), [])

    def test_pr_in_another_repository_is_refused(self):
        sha = self.pushed("docs/guide.md", "# Guide\n")
        for extra in ({"url": "https://github.com/someone/r/pull/7"}, {"isCrossRepository": True}):
            with self.subTest(extra=extra):
                gh = FakeGh(self.pr(sha, **extra))
                self.assertEqual(self.land(gh)[0], 3)
                self.assertEqual(gh.merged(), [])

    def test_history_scan_of_the_pr_commits_must_pass(self):
        sha = self.pushed("docs/guide.md", "# Guide\n")
        seen = []

        def scan(repo, rng):
            seen.append(rng)
            return {"exit_code": 1, "findings": [{"id": "sec-x", "status": "hard", "rule_class": "secret"}]}
        gh = FakeGh(self.pr(sha))
        code, msg = self.land(gh, scan)
        self.assertEqual(code, 1)
        self.assertIn("scan", msg)
        self.assertTrue(seen and seen[0].endswith(f"..{sha}"))
        self.assertEqual(gh.merged(), [])

        def broken(repo, rng):
            raise RuntimeError("gitleaks missing")
        self.assertEqual(self.land(FakeGh(self.pr(sha)), broken)[0], 3)

    @unittest.skipUnless(GITLEAKS_ROW, "gitleaks not pinned in ~/.config/review-loop/tools.lock")
    def test_real_scan_finds_a_secret_added_and_removed_in_the_pr(self):
        lock = self.tmp / "tools.lock"
        lock.write_text(GITLEAKS_ROW + "\n")
        os.environ["REVIEW_LOOP_TOOLS_LOCK"] = str(lock)
        c = canary()
        self.commit("src/x.ts", "".join(f"export const v{i} = {i};\n" for i in range(20)) + f'export const t = "{c}";\n')
        self.commit("src/x.ts", "export const v = 1;\n")
        self.git("rm", "-q", "src/x.ts")
        self.git("commit", "-q", "-m", "drop x")
        sha = self.pushed("docs/guide.md", "# Guide\n")
        gh = FakeGh(self.pr(sha))
        code, msg = land.run(str(self.repo), "7", gh=gh)
        self.assertEqual(code, 1, msg)
        self.assertIn("scan of the PR commits", msg)
        self.assertNotIn("risk:", msg)  # net diff is docs only: the scan is what stops it
        self.assertNotIn(c, msg)
        self.assertEqual(gh.merged(), [])

    def test_head_not_on_the_remote_is_an_error(self):
        sha = self.commit("docs/guide.md", "# Guide\n")
        self.record(sha)  # never pushed
        gh = FakeGh(self.pr(sha))
        self.assertEqual(self.land(gh)[0], 3)
        self.assertEqual(gh.merged(), [])


if __name__ == "__main__":
    unittest.main()
