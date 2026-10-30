"""Tests for `review-loop epic` (review_loop/epic.py): preflight, tickets and seams, chunk coverage, checks, record.

usage: python3 -m unittest tests.test_epic -v      (from the repo root)

Fake runners stand in for `claude -p` and `copilot`; scan runs for real (pinned gitleaks). Each case builds a
throwaway repo with GIT_CONFIG_GLOBAL=/dev/null: main, two ticket branches, and epic/<slug> with both merged --no-ff.
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from review_loop import epic  # noqa: E402 - needs the sys.path entry above
from tests.test_eot import RepoCase  # noqa: E402
from tests.test_scan import canary  # noqa: E402
from tests.test_workers import claude_stdout, done  # noqa: E402

LEAK = {
    "reasoning": "share.py:3 returns load_doc(), which ticket A made include member emails.", "lens": "security",
    "title": "share link returns member emails", "body": "Return only title and body.", "surface": "code",
    "cwe": "CWE-200", "sites": [{"path": "src/share.py", "start_line": 3, "end_line": 3},
                                {"path": "src/store.py", "start_line": 2, "end_line": 3}],
    "failure_scenario": {"input": "GET /s/<token>", "expected": "title and body", "actual": "members' emails"},
    "evidence": {"kind": "trace", "ref": None},
}


def site(path, a, b):
    return {"path": path, "start_line": a, "end_line": b}


def copilot_stdout(obj):
    return json.dumps({"type": "assistant.message", "data": {"content": json.dumps(obj)}}) + "\n"


class FakeWorkers:
    """Finders answer `find` (reviewed_paths filled from the chunk's path list); verifiers answer `verdict`.
    Answers in the format of the harness in argv[0]."""

    def __init__(self, find=(), verdict="confirmed"):
        self.find, self.verdict, self.calls = list(find), verdict, []

    def __call__(self, argv, stdin, cwd, timeout, env):
        self.calls.append((argv[0], "verify" if "Finding id: " in stdin else "find"))
        if "Finding id: " in stdin:
            fid = stdin.split("Finding id: ", 1)[1].split()[0]
            out = {"id": fid, "reasoning": "traced src/share.py:3", "counter_evidence": None, "verdict": self.verdict}
        else:
            listed = stdin.split("Changed paths in this chunk", 1)[1].split("Other paths", 1)[0]
            paths = re.findall(r"^- (\S+)$", listed, re.M)
            out = {"findings": [f for f in self.find if f["sites"][0]["path"] in paths], "reviewed_paths": paths}
        return done(argv, copilot_stdout(out) if argv[0] == "copilot" else claude_stdout(out))


class EpicCase(RepoCase):
    """main: src/store.py, src/ids.py. Ticket AB-1 widens load_doc; ticket CD-2 adds src/share.py using load_doc
    and new_id. Both merged --no-ff into epic/demo."""

    def setUp(self):
        super().setUp()
        self.write("src/store.py", "def load_doc(i):\n    return {'id': i}\n")
        self.write("src/ids.py", "import uuid\n\ndef new_id():\n    return uuid.uuid4().hex\n")
        self.commit("chore: store")
        self.main = self.git("rev-parse", "HEAD").strip()
        self.git("checkout", "-q", "-b", "ticket/AB-1-members")
        self.write("src/store.py", "def load_doc(i):\n    doc = {'id': i}\n    doc['members'] = members(i)\n    return doc\n")
        self.commit("feat: members on documents (AB-1)")
        self.git("checkout", "-q", "-b", "ticket/CD-2-share", self.main)
        self.write("src/share.py", "from store import load_doc\nfrom ids import new_id\ndef share(i):\n"
                                   "    return load_doc(i), new_id()\n")
        self.commit("feat: share links (CD-2)")
        self.git("checkout", "-q", "-b", "epic/demo", self.main)
        for t, msg in (("ticket/AB-1-members", "Merge AB-1 members into epic/demo"),
                       ("ticket/CD-2-share", "Merge CD-2 share links into epic/demo")):
            self.git("merge", "-q", "--no-ff", "-m", msg, t)
        self.git("checkout", "-q", "main")

    def run_epic(self, runner, *args, slug="demo", journey_run=None, run_ui=None):
        buf = io.StringIO()
        cwd = os.getcwd()
        kw = {"journey_run": journey_run} if journey_run else {}
        with redirect_stdout(buf):
            os.chdir(self.repo)
            try:
                code = epic.main([slug, "--base", "main", *args], runner=runner, run_ui=run_ui, **kw)
            finally:
                os.chdir(cwd)
        out = json.loads(buf.getvalue())
        self.assertEqual(code, out["outcome"]["exit_code"])
        return code, out

    def name_only(self, a="main", b="epic/demo"):
        return sorted(self.git("diff", "--name-only", a, b).split())


class PreflightTest(EpicCase):
    def assert_refused(self, why, *args, slug="demo"):
        code, out = self.run_epic(FakeWorkers(), *args, slug=slug)
        self.assertEqual(code, 3)
        self.assertIn(why, out["outcome"]["error"])
        self.assertIsNone(out["record_path"])

    def test_missing_branch_bad_slug_and_bad_base(self):
        self.assert_refused("no branch epic/nope", slug="nope")
        self.assert_refused("bad epic slug", slug="../x")
        code, out = self.run_epic(FakeWorkers(), "--base", "no-such-ref")
        self.assertEqual(code, 3)
        self.assertIn("does not resolve", out["outcome"]["error"])

    def test_dirty_checkout_is_refused(self):
        (self.repo / "src/store.py").write_text("changed\n")
        self.assert_refused("uncommitted changes")

    def test_merge_in_progress_is_refused(self):
        git_dir = Path(self.repo, self.git("rev-parse", "--git-dir").strip())
        (git_dir / "MERGE_HEAD").write_text(self.main + "\n")
        self.assert_refused("in progress (MERGE_HEAD)")

    def test_epic_already_in_base_is_refused(self):
        self.git("update-ref", "refs/heads/epic/old", self.main)
        self.assert_refused("no commits that main lacks", slug="old")


class SeamAndChunkTest(EpicCase):
    def test_tickets_and_seams_from_git(self):
        br, mb, head = epic.preflight(str(self.repo), "demo", "main")
        units = epic.tickets(str(self.repo), mb, head)
        self.assertEqual([(u["id"], u["merge"], u["ref"]) for u in units],
                         [("AB-1", True, "ticket/AB-1-members"), ("CD-2", True, "ticket/CD-2-share")])
        self.assertEqual([u["files"] for u in units], [["src/store.py"], ["src/share.py"]])
        seams, _ = epic.seams(str(self.repo), head, units, set(self.name_only()))
        self.assertIn({"kind": "symbol", "symbol": "load_doc", "defined_in": {"ticket": "AB-1", "path": "src/store.py"},
                       "used_in": [{"ticket": "CD-2", "path": "src/share.py"}]}, seams)

    def test_linear_commits_group_by_ticket_key(self):
        self.git("checkout", "-q", "-b", "epic/linear", self.main)
        for i, msg in enumerate(("feat: one (XY-7)", "fix: two (XY-7)", "feat: three")):
            self.write(f"src/f{i}.py", f"x = {i}\n")
            self.commit(msg)
        self.git("checkout", "-q", "main")
        br, mb, head = epic.preflight(str(self.repo), "linear", "main")
        units = epic.tickets(str(self.repo), mb, head)
        self.assertEqual([(u["id"], len(u["commits"])) for u in units], [("XY-7", 2), (f"commit-{head[:7]}", 1)])

    def test_chunks_cover_the_diff_exactly_and_split_a_big_file(self):
        """A file over LIMIT changed lines is split at hunk boundaries, a hunk over LIMIT at line boundaries, into
        parts of its own; every other file sits in exactly one chunk of at most LIMIT lines."""
        self.git("checkout", "-q", "-b", "epic/big", self.main)
        self.write("src/big.py", "".join(f"v{i} = {i}\n" for i in range(650)))  # one 650-line hunk
        for i in range(12):
            self.write(f"src/m{i}.py", "".join(f"m{i}_{j} = {j}\n" for j in range(40)))
        self.write("docs/notes.md", "# notes\n")
        self.git("rm", "-q", "src/ids.py")
        self.commit("feat: big")
        self.git("checkout", "-q", "main")
        br, mb, head = epic.preflight(str(self.repo), "big", "main")
        chunks, diffs = epic.plan_chunks(str(self.repo), mb, head, [])
        covered = sorted({p for c in chunks for p in c["paths"]})
        self.assertEqual(covered, self.name_only("main", "epic/big"))
        big = [c for c in chunks if c["paths"] == ["src/big.py"]]
        self.assertEqual([c["part"] for c in big], [[1, 3], [2, 3], [3, 3]])
        self.assertEqual(sum(c["lines"] for c in big), 650)
        self.assertTrue(all(c["lines"] <= epic.LIMIT for c in chunks if c["review"] == "finder"))
        self.assertEqual([c["paths"] for c in chunks if c["review"] != "finder"], [["docs/notes.md"]])
        self.assertIn("+v649 = 649", diffs[big[-1]["id"]])

    def test_seam_sides_share_a_chunk(self):
        chunks = epic.chunks({"a.py": 150, "b.py": 100, "c.py": 120, "d.py": 140}, [["a.py", "c.py"]], set())
        self.assertIn(["a.py", "c.py"], [c["paths"] for c in chunks])

    def test_duplicates_group_kept_findings_from_other_chunks_only(self):
        """Grouping is for follow-ups: each finding keeps its own status, a discarded one never hides another."""
        def f(fid, lens, status, a, b):
            return {"id": fid, "lens": lens, "status": status, "sites": [site("s.ts", a, b), site("ids.ts", 10, 13)]}

        where = {"rev-a": "c01", "rev-b": "c02", "rev-c": "c01", "rev-d": "c02", "rev-e": "c02", "rev-f": "c03"}
        found = [f("rev-a", "security", "blocking", 19, 19), f("rev-b", "security", "blocking", 16, 20),
                 f("rev-c", "security", "blocking", 18, 19), f("rev-d", "correctness", "blocking", 19, 19),
                 f("rev-e", "security", "blocking", 40, 41)]
        self.assertEqual(epic.duplicates(found, where), {"rev-a": ["rev-b"]})  # rev-c: same chunk as rev-a
        refuted = [f("rev-a", "security", "discarded", 19, 19), f("rev-b", "security", "blocking", 19, 19),
                   f("rev-f", "security", "advisory", 19, 19)]
        self.assertEqual(epic.duplicates(refuted, where), {})
        for g in found:
            g.update(title=f"t {g['id']}", reasoning="r", failure_scenario=None, body=None)
        out = Path(tempfile.mkdtemp(prefix="review-loop-fu-"))
        self.addCleanup(shutil.rmtree, out)
        written = epic.write_follow_ups(out, "demo", found, {}, {"rev-a": ["rev-b"]})
        self.assertEqual(len(written), 4)
        self.assertIn("`rev-b` (blocking): t rev-b", (out / written[0]).read_text())

    def test_coverage_check_refuses_gaps_and_duplicates(self):
        ok = [{"id": "c01", "paths": ["a", "b"], "lines": 2, "review": "finder"}]
        epic.check_coverage(ok, ["a", "b"])
        for chunks, names in (
                (ok, ["a", "b", "c"]),
                (ok + [{"id": "c02", "paths": ["b"], "lines": 1, "review": "finder"}], ["a", "b"]),
                ([{"id": "c01", "paths": ["a"], "lines": 2, "review": "finder", "part": [1, 2]}], ["a"]),
                ([{"id": "c01", "paths": ["a"], "lines": epic.LIMIT + 1, "review": "finder"}], ["a"])):
            with self.assertRaises(epic.EpicError):
                epic.check_coverage(chunks, names)


class RunTest(EpicCase):
    def test_kept_finding_blocks_writes_a_follow_up_and_a_valid_record(self):
        fake = FakeWorkers([LEAK])
        code, out = self.run_epic(fake, "--finder", "claude:sonnet", "--verifier", "copilot")
        self.assertEqual((code, out["outcome"]["summary"]), (1, "blocked"))
        f = next(f for f in out["findings"] if f["id"].startswith("rev-"))
        self.assertEqual((f["status"], f["verification"]["family"]), ("blocking", "gpt"))
        self.assertEqual(fake.calls, [("claude", "find"), ("copilot", "verify")])
        e = out["epic"]
        self.assertEqual(out["key"]["merge_base"], self.main)
        self.assertIn(f"/review-loop/{out['key']['patch_id']}/epic-{self.main}/", out["record_path"])
        self.assertEqual(sorted(p for c in e["chunks"] for p in c["paths"]), self.name_only())
        self.assertEqual(e["same_family_verify"], [])
        rd = Path(out["record_path"]).parent
        self.assertEqual(e["follow_ups"], [f"follow-ups/fu-01-{f['id']}.md"])
        fu = (rd / e["follow_ups"][0]).read_text()
        for want in ("share link returns member emails", "- AB-1", "- CD-2", "`src/share.py:3-3`",
                     "## Definition of done", "Return only title and body."):
            self.assertIn(want, fu)
        self.assertTrue((rd / "prompts/find-c01.md").is_file())
        self.assert_valid_record(out["record_path"])

    def test_same_family_verifier_is_a_recorded_fallback(self):
        code, out = self.run_epic(FakeWorkers([LEAK], "refuted"), "--finder", "claude:sonnet", "--verifier", "claude:sonnet")
        self.assertEqual(code, 0)
        f = next(f for f in out["findings"] if f["id"].startswith("rev-"))
        self.assertEqual(f["status"], "discarded")
        self.assertEqual(out["epic"]["same_family_verify"], [f["id"]])
        self.assertEqual(out["epic"]["follow_ups"], [])

    def test_checks_are_not_applicable_on_a_plain_repo(self):
        code, out = self.run_epic(FakeWorkers(), "--finder", "claude:sonnet")
        self.assertEqual((code, out["outcome"]["summary"]), (0, "no_findings_reported (unverified)"))
        self.assertEqual({k: c["status"] for k, c in out["epic"]["checks"].items()},
                         {"journey": "not_applicable", "threat_model": "not_applicable", "ui": "not_applicable",
                          "image": "not_applicable"})
        self.assert_valid_record(out["record_path"])

    def test_failed_journey_sensitive_repo_and_changed_image_go_to_a_human(self):
        self.git("checkout", "-q", "epic/demo")
        self.write("package.json", json.dumps({"scripts": {"e2e": "exit 1"}}))
        self.write("Dockerfile", "FROM scratch\n")
        self.write("src/routes.py", "@app.route('/s/<token>')\ndef open_share(token):\n    return token\n")
        self.commit("feat: journey, image, route")
        self.git("checkout", "-q", "main")
        (self.repo / "node_modules").mkdir()
        self.git("config", "review-loop.sensitive", "true")
        ran = []

        def journey_run(argv, cwd, timeout, env):
            ran.append(argv)
            return subprocess.CompletedProcess(argv, 1, "journey step 3 failed\n", "")

        code, out = self.run_epic(FakeWorkers(), "--finder", "claude:sonnet", journey_run=journey_run)
        self.assertEqual((code, out["outcome"]["summary"]), (2, "needs_human"))
        checks = out["epic"]["checks"]
        self.assertEqual(ran, [["npm", "run", "--silent", "e2e"]])
        self.assertEqual((checks["journey"]["status"], checks["journey"]["exit_code"]), ("failed", 1))
        self.assertEqual(checks["threat_model"]["status"], "needs_human")
        self.assertEqual(checks["image"]["status"], "needs_human")
        self.assertEqual(out["epic"]["waiting_on_human"], ["image", "journey", "threat_model"])
        rd = Path(out["record_path"]).parent
        self.assertIn("journey step 3 failed", (rd / "journey.log").read_text())
        self.assertIn("src/routes.py:1: @app.route('/s/<token>')", (rd / "threat-model-delta.md").read_text())
        self.assert_valid_record(out["record_path"])

    def test_journey_without_node_modules_is_skipped_and_untouched_image_informational(self):
        self.write("Dockerfile", "FROM scratch\n")
        self.commit("chore: image")
        self.git("checkout", "-q", "epic/demo")
        self.git("merge", "-q", "--no-ff", "-m", "Merge main into epic/demo", "main")
        self.write("package.json", json.dumps({"scripts": {"test:e2e": "exit 0"}}))
        self.commit("chore: e2e")
        self.git("checkout", "-q", "main")
        code, out = self.run_epic(FakeWorkers(), "--finder", "claude:sonnet")
        checks = out["epic"]["checks"]
        self.assertEqual((checks["journey"]["status"], checks["image"]["status"]), ("skipped", "informational"))
        self.assertEqual(code, 0)

    def test_ui_change_runs_every_story_and_writes_the_checklist(self):
        self.git("checkout", "-q", "epic/demo")
        self.write("src/Button.tsx", "export const Button = () => null;\n")
        self.commit("feat: button")
        self.git("checkout", "-q", "main")
        calls = []

        def run_ui(repo, base, head, full=False):
            calls.append(full)
            return {"status": "ran", "findings": [], "outcome": {"exit_code": 0, "summary": "no_findings"}}

        code, out = self.run_epic(FakeWorkers(), "--finder", "claude:sonnet", run_ui=run_ui)
        self.assertEqual((code, calls), (2, [True]))
        self.assertEqual(out["epic"]["checks"]["ui"]["status"], "needs_human")
        self.assertTrue((Path(out["record_path"]).parent / "a11y-checklist.md").is_file())

    def test_secret_in_a_commit_message_stops_before_any_model_even_with_a_prd(self):
        prd = self.tmp / "prd.md"
        prd.write_text("# PRD\n")
        self.git("checkout", "-q", "epic/demo")
        self.write("src/k.py", "K = 1\n")
        self.commit(f"feat: k\n\nkey {canary()}")
        self.git("checkout", "-q", "main")
        fake = FakeWorkers()
        code, out = self.run_epic(fake, "--finder", "claude:sonnet", "--prd", str(prd))
        self.assertEqual(code, 1)
        self.assertEqual(fake.calls, [])
        self.assertEqual([(f["sites"][0]["path"], f["status"]) for f in out["findings"]], [("<commits>", "hard")])

    def test_secret_in_the_epic_stops_before_any_model(self):
        c = canary()
        self.git("checkout", "-q", "epic/demo")
        self.write("src/k.py", f'K = "{c}"\n')
        self.commit("feat: k")
        self.git("checkout", "-q", "main")
        fake = FakeWorkers()
        code, out = self.run_epic(fake, "--finder", "claude:sonnet")
        self.assertEqual(code, 1)
        self.assertEqual(fake.calls, [])
        for p in Path(out["record_path"]).parent.rglob("*"):
            if p.is_file():
                self.assertNotIn(c, p.read_text(errors="replace"), p)


class FixtureSeamTest(unittest.TestCase):
    """Seams on the golden toy epic: each seeded bug's two tickets meet in a recorded seam."""

    def test_golden_epic_seams(self):
        tmp = Path(tempfile.mkdtemp(prefix="review-loop-epic-fixture-"))
        self.addCleanup(shutil.rmtree, tmp)
        subprocess.run(["bash", str(ROOT / "golden/epic/build.sh"), str(tmp)], check=True, capture_output=True)
        repo = str(tmp / "doc-sharing")
        br, mb, head = epic.preflight(repo, "doc-sharing", "main")
        units = epic.tickets(repo, mb, head)
        self.assertEqual([u["id"] for u in units], ["DS-1", "DS-2", "DS-3"])
        names = set(epic.name_only(repo, mb, head))
        seams, _ = epic.seams(repo, head, units, names)
        files = {s["path"]: s["tickets"] for s in seams if s["kind"] == "file"}
        self.assertEqual(files["src/documents/routes.ts"], ["DS-1", "DS-2"])  # IDOR: T1 x T2
        self.assertEqual(files["prisma/schema.prisma"], ["DS-1", "DS-2", "DS-3"])  # restore: T2 x T3
        sym = {(s["symbol"], s["defined_in"]["ticket"]): {u["path"] for u in s["used_in"]}
               for s in seams if s["kind"] == "symbol"}
        self.assertIn("src/sharing/routes.ts", sym[("findDocument", "DS-1")])  # email leak: T1 x T3
        self.assertIn("src/sharing/routes.ts", sym[("toDocumentDto", "DS-1")])
        self.assertIn("src/sharing/routes.ts", sym[("newId", "DS-2")])  # predictable tokens: T2 x T3
        chunks, _ = epic.plan_chunks(repo, mb, head, seams)
        self.assertEqual(sorted(p for c in chunks for p in c["paths"]), sorted(names))


if __name__ == "__main__":
    unittest.main()
