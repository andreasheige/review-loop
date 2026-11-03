"""Tests for `review-loop label` and `stats` (review_loop/stats.py).

usage: python3 -m unittest tests.test_stats -v      (from the repo root)
"""
import csv
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from review_loop import recheck, stats  # noqa: E402 - needs the sys.path entry above
from tests.test_eot import BUG, NIT, FakeClaude, RepoCase  # noqa: E402


class StatsTest(RepoCase):
    def run_in_repo(self, fn, *args, **kw):
        buf, cwd = io.StringIO(), os.getcwd()
        with redirect_stdout(buf):
            os.chdir(self.repo)
            try:
                code = fn(*args, **kw)
            finally:
                os.chdir(cwd)
        return code, buf.getvalue()

    def reviewed(self):
        self.change()
        _, out = self.eot(FakeClaude({"findings": [BUG, NIT], "reviewed_paths": ["src/calc.py"]}))
        return {f["lens"]: f["id"] for f in out["findings"]}

    def test_human_label_needs_the_terminal(self):
        ids = self.reviewed()
        code, _ = self.run_in_repo(stats.main_label, [ids["correctness"], "wrong"], confirm=lambda q: False)
        self.assertEqual(code, 3)
        code, out = self.run_in_repo(stats.main_label, [ids["correctness"], "wrong"], confirm=lambda q: True)
        self.assertEqual((code, json.loads(out)["by"]), (0, "human"))

    def test_agent_label_needs_evidence_and_is_separate(self):
        ids = self.reviewed()
        no = lambda q: False  # noqa: E731 - no terminal
        self.assertEqual(self.run_in_repo(stats.main_label, [ids["correctness"], "fixed"], confirm=no)[0], 3)
        code, out = self.run_in_repo(stats.main_label, [ids["correctness"], "fixed", "--evidence", "tests/test_calc.py"],
                                     confirm=no)
        self.assertEqual((code, json.loads(out)["by"]), (0, "agent"))
        st = stats.stats(str(self.repo))
        self.assertEqual((st["labels_agent"]["fixed"], st["labels_human"]["fixed"], st["precision_human"]), (1, 0, None))

    def test_unknown_finding_is_refused(self):
        self.reviewed()
        self.assertEqual(self.run_in_repo(stats.main_label, ["rev-000000000000", "fixed"], confirm=lambda q: True)[0], 3)

    def test_stats_and_csv_rows(self):
        ids = self.reviewed()
        yes = lambda q: True  # noqa: E731
        self.run_in_repo(stats.main_label, [ids["correctness"], "fixed"], confirm=yes)
        self.run_in_repo(stats.main_label, [ids["simplify"], "noise"], confirm=yes)
        out_csv = self.tmp / "metrics.csv"
        code, out = self.run_in_repo(stats.main_stats, ["--csv", str(out_csv)])
        st = json.loads(out)["repo"]
        self.assertEqual((code, st["records"], st["tickets"], st["blocked"]), (0, 1, 1, 1))
        self.assertEqual((st["findings"]["blocking"], st["findings"]["advisory"], st["snr"]), (1, 1, 0.5))
        self.assertEqual((st["precision_human"], st["verifier_refutation_rate"]), (0.5, 0.0))
        rows = list(csv.reader(out_csv.open()))
        self.assertEqual(rows[0], ["date", "metric", "key", "value"])
        self.assertIn(["review_loop_precision_human", "repo", "0.5"], [r[1:] for r in rows])
        self.assertNotIn(BUG["title"], out_csv.read_text(), "counts only, never finding text")


    def test_finding_carried_across_rounds_counts_once(self):
        self.reviewed()
        self.write("src/calc.py", "def add(a, b):\n    return a - b  # 1\n")
        self.commit("fix: try")
        self.run_in_repo(recheck.main, ["--base", self.base, "--finder", "claude:sonnet"],
                         runner=FakeClaude({"findings": [], "reviewed_paths": ["src/calc.py"]}, "confirmed"))
        st = stats.stats(str(self.repo))
        self.assertEqual((st["records"], st["findings"]["blocking"], st["rounds_max"]), (2, 1, 2))

if __name__ == "__main__":
    unittest.main()


class ConfirmOnTtyTest(unittest.TestCase):
    """The real prompt, on a real terminal (a pty), with nothing injected."""

    def ask(self, typed: bytes) -> bool:
        import pty
        master, slave = pty.openpty()
        try:
            os.write(master, typed)
            return stats.confirm_on_tty("Accept?", tty=os.ttyname(slave))
        finally:
            os.close(master)
            os.close(slave)

    def test_y_on_a_terminal_is_a_yes(self):
        self.assertTrue(self.ask(b"y\n"))

    def test_anything_else_on_a_terminal_is_a_no(self):
        self.assertFalse(self.ask(b"n\n"))

    def test_no_terminal_is_a_no(self):
        self.assertFalse(stats.confirm_on_tty("Accept?", tty="/nonexistent/tty"))
