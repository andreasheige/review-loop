"""Fixture tests for `review-loop ui` (plan 7.1): axe, keyboard trap and screenshots, base vs head.

usage: REVIEW_LOOP_UI_NODE_MODULES=<a node_modules with playwright and axe-core> python3 -m unittest tests.test_ui -v

Skipped without that variable: review-loop installs no Node packages. The two sides are tiny static sites in the
shape of a built Storybook (index.json + iframe.html?id=...), so no Storybook build runs here.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from review_loop import ui

NM = os.environ.get("REVIEW_LOOP_UI_NODE_MODULES")
OK_BUTTON = '<button style="color:#000;background:#fff">Save</button>'
STORIES = {  # id -> (base html, head html)
    "button--primary": (OK_BUTTON, '<button style="color:#999;background:#aaa">Save</button>'),  # new contrast failure
    "panel--form": ('<input aria-label="Name"><button>Go</button>',
                    '<input aria-label="Name" id="trap" onkeydown="if(event.key===\'Tab\')event.preventDefault()">'
                    '<button>Go</button>'),  # new keyboard trap
    "card--default": ('<p style="color:#000;background:#fff">Hello</p>',
                      '<p style="color:#000;background:#fff">Hello there</p>'),  # visual change only
    "legacy--old": ('<p style="color:#bbb;background:#fff">Old</p>', '<p style="color:#bbb;background:#fff">Old</p>'),
}


def site(root: Path, side: int) -> Path:
    root.mkdir(parents=True)
    entries = {sid: {"id": sid, "type": "story", "importPath": "./src/Button.stories.tsx"} for sid in STORIES}
    (root / "index.json").write_text(json.dumps({"v": 5, "entries": entries}))
    pages = {sid: html[side] for sid, html in STORIES.items()}
    (root / "iframe.html").write_text(
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>story</title></head><body>'
        '<main id="storybook-root"></main><script>const pages=' + json.dumps(pages) +
        ';document.getElementById("storybook-root").innerHTML=pages[new URLSearchParams(location.search).get("id")]||"";'
        '</script></body></html>')
    return root


@unittest.skipUnless(NM and shutil.which("node"), "set REVIEW_LOOP_UI_NODE_MODULES (playwright + axe-core) to run")
class UiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="review-loop-ui-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
        self.git = lambda *a: subprocess.run(["git", *a], cwd=self.repo, env=env, check=True, capture_output=True)
        self.git("init", "-q", "-b", "main")
        (self.repo / "src").mkdir()
        (self.repo / "src/Button.tsx").write_text("export const Button = () => null;\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")

    def run_ui(self, changed="src/Button.tsx"):
        (self.repo / changed).write_text("export const Button = () => 1;\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "head")
        base, head = site(self.tmp / "base", 0), site(self.tmp / "head", 1)
        return ui.run(str(self.repo), "HEAD~1", "HEAD", (str(base), str(head)))

    def test_contrast_and_trap_block_visual_change_needs_human_old_goes_to_backlog(self):
        r = self.run_ui()
        by = {}
        for f in r["findings"]:
            by.setdefault(f["evidence"]["ref"].split(":", 1)[1], []).append(f)
        contrast = [f for f in by.get("axe-color-contrast", []) if "button--primary" in f["sites"][0]["path"]]
        self.assertTrue(contrast and all(f["status"] == "hard" for f in contrast), contrast)
        self.assertEqual({f["status"] for f in by["keyboard-trap"]}, {"hard"})
        self.assertIn("<story:panel--form>", {f["sites"][0]["path"] for f in by["keyboard-trap"]})
        visual = {f["sites"][0]["path"] for f in by["visual-change"]}
        self.assertIn("<story:card--default>", visual)
        self.assertEqual({f["status"] for f in by["visual-change"]}, {"needs_human"})
        old = [f for f in by.get("axe-color-contrast", []) if "legacy--old" in f["sites"][0]["path"]]
        self.assertTrue(old and all(f["status"] == "advisory" and f["introduced_by"] == "pre-existing" for f in old))
        self.assertEqual(r["outcome"]["exit_code"], 1)
        pid = next((self.repo / ".git/review-loop").iterdir())
        self.assertTrue((pid / "ui.json").is_file())

    def test_non_ui_change_is_not_applicable(self):
        (self.repo / "README.md").write_text("x\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "docs")
        r = ui.run(str(self.repo), "HEAD~1", "HEAD", None)
        self.assertEqual((r["status"], r["outcome"]["exit_code"]), ("not_applicable", 0))


class OptInTest(unittest.TestCase):
    """No Playwright in the repo: the opt-in prompt (plan 7.4). Needs no Node."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="review-loop-optin-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        (self.tmp / "empty-nm").mkdir()
        patcher = mock.patch.dict(os.environ, {"REVIEW_LOOP_UI_NODE_MODULES": str(self.tmp / "empty-nm"),
                                               "REVIEW_LOOP_STATE_DIR": str(self.tmp / "state"),
                                               "GIT_CONFIG_GLOBAL": "/dev/null"})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
        self.git = lambda *a: subprocess.run(["git", *a], cwd=self.repo, env=env, check=True, capture_output=True)
        self.git("init", "-q", "-b", "main")
        self.git("remote", "add", "origin", "https://github.com/andreasheige/ui-fixture.git")
        (self.repo / "Button.tsx").write_text("a\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")
        (self.repo / "Button.tsx").write_text("b\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "head")

    def ui(self, ask):
        return ui.run(str(self.repo), "HEAD~1", "HEAD", None, ask=ask)

    def never_asked(self, question):
        raise AssertionError("asked again")

    def test_an_agent_cannot_answer(self):
        r = self.ui(lambda q: None)  # no /dev/tty
        self.assertEqual((r["status"], r["outcome"]["exit_code"]), ("no_playwright:unanswered", 0))
        self.assertFalse(ui.optin_path().exists())

    def test_not_now_is_not_asked_again_within_7_days(self):
        self.assertEqual(self.ui(lambda q: "n")["status"], "no_playwright:snoozed")
        self.assertEqual(self.ui(self.never_asked)["status"], "no_playwright:snoozed")
        data = json.loads(ui.optin_path().read_text())
        key = "https://github.com/andreasheige/ui-fixture.git"
        data[key]["at"] = "2026-01-01T00:00:00+00:00"
        ui.optin_path().write_text(json.dumps(data))
        asked = []
        self.ui(lambda q: asked.append(q) or "n")
        self.assertEqual(len(asked), 1)

    def test_never_sticks_and_shows_in_the_digest(self):
        self.assertEqual(self.ui(lambda q: "v")["status"], "no_playwright:never")
        self.assertEqual(self.ui(self.never_asked)["status"], "no_playwright:never")
        from review_loop import sweep
        rows = [line.split("\t") for line in sweep.digest([self.tmp]).splitlines()]
        self.assertEqual(rows[0][-1], "ui opt-in")
        self.assertEqual([r[-1] for r in rows if r[0] == str(self.repo)], ["never"])


if __name__ == "__main__":
    unittest.main()
