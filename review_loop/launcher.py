"""Shared worker launcher: every finder/verifier runs in a scratch detached worktree with agent config stripped,
under a minimal environment, so nothing from the reviewed repo or the user's harness setup loads into the worker.

What each layer stops:
- scratch worktree + STRIP: planted `.claude/settings.json` hooks, `.mcp.json` servers, AGENTS.md/CLAUDE.md
  instructions, and tracked `.env*` files in the reviewed repo. Git hooks are off for the checkout itself.
- worker_env: tokens and session vars of the calling harness (GITHUB_TOKEN, TT_*, CLAUDECODE, ...).
- codex_home: a scratch CODEX_HOME holding only a link to auth.json, so ~/.codex hooks.json (tt), AGENTS.md,
  rules and memories never load. Claude's equivalent is --restricted --safe-mode in workers.run_claude.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .gitdiff import git, verify_commit

STRIP_NAMES = {".claude", ".codex", ".mcp.json", "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENTS.override.md"}
STRIP_PATHS = (".github/copilot-instructions.md",)
ENV_KEEP = ("PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TERM",
            "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "CLAUDE_CONFIG_DIR")


def strip(root: Path) -> list[str]:
    """Remove agent config and .env* anywhere under root (never descending into .git); returns removed paths."""
    removed = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in [*dirnames, *filenames]:
            if name in STRIP_NAMES or name.startswith(".env"):
                p = Path(dirpath) / name
                shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
                removed.append(str(p.relative_to(root)))
        dirnames[:] = [d for d in dirnames if d not in STRIP_NAMES and not d.startswith(".env")]
    for rel in STRIP_PATHS:
        p = root / rel
        if p.is_file() or p.is_symlink():
            p.unlink()
            removed.append(rel)
    return sorted(removed)


@contextmanager
def scratch_worktree(repo: str, rev: str = "HEAD"):
    """Yield the path of a detached, stripped worktree of repo at rev; removed again on exit."""
    sha = verify_commit(repo, rev)
    parent = Path(tempfile.mkdtemp(prefix="review-loop-wt-"))
    wt = parent / "wt"
    try:
        # hooksPath=/dev/null: the reviewed repo's post-checkout hook must not run
        git(repo, "-c", "core.hooksPath=/dev/null", "worktree", "add", "--detach", "--quiet", str(wt), sha)
        strip(wt)
        yield str(wt)
    finally:
        git(repo, "worktree", "remove", "--force", str(wt), check=False)
        shutil.rmtree(parent, ignore_errors=True)
        git(repo, "worktree", "prune", check=False)


def worker_env(extra: dict | None = None) -> dict:
    env = {k: os.environ[k] for k in ENV_KEEP if k in os.environ}
    env.update(extra or {})
    return env


@contextmanager
def codex_home():
    """A scratch CODEX_HOME with auth.json linked from the real one (never read here)."""
    real = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")
    with tempfile.TemporaryDirectory(prefix="review-loop-codex-home-") as td:
        if (real / "auth.json").exists():
            os.symlink(real / "auth.json", Path(td) / "auth.json")
        yield td
