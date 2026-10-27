"""Git plumbing: the reviewed diff as {path: {new line number: text}} of ADDED lines, plus file reads."""
from __future__ import annotations

import os
import re
import subprocess

from .tools import SAFE_PATH

HUNK = re.compile(rb"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitError(Exception):
    pass


def git(repo: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    env = dict(os.environ, PATH=SAFE_PATH, GIT_PAGER="cat", LC_ALL="C")
    p = subprocess.run(["git", "-C", repo, "-c", "core.quotePath=false", *args], capture_output=True, env=env)
    if check and p.returncode != 0:
        raise GitError(f"git {args[0]} failed ({p.returncode})")
    return p


def verify_commit(repo: str, rev: str) -> str:
    if not rev or rev.startswith("-"):
        raise GitError(f"bad revision {rev!r}")
    return git(repo, "rev-parse", "--verify", "--quiet", "--end-of-options", rev + "^{commit}").stdout.decode().strip()


def diff_args(staged: bool, base: str | None, head: str | None) -> list[str]:
    return ["--cached"] if staged else [base, head]


def _unquote(raw: bytes) -> str:
    # git C-quotes paths with control chars or quotes even with core.quotePath=false
    if raw.startswith(b'"') and raw.endswith(b'"'):
        return raw[1:-1].decode("unicode_escape").encode("latin-1").decode("utf-8", "replace")
    return raw.decode("utf-8", "replace")


def added_lines(repo: str, staged: bool, base: str | None = None, head: str | None = None) -> dict[str, dict[int, str]]:
    out = git(repo, "diff", "-U0", "-M", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/",
              *diff_args(staged, base, head)).stdout
    files: dict[str, dict[int, str]] = {}
    path, lineno, in_hunk = None, 0, False
    # split on \n only: str.splitlines() would also split on U+2028, U+0085 … and shift line numbers
    for raw in out.split(b"\n"):
        if raw.startswith(b"diff --git "):
            path, in_hunk = None, False
        elif not in_hunk and raw.startswith(b"+++ "):
            target = raw[4:]
            path = None if target == b"/dev/null" else _unquote(target)
            if path and path.startswith("b/"):
                path = path[2:]
        elif raw.startswith(b"@@"):
            m = HUNK.match(raw)
            in_hunk, lineno = bool(m and path), int(m.group(1)) if m else 0
        elif in_hunk and raw.startswith(b"+"):
            files.setdefault(path, {})[lineno] = raw[1:].decode("utf-8", "replace")
            lineno += 1
        elif in_hunk and raw.startswith(b" "):
            lineno += 1
    return files


def show(repo: str, spec: str) -> str | None:
    """Content of <rev>:<path> (or :<path> for the index); None when it does not exist."""
    p = git(repo, "show", spec, check=False)
    return p.stdout.decode("utf-8", "replace") if p.returncode == 0 else None


def origin(repo: str) -> str | None:
    p = git(repo, "remote", "get-url", "origin", check=False)
    return p.stdout.decode().strip() if p.returncode == 0 else None
