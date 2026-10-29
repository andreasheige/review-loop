"""Git plumbing: the reviewed diff as {path: {new line number: text}} of ADDED lines, plus file reads."""
from __future__ import annotations

import os
import re
import subprocess

from .tools import SAFE_PATH

HUNK = re.compile(rb"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
OLD_HUNK = re.compile(rb"^@@ -(\d+)")


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


def added_lines(repo: str, staged: bool, base: str | None = None, head: str | None = None,
                text: bool = False) -> dict[str, dict[int, str]]:
    """{path: {line number: added text}}. text=True also reads files git would show as binary (a committed
    `-diff` attribute must not hide them); the caller drops real binaries."""
    return _lines(repo, staged, base, head, removed=False, text=text, renames=True)


def removed_lines(repo: str, staged: bool, base: str | None = None, head: str | None = None,
                  text: bool = False) -> dict[str, dict[int, str]]:
    """Like added_lines, for the old side: {old path: {old line number: text}}. No rename detection, so a file
    moved elsewhere shows every line as removed."""
    return _lines(repo, staged, base, head, removed=True, text=text, renames=False)


def _lines(repo, staged, base, head, removed: bool, text: bool, renames: bool) -> dict[str, dict[int, str]]:
    out = git(repo, "diff", "-U0", "-M" if renames else "--no-renames", *(["--text", "--no-textconv"] if text else []),
              "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/",
              *diff_args(staged, base, head)).stdout
    return parse(out, removed)


def parse(out: bytes, removed: bool = False) -> dict[str, dict[int, str]]:
    """{path: {line number: text}} of the added (or removed) lines in -U0 diff output with a/ b/ prefixes."""
    files: dict[str, dict[int, str]] = {}
    path, lineno, in_hunk = None, 0, False
    header, prefix, sign, hunk = (b"--- ", "a/", b"-", OLD_HUNK) if removed else (b"+++ ", "b/", b"+", HUNK)
    # split on \n only: str.splitlines() would also split on U+2028, U+0085 … and shift line numbers
    for raw in out.split(b"\n"):
        if raw.startswith(b"diff --git "):
            path, in_hunk = None, False
        elif not in_hunk and raw.startswith(header):
            target = raw[4:]
            if target.endswith(b"\t"):  # git appends a tab to header paths that contain a space
                target = target[:-1]
            path = None if target == b"/dev/null" else _unquote(target)
            if path and path.startswith(prefix):
                path = path[2:]
        elif raw.startswith(b"@@"):
            m = hunk.match(raw)
            in_hunk, lineno = bool(m and path), int(m.group(1)) if m else 0
        elif in_hunk and raw.startswith(sign):
            files.setdefault(path, {})[lineno] = raw[1:].decode("utf-8", "replace")
            lineno += 1
        elif in_hunk and raw.startswith(b" "):
            lineno += 1
    return files


def is_binary(repo: str, spec: str) -> bool:
    """True when the blob at <rev>:<path> (or :<path>) holds a NUL byte; False when it does not exist."""
    p = git(repo, "cat-file", "blob", spec, check=False)
    return p.returncode == 0 and b"\0" in p.stdout[:65536]


def show(repo: str, spec: str) -> str | None:
    """Content of <rev>:<path> (or :<path> for the index); None when it does not exist."""
    p = git(repo, "show", spec, check=False)
    return p.stdout.decode("utf-8", "replace") if p.returncode == 0 else None


def origin(repo: str) -> str | None:
    p = git(repo, "remote", "get-url", "origin", check=False)
    return p.stdout.decode().strip() if p.returncode == 0 else None
