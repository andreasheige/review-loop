"""Pinned scanner binaries: absolute path + sha256 from tools.lock, never PATH.

tools.lock is TSV: tool, version, realpath, sha256 (# comments allowed). Env REVIEW_LOOP_TOOLS_LOCK overrides
the path (tests). Any mismatch raises ToolError; callers decide whether that fails closed (D1/D2) or goes to
needs_human (D3).
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

# Fixed PATH for every subprocess we start (git, and git as called by gitleaks), so a stub earlier on the
# caller's PATH cannot feed the scanners a fake diff.
SAFE_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"


class ToolError(Exception):
    pass


def lock_path() -> Path:
    return Path(os.environ.get("REVIEW_LOOP_TOOLS_LOCK") or Path.home() / ".config/review-loop/tools.lock")


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def resolve(tool: str) -> tuple[str, str]:
    """Return (absolute path, version) of a pinned tool after checking its sha256, or raise ToolError."""
    lock = lock_path()
    try:
        rows = [line.split("\t") for line in lock.read_text().splitlines() if line.strip() and not line.startswith("#")]
    except OSError as e:
        raise ToolError(f"tools.lock unreadable: {lock} ({e.strerror})")
    row = next((r for r in rows if r[0] == tool), None)
    if row is None or len(row) != 4:
        raise ToolError(f"{tool} not pinned in {lock}")
    _, version, path, digest = row
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        raise ToolError(f"{tool}: locked path is not an absolute real path")
    if not (os.path.isfile(path) and os.access(path, os.X_OK)):
        raise ToolError(f"{tool}: missing at locked path {path}")
    if sha256(path) != digest.strip().lower():
        raise ToolError(f"{tool}: sha256 mismatch at {path}")
    return path, version
