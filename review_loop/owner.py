"""Whose repos are whose on this machine, from plain files in the config dir (the human owner edits them; agents can't):

  owner-origins.txt  one origin prefix per line, e.g. github.com/<you>/ — repos whose dependency names may go to
                     online lookups (OSV, registries)
  client-roots.txt   one directory per line (~ expands) — client repos: sensitive, offline only, swept by default

Blank lines and # comments are ignored. A missing file is the cautious reading: only a repo without a remote is
yours, and there are no client roots. A client-roots.txt that exists but can't be read makes every repo a client
repo (sensitive, offline), so a broken policy never turns the protection off.
"""
from __future__ import annotations

import re
from pathlib import Path

CONFIG_DIR = Path.home() / ".config/review-loop"


def _lines(name: str) -> list[str] | None:
    """[] when the file is missing, None when it exists but can't be read."""
    path = CONFIG_DIR / name
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None if path.is_symlink() else []  # a dangling link is a broken policy, not a missing one
    except (OSError, UnicodeDecodeError):
        return None
    return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]


def normalise_origin(url: str) -> str:
    """git@host:owner/repo, ssh://git@host/owner/repo and https://user@host/owner/repo all become host/owner/repo."""
    url = re.sub(r"^[a-z+]+://", "", url.strip())
    url = re.sub(r"^[^@/]+@", "", url)
    return re.sub(r"^([^/:]+):(?!\d+/)", r"\1/", url)


def own_origin(origin: str | None) -> bool:
    if origin is None:
        return True
    norm = normalise_origin(origin)
    return any(norm.startswith(p) for p in _lines("owner-origins.txt") or [])


def client_roots() -> list[Path]:
    roots = [Path(l).expanduser() for l in _lines("client-roots.txt") or []]
    return [r.resolve() for r in roots if r.is_dir()]


def in_client_root(repo: str) -> bool:
    if _lines("client-roots.txt") is None:
        return True
    path = Path(repo).resolve()
    return any(path.is_relative_to(r) for r in client_roots())
