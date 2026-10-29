"""review-loop gate: the pre-push scan. The global pre-push hook's one review-loop call.

usage: review-loop gate <remote> [<url>] [--block]     (pre-push ref lines on stdin; the URL is what's asked)

For each pushed ref that isn't a delete, scans the commits being pushed (`scan --policy`, D1–D3 plus the
control-weakening classes and accepts; D2 also per pushed commit) and prints one text report per ref, with the accept command for every
needs_human finding. The base is the remote's old sha from the hook's own stdin, or, for a new branch or a sha
not present locally, the remote's default branch from `git ls-remote` — never a local tracking ref, which
anything with write access to .git can forge. A remote with no refs yet (first push) scans every pushed commit.
No base at all (unreachable remote, commits not fetched) is a tool error.

Mode: warn (default) prints and exits 0; block exits 1 on any block, needs_human or tool error. Block comes
from the file ~/.config/review-loop/gate-mode holding `block`, or from --block; neither can make it weaker.
Each run appends one line to <state dir>/gate.jsonl (repo, mode, exit, rule classes, ms; no paths or values),
for the per-rule precision check before switching to block and the p95 < 10 s check.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from . import gitdiff, normalise, scan, unicode_check
from . import policy as policy_classes
from .secret_scan import state_dir
from .tools import SAFE_PATH

ZERO = re.compile(r"^0+$")
MAX_COMMITS = 500  # per-commit D2 beyond this many pushed commits would blow the push-time budget
SHA = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


def mode_file() -> Path:
    return Path(os.environ.get("REVIEW_LOOP_GATE_MODE_FILE") or Path.home() / ".config/review-loop/gate-mode")


def mode(block_flag: bool) -> str:
    try:
        configured = mode_file().read_text().strip()
    except OSError:
        configured = ""
    return "block" if block_flag or configured == "block" else "warn"


def parse_refs(text: str) -> list[tuple[str, str, str, str]]:
    """Pre-push stdin: `<local ref> <local sha> <remote ref> <remote sha>` per line."""
    refs = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 4 or not (SHA.match(parts[1]) and SHA.match(parts[3])):
            raise ValueError("unexpected pre-push input line")
        refs.append((parts[0], parts[1], parts[2], parts[3]))
    return refs


def has_commit(repo: str, sha: str) -> bool:
    return gitdiff.git(repo, "cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode == 0


EMPTY = "empty"


def remote_default(repo: str, remote: str) -> str | None:
    """The sha of the remote's HEAD, asked of the remote itself; EMPTY for a remote with no refs yet;
    None when unreachable or when it has refs but no HEAD."""
    env = dict(os.environ, PATH=SAFE_PATH, GIT_TERMINAL_PROMPT="0", LC_ALL="C")
    try:
        p = subprocess.run(["git", "-C", repo, "ls-remote", "--end-of-options", remote],
                           capture_output=True, env=env, timeout=8)
    except subprocess.TimeoutExpired:
        return None
    if p.returncode != 0:
        return None
    rows = [line.split("\t") for line in p.stdout.decode().splitlines()]
    if not rows:
        return EMPTY
    return next((sha for sha, *name in rows if name == ["HEAD"] and SHA.match(sha)), None)


def empty_root(repo: str) -> str:
    """A parentless commit of the empty tree: `<it>..<sha>` is then every commit reachable from sha.
    Fixed author and date, so it is the same object every time (unreferenced, gc drops it)."""
    env = dict(os.environ, PATH=SAFE_PATH, GIT_AUTHOR_NAME="review-loop", GIT_AUTHOR_EMAIL="review-loop@invalid",
               GIT_COMMITTER_NAME="review-loop", GIT_COMMITTER_EMAIL="review-loop@invalid",
               GIT_AUTHOR_DATE="1970-01-01T00:00:00Z", GIT_COMMITTER_DATE="1970-01-01T00:00:00Z")
    tree = subprocess.run(["git", "-C", repo, "hash-object", "-t", "tree", "-w", "--stdin"], input=b"",
                          capture_output=True, env=env, check=True).stdout.decode().strip()
    p = subprocess.run(["git", "-C", repo, "commit-tree", tree, "-m", "review-loop gate: empty base"],
                       capture_output=True, env=env, check=True)
    return p.stdout.decode().strip()


def base_for(repo: str, remote: str, remote_sha: str) -> str | None:
    """remote is where the push goes: the hook's URL argument, so a remote.<name>.pushurl that differs from
    the fetch URL is asked, not the fetch side."""
    if not ZERO.match(remote_sha) and has_commit(repo, remote_sha):
        return remote_sha
    default = remote_default(repo, remote)
    if default == EMPTY:
        return empty_root(repo)
    return default if default and has_commit(repo, default) else None


def intermediate_unicode(repo: str, base: str, head: str) -> list[dict]:
    """D2 on each pushed commit: hidden Unicode added and removed again within one push is still published in
    the history, and scan.run only sees the endpoint diff. D3 and the policy classes stay endpoint-only: a
    lockfile or config change undone later in the push never reaches the pushed tree."""
    commits = gitdiff.git(repo, "rev-list", "--reverse", "--no-merges", f"{base}..{head}").stdout.decode().split()
    if len(commits) < 2:
        return []
    found = []
    for c in commits[:MAX_COMMITS]:
        parent = gitdiff.git(repo, "rev-parse", "--verify", "--quiet", f"{c}^", check=False).stdout.decode().strip()
        found += unicode_check.scan(policy_classes.text_lines(repo, False, parent or empty_root(repo), c, removed=False))
    return found


def run(repo: str, remote: str, stdin: str, block: bool = False) -> tuple[int, str]:
    start, gate_mode = time.monotonic(), mode(block)
    reports, codes, classes = [], [], []
    try:
        repo = gitdiff.git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip()
        refs = parse_refs(stdin)
    except (gitdiff.GitError, ValueError) as e:
        refs, codes = [], [3]
        reports.append(f"review-loop gate: {e}\n")
    for local_ref, local_sha, remote_ref, remote_sha in refs:
        if ZERO.match(local_sha):
            continue  # a delete pushes no content
        base = base_for(repo, remote, remote_sha)
        if base is None:
            codes.append(3)
            reports.append(f"review-loop gate: {remote_ref}: no base to compare with (remote unreachable, or its "
                           f"commits aren't fetched): run `git fetch {remote}` and push again\n")
            continue
        if base == local_sha:
            continue
        out = scan.run(repo, False, f"{base}..{local_sha}", policy=True)
        extra = intermediate_unicode(repo, base, local_sha)
        if extra:
            errors = [out["error"]] if out.get("error") else []
            out = {**scan.result(normalise.merge(out["findings"] + extra), errors, out["tools"]), "policy": True}
        codes.append(out["exit_code"])
        classes += [f["rule_class"] for f in out["findings"] if f["status"] in ("hard", "needs_human")]
        if out["exit_code"]:
            reports.append(f"{remote_ref}: " + scan.text_report(out))
    code = max(codes, default=0)
    log(repo, gate_mode, code, classes, round((time.monotonic() - start) * 1000))
    if not code:
        return 0, ""
    if gate_mode == "warn":
        return 0, "".join(f"⚠ {r}" for r in reports) + "  (gate in warn mode: push allowed)\n"
    return 1, "".join(f"✘ {r}" for r in reports) + "  Push refused (review-loop gate). Fix the findings, or accept a needs_human one at a terminal.\n"


def log(repo: str, gate_mode: str, code: int, classes: list, ms: int) -> None:
    try:
        d = state_dir()
        d.mkdir(parents=True, exist_ok=True)
        line = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "repo": Path(repo).name, "mode": gate_mode, "exit": code, "classes": sorted(set(c or "-" for c in classes)), "ms": ms}
        with open(d / "gate.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(line) + "\n")
    except OSError:
        pass  # the log feeds metrics; it must never change the push outcome


def main(argv: list[str]) -> int:
    args = [a for a in argv if a != "--block"]
    if not args or args[0].startswith("-"):
        sys.stderr.write("usage: review-loop gate <remote> [<url>] [--block]   (pre-push ref lines on stdin)\n")
        return 3
    try:
        code, text = run(".", args[1] if len(args) > 1 else args[0], sys.stdin.read(), "--block" in argv)
    except Exception as e:  # noqa: BLE001 - a crash must not pass silently: warn or block like a tool error
        code, text = (1 if mode("--block" in argv) == "block" else 0), f"review-loop gate: internal error: {type(e).__name__}\n"
    sys.stderr.write(text)
    return code
