"""review-loop land <pr> (plan 8.8): the only way an agent merges, and only a risk:low PR.

The tier is recomputed here (risk.assess) on the PR's head as GitHub has it, against a freshly fetched base: a
label, the PR text or the local checkout never count. Low also means a clean eot/recheck record for exactly
that content. The PR must be open, not a draft, mergeable, with no pending or failing checks. The merge is a
rebase-merge pinned with --match-head-commit, so a push after the check makes GitHub refuse it.

Everything else is refused with "waiting for Andreas" and the reasons. Each run is a line in <state>/land.jsonl.
Exit codes: 0 merged, 1 refused, 3 tool error. A bare `gh pr merge` stays denied for agents by the guard.
Known limit (Level 1): this file lives in an agent-writable checkout; land.jsonl is the audit trail.
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys

from . import risk, scan
from .gitdiff import GitError, git
from .secret_scan import state_dir

FIELDS = "number,url,isCrossRepository,state,isDraft,mergeable,baseRefName,headRefName,headRefOid,statusCheckRollup"
GITHUB_REPO = re.compile(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?/?$", re.I)
OK_CHECK = {"SUCCESS", "NEUTRAL", "SKIPPED"}


class LandError(Exception):
    pass


def default_gh(args: list[str], cwd: str) -> tuple[int, str]:
    p = subprocess.run(["gh", *args], cwd=cwd, capture_output=True, text=True)
    return p.returncode, p.stdout if p.returncode == 0 else p.stderr


def checks(rollup: list[dict]) -> tuple[list[str], list[str]]:
    """(pending, failing) check names. Check runs have status/conclusion, commit statuses have state."""
    pending, failing = [], []
    for c in rollup or []:
        name = c.get("name") or c.get("context") or "?"
        if "state" in c and "status" not in c:
            st = c.get("state")
            (pending if st in ("PENDING", "EXPECTED") else failing if st not in OK_CHECK else []).append(name)
        elif c.get("status") != "COMPLETED":
            pending.append(name)
        elif c.get("conclusion") not in OK_CHECK:
            failing.append(name)
    return pending, failing


def log(row: dict) -> None:
    try:
        state_dir().mkdir(parents=True, exist_ok=True)
        with open(state_dir() / "land.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
    except OSError:
        pass


def default_scan(repo: str, rng: str) -> dict:
    return scan.run(repo, False, rng, policy=True)


def same_repo(repo: str, pr_url: str) -> bool:
    """origin (as configured, before any insteadOf) is the repository the PR lives in."""
    url = git(repo, "config", "--get", "remote.origin.url", check=False).stdout.decode().strip()
    mine = GITHUB_REPO.search(url)
    theirs = re.search(r"github\.com/([^/]+/[^/]+)/pull/\d+", pr_url or "")
    return bool(mine and theirs and mine.group(1).lower() == theirs.group(1).lower())


def run(repo: str, pr: str, gh=default_gh, scan_fn=default_scan) -> tuple[int, str]:
    row = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), "pr": pr, "merged": False}
    try:
        code, out = gh(["pr", "view", pr, "--json", FIELDS], repo)
        if code:
            raise LandError(f"gh pr view failed: {out.strip()[:200]}")
        info = json.loads(out)
        sha, base, head_ref = info["headRefOid"], info["baseRefName"], info["headRefName"]
        row["head"] = sha
        if info.get("isCrossRepository") or not same_repo(repo, info.get("url", "")):
            raise LandError(f"PR {info.get('url')} is not from this repository's origin: land it by hand")
        remote = git(repo, "ls-remote", "origin", f"refs/heads/{head_ref}", check=False).stdout.decode().split()
        if not remote or remote[0] != sha:
            raise LandError(f"origin's {head_ref} is not the PR head {sha[:12]}: push it first")
        git(repo, "fetch", "-q", "origin", base, head_ref)
        refused = []
        if info["state"] != "OPEN" or info.get("isDraft"):
            refused.append(f"PR is {'a draft' if info.get('isDraft') else info['state'].lower()}")
        if info.get("mergeable") != "MERGEABLE":
            refused.append(f"PR is not mergeable ({str(info.get('mergeable')).lower()}): rebase onto {base}")
        pending, failing = checks(info.get("statusCheckRollup"))
        if pending:
            refused.append(f"checks pending: {', '.join(pending)} (try again when they finish)")
        if failing:
            refused.append(f"checks failing: {', '.join(failing)}")
        r = risk.assess(repo, f"origin/{base}", sha)
        # the record matches content, not history: scan the PR's own commits too (a secret added and removed)
        try:
            s = scan_fn(repo, f"{r['base']}..{sha}")
        except Exception as e:  # noqa: BLE001 - a scan that can't run is never a pass
            raise LandError(f"scan of the PR commits failed: {e}") from e
        if s.get("exit_code") != 0:
            refused.append(f"scan of the PR commits: exit {s.get('exit_code')}, "
                           f"{sum(f.get('status') in ('hard', 'needs_human', 'blocking') for f in s.get('findings', []))} finding(s)")
        row["tier"] = r["tier"]
        if r["tier"] != "low":
            refused.append(f"risk:{r['tier']}: " + "; ".join(r["reasons"]))
        if refused:
            row["refused"] = refused
            log(row)
            return 1, "Not landing; waiting for Andreas to review and merge:\n" + "\n".join(f"  - {x}" for x in refused)
        code, out = gh(["pr", "merge", pr, "--rebase", "--match-head-commit", sha], repo)
        if code:
            raise LandError(f"gh pr merge failed: {out.strip()[:200]}")
        row["merged"] = True
        log(row)
        return 0, f"Landed PR {pr} (risk:low, {r['files']} files, {r['lines']} lines) at {sha[:12]}."
    except (LandError, GitError, KeyError, ValueError) as e:
        row["error"] = str(e)[:300]
        log(row)
        return 3, f"review-loop land: {e}"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="review-loop land")
    ap.add_argument("pr")
    ap.add_argument("--repo", default=".")
    a = ap.parse_args(argv)
    code, msg = run(a.repo, a.pr)
    (sys.stdout if code == 0 else sys.stderr).write(msg + "\n")
    return code
