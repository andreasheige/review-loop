"""review-loop scan: D1 secrets (gitleaks), D2 hidden Unicode, D3 dependency lockfiles on one diff.

usage: review-loop scan (--staged | --range A..B) [--sarif PATH]

Stdout: one JSON object {findings, exit_code, summary[, error], tools}. Exit 0 pass, 1 block, 2 needs_human,
3 tool error. D1/D2 failures (scanner missing, hash mismatch, crash) are 3 = block, never 0; D3 lookup
failures are needs_human findings, never a pass.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import deps, gitdiff, normalise, unicode_check
from .secret_scan import Gitleaks
from .tools import ToolError


def run(repo: str, staged: bool, rng: str | None = None, sarif: str | None = None, net=None) -> dict:
    findings, errors, tools = [], [], {}
    try:
        repo = gitdiff.git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip()
        base = head = None
        if not staged:
            a, sep, b = (rng or "").partition("..")
            if not sep or b.startswith("."):
                raise gitdiff.GitError(f"--range must be A..B, got {rng!r}")
            base, head = gitdiff.verify_commit(repo, a), gitdiff.verify_commit(repo, b)
    except gitdiff.GitError as e:
        return result([], [str(e)], tools)

    leaks = None
    try:
        leaks = Gitleaks(repo, staged, base, head)  # runs while D2 and D3 do their part
        tools["gitleaks"] = leaks.version
    except (ToolError, OSError) as e:
        errors.append(f"D1: {e}")

    try:
        added = gitdiff.added_lines(repo, staged, base, head)
        findings += unicode_check.scan(added)
        lockfiles = [
            (p, gitdiff.show(repo, f"HEAD:{p}" if staged else f"{base}:{p}"), gitdiff.show(repo, f":{p}" if staged else f"{head}:{p}"))
            for p in added if Path(p).name in deps.LOCKFILES
        ]
        lockfiles = [(p, old, new) for p, old, new in lockfiles if new is not None]
        if lockfiles:
            findings += deps.scan(lockfiles, gitdiff.origin(repo), net)
    except gitdiff.GitError as e:
        errors.append(f"D2: {e}")
    finally:
        if leaks:
            try:
                findings += leaks.collect()
            except ToolError as e:
                errors.append(f"D1: {e}")
    return result(normalise.merge(findings), errors, tools, sarif)


def result(findings: list[dict], errors: list[str], tools: dict, sarif: str | None = None) -> dict:
    code, summary = normalise.outcome(findings, errors)
    out = {"findings": findings, "exit_code": code, "summary": summary, "tools": tools}
    if errors:
        out["error"] = "; ".join(errors)
    if sarif:
        normalise.write_sarif(sarif, findings, tools)
    return out


class Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse exits 2, which would read as needs_human
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(3)


def main(argv: list[str]) -> int:
    ap = Parser(prog="review-loop scan", description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true", help="scan the index diff")
    mode.add_argument("--range", metavar="A..B", help="scan the commits in A..B")
    ap.add_argument("--sarif", metavar="PATH", help="also write SARIF 2.1.0 here")
    ap.add_argument("--format", choices=["json", "text"], default="json", help="text: one line per finding, for git hooks")
    args = ap.parse_args(argv)
    try:
        out = run(".", args.staged, args.range, args.sarif)
    except Exception as e:  # noqa: BLE001 - an unexpected crash must be exit 3 (block), never 0
        out = result([], [f"internal error: {type(e).__name__}"], {})
    if args.format == "text":
        sys.stdout.write(text_report(out))
    else:
        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return out["exit_code"]


def text_report(out: dict) -> str:
    """Human summary for hooks: no secret values (findings never hold them), no raw hidden characters."""
    lines = [f"review-loop scan: {out['summary']}"]
    for f in out["findings"]:
        site = f["sites"][0]
        lines.append(f"  {f['status']:<11} {f['rule_class'] or '-':<15} {site['path']}:{site['start_line']}  {f['title']}  [{f['id']}]")
    if out.get("error"):
        lines.append(f"  error: {out['error']}")
    return "\n".join(lines) + "\n"
