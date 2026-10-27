"""Tool hits → contract findings (contract/finding.schema.json), exit code, and SARIF 2.1.0.

Ids are stable across --staged, --range and rebase: sec-<tool>-<sha1(ruleId|path|K)[:12]>, never a line
number or commit SHA. A hit whose lines do not overlap added lines is advisory / pre-existing.
"""
from __future__ import annotations

import hashlib
import json
import os

from . import VERSION

SUMMARY = {0: "no_findings_reported (unverified)", 1: "blocked", 2: "needs_human", 3: "error"}
SARIF_LEVEL = {"hard": "error", "needs_human": "warning", "advisory": "note"}


def sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", "surrogatepass")).hexdigest()


def stable_id(tool: str, rule: str, path: str, k: str) -> str:
    return f"sec-{tool}-{sha1(f'{rule}|{path}|{k}')[:12]}"


def finding(*, tool, rule, path, k, lines, status, rule_class, surface, title, reasoning, ref, introduced=True, body=None):
    f = {
        "id": stable_id(tool, rule, path, k),
        "reasoning": reasoning,
        "lens": "security",
        "surface": surface,
        "title": title[:200],
        "sites": [{"path": path, "start_line": lines[0], "end_line": lines[1]}],
        "failure_scenario": None,
        "evidence": {"kind": "tool", "ref": ref},
        "rule_class": rule_class,
        "introduced_by": "diff" if introduced else "pre-existing",
        "status": status if introduced else "advisory",
    }
    if body:
        f["body"] = body
    return f


def merge(findings: list[dict]) -> list[dict]:
    """Same id twice (e.g. the same secret on two lines of one file) is one finding with several sites."""
    out: dict[str, dict] = {}
    for f in findings:
        if f["id"] in out:
            sites = out[f["id"]]["sites"]
            sites += [s for s in f["sites"] if s not in sites]
        else:
            out[f["id"]] = f
    return list(out.values())


def outcome(findings: list[dict], errors: list[str]) -> tuple[int, str]:
    statuses = {f["status"] for f in findings}
    if errors:
        return 3, SUMMARY[3]
    if "hard" in statuses:
        return 1, SUMMARY[1]
    if "needs_human" in statuses:
        return 2, SUMMARY[2]
    return 0, "advisory_only" if findings else SUMMARY[0]


def write_sarif(path: str, findings: list[dict], tools: dict[str, str]) -> None:
    rules = sorted({f["evidence"]["ref"].rsplit(":", 1)[-1] for f in findings})
    results = [{
        "ruleId": f["evidence"]["ref"].rsplit(":", 1)[-1],
        "level": SARIF_LEVEL.get(f["status"], "note"),
        "message": {"text": f["title"]},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": s["path"]},
            "region": {"startLine": s["start_line"], "endLine": s["end_line"]},
        }} for s in f["sites"]],
        "partialFingerprints": {"reviewLoopId/v1": f["id"]},
        "properties": {k: f[k] for k in ("status", "rule_class", "introduced_by", "surface")},
    } for f in findings]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "review-loop", "version": VERSION, "rules": [{"id": r} for r in rules],
                                "properties": {"scanners": tools}}},
            "results": results,
        }],
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f, indent=2)
