#!/usr/bin/env python3
"""Score `review-loop epic` output against expected.json.

usage: score.py BUGGY.json [CLEAN.json]      (the JSON `review-loop epic` printed, record_path included)

Buggy epic: per seeded bug, the non-discarded findings whose sites overlap one of the bug's sites (same path,
line ranges overlap within baseline.TOLERANCE). Overlap is necessary, not sufficient: a bug counts as found only
if such a finding also describes that bug, which a human judges from the titles printed here.
Clean twin: every blocking/proven/hard finding is a false positive.
Both: chunk coverage, i.e. the record's chunks list each file of the epic diff exactly once (parts once each).
Stdlib only.
"""
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from baseline import TOLERANCE  # noqa: E402 - needs the sys.path entry above


def overlaps(site, finding):
    return any(s["path"] == site["path"] and s["start_line"] - TOLERANCE <= site["end_line"]
               and site["start_line"] <= s["end_line"] + TOLERANCE for s in finding["sites"])


def coverage(rec):
    e = rec.get("epic") or {}
    seen = Counter((p, tuple(c.get("part") or ())) for c in e.get("chunks", []) for p in c["paths"])
    return bool(seen) and all(k == 1 for k in seen.values())


def summary(rec):
    workers = sorted({f"{w['role']}={w['harness']}:{w['model']}" for w in rec.get("workers", [])})
    wall = (rec.get("epic") or {}).get("wall_seconds")
    return f"exit {rec['outcome']['exit_code']} {rec['outcome']['summary']}, wall {wall}s, {', '.join(workers)}"


def main(argv):
    exp = json.loads((HERE / "expected.json").read_text())
    buggy = json.loads(Path(argv[1]).read_text())
    print(f"buggy: {summary(buggy)}; chunks cover the diff once: {coverage(buggy)}")
    shown = [f for f in buggy["findings"] if f["status"] != "discarded"]
    for bug in exp["bugs"]:
        hits = [f for f in shown if any(overlaps(s, f) for s in bug["sites"])]
        print(f"  {bug['id']:34} {len(hits)} overlapping kept finding(s)")
        for f in hits:
            print(f"      {f['status']:<9} {f['lens']:<11} {f['title'][:110]}  [{f['id']}]")
    other = [f for f in shown if not any(overlaps(s, f) for b in exp["bugs"] for s in b["sites"])]
    for f in other:
        print(f"  (no bug site) {f['status']:<9} {f['lens']:<11} {f['title'][:100]}")
    if len(argv) > 2:
        clean = json.loads(Path(argv[2]).read_text())
        fps = [f for f in clean["findings"] if f["status"] in ("blocking", "proven", "hard")]
        print(f"clean: {summary(clean)}; chunks cover the diff once: {coverage(clean)}; blocking FPs: {len(fps)}")
        for f in clean["findings"]:
            if f["status"] != "discarded":
                print(f"      {f['status']:<9} {f['lens']:<11} {f['title'][:110]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
