"""review-loop label / stats: how the review loop does, from its own records. Counts only, never finding text.

usage: review-loop label <finding-id> fixed|wrong|intentional|noise [--evidence TEXT] [--note TEXT]
       review-loop stats [--repo PATH]... [--csv PATH] [--format json|text]

label: stored in $(git rev-parse --git-common-dir)/review-loop/labels.jsonl. A human label needs a "y" typed at the
terminal (/dev/tty), which an agent's shell does not have. Without one, only `fixed` and `noise` can be given, with
--evidence (a test or a citation), and they count as agent labels, apart from human ones.

stats: over every eot/recheck record of each repo. Precision = (fixed + intentional) / all labelled, human labels
only. --csv appends `date,metric,key,value` rows (key = repo directory name), the agent-safety metrics.csv format.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
from datetime import date, datetime, timezone
from pathlib import Path

from . import eot, scan
from .gitdiff import GitError, git

LABELS = ("fixed", "wrong", "intentional", "noise")
AGENT_LABELS = ("fixed", "noise")


def common_dir(repo: str) -> Path:
    top = git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip()
    return Path(top, git(top, "rev-parse", "--git-common-dir").stdout.decode().strip())


def find(common: Path, finding_id: str) -> tuple[dict, dict] | None:
    """(record, finding) for the newest record holding the id."""
    hits = [(r, f) for r, _ in eot.records(common) for f in r["findings"] if f["id"] == finding_id]
    return max(hits, key=lambda x: x[0]["created_at"]) if hits else None


def confirm_on_tty(question: str) -> bool:
    try:
        with open("/dev/tty", "r+") as tty:
            tty.write(f"{question} [y/N] ")
            tty.flush()
            return tty.readline().strip().lower() == "y"
    except OSError:
        return False


def label(repo: str, finding_id: str, value: str, evidence: str | None, note: str | None, confirm=confirm_on_tty) -> dict:
    common = common_dir(repo)
    hit = find(common, finding_id)
    if not hit:
        raise eot.EotError(f"no finding {finding_id} in this repo's records")
    rec, f = hit
    if confirm(f"Label {finding_id} ({f['status']}, {f['lens']}, {f['sites'][0]['path']}) as {value}?"):
        by = "human"
    elif value in AGENT_LABELS and evidence:
        by = "agent"
    else:
        raise eot.EotError(f"`{value}` needs a human at the terminal" if value not in AGENT_LABELS
                           else "an agent label needs --evidence (a test or a citation)")
    row = {"finding_id": finding_id, "label": value, "by": by, "evidence": evidence, "note": note,
           "status": f["status"], "patch_id": rec["key"]["patch_id"], "round": rec["round"],
           "labelled_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    with open(common / "review-loop" / "labels.jsonl", "a") as fh:
        fh.write(json.dumps(row) + "\n")
    return row


def lines(path: Path) -> list[dict]:
    try:
        return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]
    except (OSError, ValueError):
        return []


def stats(repo: str) -> dict:
    common = common_dir(repo)
    recs = sorted((r for r, _ in eot.records(common)), key=lambda r: (r["created_at"], r["round"]))
    first, last = {}, {}  # a finding carried across rounds counts once: found as in its first round, now as in its last
    for r in recs:
        for f in r["findings"]:
            first.setdefault(f["id"], f)
            last[f["id"]] = f
    findings = list(last.values())
    model = [f for f in first.values() if f["id"].startswith("rev-")]
    verified = [f for f in model if f.get("verification")]
    rounds: dict[str, int] = {}
    for r in recs:
        b = r.get("branch") or r["key"]["patch_id"]
        rounds[b] = max(rounds.get(b, 0), r["round"])
    walls = [sum(w.get("wall_seconds", 0) for w in r.get("workers", [])) for r in recs if r.get("workers")]
    tokens = [sum(w.get("tokens", 0) for w in r.get("workers", [])) for r in recs if r.get("workers")]
    labels = lines(common / "review-loop" / "labels.jsonl")
    latest = {}
    for row in labels:  # the last label per (finding, who) counts
        latest[(row["finding_id"], row["by"])] = row["label"]
    human = [v for (_, by), v in latest.items() if by == "human"]
    agent = [v for (_, by), v in latest.items() if by == "agent"]
    shown = [f for f in model if f["status"] != "discarded"]
    return {
        "records": len(recs), "tickets": len(rounds),
        "rounds_max": max(rounds.values(), default=0),
        "rounds_median": statistics.median(rounds.values()) if rounds else None,
        "errors": sum(r["outcome"]["exit_code"] == 3 for r in recs),
        "blocked": sum(r["outcome"]["exit_code"] == 1 for r in recs),
        "needs_human": sum(r["outcome"]["exit_code"] == 2 for r in recs),
        "findings": {s: sum(f["status"] == s for f in findings)
                     for s in ("hard", "needs_human", "proven", "blocking", "advisory", "discarded")},
        "snr": round(sum(f["status"] in ("blocking", "proven") for f in shown) / len(shown), 3) if shown else None,
        "verifier_refutation_rate": round(sum(f["verification"]["verdict"] != "confirmed" for f in verified)
                                          / len(verified), 3) if verified else None,
        "wall_s_median": round(statistics.median(walls), 1) if walls else None,
        "tokens_total": sum(tokens),
        "labels_human": {v: human.count(v) for v in LABELS},
        "labels_agent": {v: agent.count(v) for v in AGENT_LABELS},
        "precision_human": round(sum(v in ("fixed", "intentional") for v in human) / len(human), 3) if human else None,
        "overrides": len(lines(common / "review-loop" / "accepts.jsonl")),
        "skips": len(lines(common / "review-loop" / "skips.log")),
    }


def rows(key: str, st: dict, day: str) -> list[list]:
    out = []
    for k, v in st.items():
        if isinstance(v, dict):
            out += [[day, f"review_loop_{k}_{sub}", key, n] for sub, n in v.items()]
        elif v is not None:
            out.append([day, f"review_loop_{k}", key, v])
    return out


def main_label(argv: list[str], confirm=confirm_on_tty) -> int:
    ap = scan.Parser(prog="review-loop label", description=__doc__.splitlines()[0])
    ap.add_argument("finding_id")
    ap.add_argument("label", choices=LABELS)
    ap.add_argument("--evidence")
    ap.add_argument("--note")
    a = ap.parse_args(argv)
    try:
        row = label(".", a.finding_id, a.label, a.evidence, a.note, confirm)
    except (eot.EotError, GitError, OSError) as e:
        sys.stderr.write(f"review-loop label: {e}\n")
        return 3
    print(json.dumps(row))
    return 0


def main_stats(argv: list[str]) -> int:
    ap = scan.Parser(prog="review-loop stats", description=__doc__.splitlines()[0])
    ap.add_argument("--repo", action="append")
    ap.add_argument("--csv", metavar="PATH")
    ap.add_argument("--format", choices=["json", "text"], default="json")
    a = ap.parse_args(argv)
    out = {}
    try:
        for repo in a.repo or ["."]:
            out[Path(git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip()).name] = stats(repo)
    except (GitError, OSError) as e:
        sys.stderr.write(f"review-loop stats: {e}\n")
        return 3
    if a.csv:
        day = date.today().isoformat()
        new = not os.path.exists(a.csv)
        with open(a.csv, "a", newline="") as fh:
            w = csv.writer(fh)
            if new:
                w.writerow(["date", "metric", "key", "value"])
            for key, st in out.items():
                w.writerows(rows(key, st, day))
    if a.format == "text":
        for key, st in out.items():
            print(key)
            for k, v in st.items():
                print(f"  {k:26} {v}")
    else:
        print(json.dumps(out, indent=2))
    return 0
