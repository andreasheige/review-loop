"""review-loop recheck: after fixing eot findings, review what changed since the last completed round.

usage: review-loop recheck [--base REF] [--rev REV] [--ticket PATH | --intent TEXT] [--author-family claude|gpt|unknown]
                           [--finder HARNESS[:MODEL]]... [--verifier HARNESS[:MODEL]]... [--format json|text]

The branch is the ticket key: every eot/recheck record of this branch (minus those already merged into base) forms
one chain, from its latest completed eot. A round "completed" when it had no error and no D1 stop. From the completed rounds come the open findings
(blocking/proven, latest status per id) and the advisory ones (known, never reported again by id).

Each round: scan the whole ticket range again (a D1 hit stops before any model sees the diff); a finder reads the
ticket paths changed since the last completed round's head (the merge-base if none); every open finding is verified
again against the whole ticket diff and stays open unless every verifier refutes it (proven ones stay for their
repro). A round that stops or errors keeps the open findings in its record. Same patch-id as the latest completed
round and no new scan hit in the history: its outcome is reported again without a model. A branch that no longer
changes anything against the base gets the scan only. Cap: round 3 (two rechecks); open findings then exit 2. Past
the cap only the scan runs: a hard hit exits 1, anything else exits 2 (a human looks at the change).
"""
from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import eot, scan, workers
from .gitdiff import GitError, git, verify_commit

MAX_ROUND = 3
OPEN = ("blocking", "proven")


def known_entry(f: dict) -> dict:
    return {"id": f["id"], "lens": f["lens"], "path": f["sites"][0]["path"], "title": f["title"]}


def state(done: list[dict]) -> dict[str, dict]:
    """Latest status per model finding id over the completed rounds."""
    out: dict[str, dict] = {}
    for r in done:
        for f in r["findings"]:
            if f["id"].startswith("rev-"):
                out[f["id"]] = f
    return out


def run(repo: str, base_ref: str, rev: str = "HEAD", *, ticket=None, intent_text=None, family=None,
        finders=None, verifiers=None, runner=workers.default_runner) -> tuple[dict, Path | None]:
    repo = git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip()
    head = verify_commit(repo, rev)
    base = git(repo, "merge-base", verify_commit(repo, base_ref), head).stdout.decode().strip()
    common = Path(repo, git(repo, "rev-parse", "--git-common-dir").stdout.decode().strip())
    br = eot.branch(repo)
    if not br:
        raise eot.EotError("recheck needs a branch (the branch is the ticket key); check one out")
    links = eot.chain(repo, common, base, br, head)
    if not links:
        raise eot.EotError(f"no earlier eot record for branch {br}; run `review-loop eot` first")
    try:
        pid = eot.patch_id(repo, base, head)
    except eot.EotError:  # the fixes undid the whole ticket: nothing left to review, but the history is still scanned
        sc = scan.run(repo, staged=False, rng=f"{base}..{head}", sarif=None)
        o = eot.outcome(sc["findings"], f"scan: {sc['error']}" if sc.get("error") else None)
        return {**links[-1][0], "findings": sc["findings"], "outcome": o,
                "note": "the branch no longer changes anything against the base; only the scan ran"}, None
    done = [(r, d) for r, d in links if eot.completed(r)]
    eots = [i for i, (r, _) in enumerate(done) if r["command"] == "eot"]
    done = done[eots[-1]:] if eots else done  # a re-run eot (only allowed before any recheck) starts afresh
    if done and done[-1][0]["key"]["patch_id"] == pid:
        # same end state, but commits in between may add a secret and remove it again: D1 scans the history
        r, d = done[-1]
        sc = scan.run(repo, staged=False, rng=f"{base}..{head}", sarif=None)
        if not sc.get("error") and {f["id"] for f in sc["findings"]} <= {f["id"] for f in r["findings"]}:
            return {**r, "note": f"no change since round {r['round']}; its outcome stands"}, d
    latest = state([r for r, _ in done])
    open_ = [f for f in latest.values() if f["status"] in OPEN]
    known = [known_entry(f) for f in latest.values() if f["status"] == "advisory"]
    n = (done[-1][0]["round"] if done else 0) + 1
    prev = links[-1][0]

    if n > MAX_ROUND:  # past the cap: scan only, never another model round
        sc = scan.run(repo, staged=False, rng=f"{base}..{head}", sarif=None)
        o = eot.outcome(sc["findings"], f"scan: {sc['error']}" if sc.get("error") else None)
        if o["exit_code"] == 0:
            o = {"exit_code": 2, "summary": "needs_human"}
        return {**done[-1][0], "findings": sc["findings"] + open_, "outcome": o,
                "note": f"recheck cap reached (round {MAX_ROUND}); a human reviews what changed since"}, done[-1][1]

    family = family or eot.author_family(repo, base, head)
    finders = finders or [eot.worker_spec(h) for h in eot.NON_AUTHOR[family]]
    verifiers = verifiers or finders
    round_dir = common / "review-loop" / pid / f"round-{n}"
    shutil.rmtree(round_dir, ignore_errors=True)
    (round_dir / "prompts").mkdir(parents=True)

    in_ticket = [c for c in eot.changes(repo, base, head) if not eot.skipped(c[1])]
    ticket_paths = sorted({p for _, p, src in in_ticket for p in (p, src) if p})
    since = done[-1][0]["head"] if done else base
    text, source = eot.intent(repo, base, head, ticket, intent_text)
    record = {
        "schema_version": 1, "command": "recheck",
        "key": {"patch_id": pid, "base_ref": base_ref, "merge_base": None},
        "round": n, "created_at": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "head": head, "branch": br,
        "previous": {"patch_id": prev["key"]["patch_id"], "round": prev["round"]}, "settled": known,
        "author_family": family, "intent_source": source, "workers": [], "tools": {},
        "reviewed_paths": [], "findings": [],
    }
    error, reviewed = None, False
    try:
        sc = scan.run(repo, staged=False, rng=f"{base}..{head}", sarif=str(round_dir / "scan.sarif"))
        record["tools"] = sc["tools"]
        record["findings"] = list(sc["findings"])
        if sc.get("error"):
            raise eot.EotError(f"scan: {sc['error']}")
        if any(f["rule_class"] == "secret" and f["introduced_by"] == "diff" for f in sc["findings"]):
            raise eot.StopReview
        kept = [c for c in eot.changes(repo, since, head) if not eot.skipped(c[1])
                and (c[1] in ticket_paths or c[2] in ticket_paths)]
        eligible = sorted(p for st, p, _ in kept if st != "D")
        deleted = sorted(p for st, p, _ in kept if st == "D")
        diff_paths = sorted({p for _, p, src in kept for p in (p, src) if p})
        if ticket_paths and (diff_paths or open_):
            full = git(repo, "--literal-pathspecs", "diff", "-M", "--no-color", "--no-ext-diff", base, head, "--",
                       *ticket_paths).stdout.decode("utf-8", "replace")
            record["findings"] += eot.review(repo, since if diff_paths else base, head, text, eligible, deleted,
                                             diff_paths or ticket_paths, finders, verifiers, round_dir, record, runner,
                                             open_, known, verify_diff=full)
            reviewed = True
    except eot.StopReview:
        pass
    except (eot.EotError, workers.WorkerError, GitError, OSError) as e:
        error = str(e)
    except Exception as e:  # noqa: BLE001 - an unexpected crash is exit 3 with a record, never 0
        error = f"internal error: {type(e).__name__}"
    if not reviewed:  # stopped, failed or nothing to check against: the open findings stay open
        record["findings"] += open_
    record["outcome"] = eot.outcome(record["findings"], error, last_round=n == MAX_ROUND)
    eot.write(round_dir / "record.json", record)
    return record, round_dir


def main(argv: list[str], runner=workers.default_runner) -> int:
    return eot.main(argv, runner, command="recheck", run_fn=run)
