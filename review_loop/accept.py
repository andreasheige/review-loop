"""review-loop accept: a human's override of one finding, per (finding id, rule_class), never per patch-id.

usage: review-loop accept <finding-id> --reason TEXT [--expires YYYY-MM-DD] [--rule-class CLASS] [--base REF]

The finding must exist (newest eot/recheck record, else a policy scan of merge-base(base, HEAD)..HEAD) and its rule
class must match; the terminal prompt shows its status, place and title.

Needs a "y" typed at the terminal (/dev/tty), which an agent's shell does not have. Every security class needs
--expires (at most 90 days ahead); only a review accept (a rev- finding) may have none. A review accept never
clears a deterministic or needs_human finding: the rule_class must match. Stored in
$(git rev-parse --git-common-dir)/review-loop/accepts.jsonl (contract/accept.schema.json) and applied live by
every scan, eot and recheck: a matching, unexpired accept turns the finding advisory.
"""
from __future__ import annotations

import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from . import scan
from .gitdiff import GitError, git

CLASSES = ("review", "secret", "unicode", "dep-nonexistent", "dep-mal", "dep-kev", "dep-young", "sast", "workflow",
           "control-weakening")
MAX_DAYS = 90


def store(repo: str) -> Path:
    top = git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip()
    return Path(top, git(top, "rev-parse", "--git-common-dir").stdout.decode().strip(), "review-loop", "accepts.jsonl")


def load(repo: str, today: date | None = None) -> list[dict]:
    """Unexpired accepts that came through the TTY path; anything malformed is ignored, never trusted."""
    today = today or date.today()
    try:
        rows = [json.loads(ln) for ln in store(repo).read_text().splitlines() if ln.strip()]
    except (OSError, ValueError, GitError):
        return []
    out = []
    for a in rows:
        if (not isinstance(a, dict) or a.get("tty") is not True or a.get("rule_class") not in CLASSES
                or not isinstance(a.get("finding_id"), str) or not isinstance(a.get("reason"), str)):
            continue
        exp = a.get("expires")
        if exp is None and a["rule_class"] != "review":
            continue
        try:
            if exp is not None and date.fromisoformat(exp) < today:
                continue
        except (TypeError, ValueError):
            continue
        out.append(a)
    return out


def apply(repo: str, findings: list[dict]) -> list[dict]:
    accepted = {(a["finding_id"], a["rule_class"]): a for a in load(repo)}
    for f in findings:
        a = accepted.get((f["id"], f.get("rule_class") or "review"))
        if a and f["status"] != "advisory":
            f["status"] = "advisory"
            f["body"] = f"accepted until {a['expires'] or 'revoked'}: {a['reason']}"[:500]
    return findings


def lookup(repo: str, finding_id: str, base_ref: str | None = None) -> dict | None:
    """The finding as last seen: the newest eot/recheck record holding it, else a policy scan of the branch."""
    from . import eot

    top = git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip()
    common = Path(top, git(top, "rev-parse", "--git-common-dir").stdout.decode().strip())
    hits = [(r["created_at"], f) for r, _ in eot.records(common) for f in r["findings"] if f["id"] == finding_id]
    if hits:
        return max(hits, key=lambda x: x[0])[1]
    base = git(top, "merge-base", base_ref or eot.default_base(top), "HEAD", check=False).stdout.decode().strip()
    if not base:
        return None
    live = scan.run(top, staged=False, rng=f"{base}..HEAD", policy=True)
    return next((f for f in live["findings"] if f["id"] == finding_id), None)


def command(f: dict) -> str:
    """The exact command a human runs to accept a finding (printed for headless harnesses)."""
    rc = f.get("rule_class") or "review"
    exp = "" if rc == "review" else f" --expires {(date.today() + timedelta(days=14)).isoformat()}"
    return f'review-loop accept {f["id"]} --rule-class {rc} --reason "<why this is fine>"{exp}'


def main(argv: list[str], confirm=None) -> int:
    from .stats import confirm_on_tty  # one TTY prompt for labels and accepts

    ap = scan.Parser(prog="review-loop accept", description=__doc__.splitlines()[0])
    ap.add_argument("finding_id")
    ap.add_argument("--reason", required=True)
    ap.add_argument("--expires", metavar="YYYY-MM-DD")
    ap.add_argument("--rule-class", choices=CLASSES)
    ap.add_argument("--base", help="base ref for finding a scan finding (default as eot)")
    a = ap.parse_args(argv)
    rc = a.rule_class or ("review" if a.finding_id.startswith("rev-") else None)

    def refuse(msg):
        sys.stderr.write(f"review-loop accept: {msg}\n")
        return 3

    if not rc:
        return refuse("--rule-class is required for a scan finding (see the finding's rule class)")
    if (rc == "review") != a.finding_id.startswith("rev-"):
        return refuse("a review accept is only for rev- findings, and a rev- finding only takes a review accept")
    if len(a.reason.strip()) < 10:
        return refuse("--reason needs at least 10 characters")
    if rc != "review" and not a.expires:
        return refuse(f"--expires is required for {rc}")
    if a.expires:
        try:
            exp = date.fromisoformat(a.expires)
        except ValueError:
            return refuse("--expires must be YYYY-MM-DD")
        if not date.today() <= exp <= date.today() + timedelta(days=MAX_DAYS):
            return refuse(f"--expires must be between today and {MAX_DAYS} days ahead")
    try:
        f = lookup(".", a.finding_id, a.base)
    except GitError as e:
        return refuse(str(e))
    if not f:
        return refuse(f"no finding {a.finding_id} in this repo's records or in a scan of this branch")
    if (f.get("rule_class") or "review") != rc:
        return refuse(f"{a.finding_id} is {f.get('rule_class') or 'review'}, not {rc}")
    site = f["sites"][0]
    if not (confirm or confirm_on_tty)(f"Accept {f['status'].upper()} {rc} finding at {site['path']}:{site['start_line']}"
                                       f" — {f['title']} — until {a.expires or 'revoked'}, because: {a.reason}?"):
        return refuse("needs a human at the terminal")
    row = {"finding_id": a.finding_id, "rule_class": rc, "reason": a.reason.strip(), "expires": a.expires,
           "accepted_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "tty": True}
    try:
        path = store(".")
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as fh:
            fh.write(json.dumps(row) + "\n")
    except (OSError, GitError) as e:
        return refuse(str(e))
    print(json.dumps(row))
    return 0
