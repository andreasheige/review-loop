"""review-loop risk (plan 8.7): how much human review a change needs — low, medium or high — decided in code.

Inputs are the diff merge-base(base, rev)..rev, the eot/recheck record for exactly that content, the UI result and
the repo's sensitivity. A label or PR text never counts: `land` (8.8) recomputes this from the pushed head.

  high    a security path (eot.SECURITY_PATH), migrations, infra/CI, guard or agent config, a dependency manifest,
          a sensitive repo, an accepted needs_human or hard finding, a visual UI change, or more than LARGE lines
  low     docs, tests or copy only, at most SMALL lines, reviewed clean in round 1 with nothing open
  medium  everything else, including no passing review record yet

Exit codes: 0 with a tier, 3 on a tool error. Never blocks anything by itself.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

from . import accept, eot, gate, policy
from .gitdiff import GitError, git
from .tools import write_safely
from .ui import UI_FILE

SMALL, LARGE, READ_MAX = 60, 400, 3
HIGH_PATH = re.compile(
    r"(^|/)(migrations?|migrate|db/schema|infra|infrastructure|terraform|helm|charts|k8s|kubernetes|deploy|\.pipelines|"
    r"\.github|\.claude|\.codex|\.pi|\.gemini|\.agents?|hooks|\.husky)(/|$)"
    r"|(^|/)(CLAUDE|AGENTS|GEMINI)\.md$|(^|/)\.review-loop\.toml$|(^|/)(azure-pipelines|docker-compose)[^/]*\.ya?ml$"
    r"|(^|/)(Dockerfile|Containerfile)[^/]*$|\.(tf|tfvars|bicep|sql)$", re.I)
MANIFEST = re.compile(r"(^|/)(package\.json|pyproject\.toml|requirements[^/]*\.txt|setup\.py|setup\.cfg|go\.mod|"
                      r"Cargo\.toml|Gemfile|composer\.json|pom\.xml|build\.gradle(\.kts)?|[^/]+\.csproj|"
                      r"Directory\.Packages\.props)$", re.I)
DOC = re.compile(r"\.(md|mdx|rst|txt|adoc)$|(^|/)(docs?|LICENSE[^/]*|CHANGELOG[^/]*)(/|$)", re.I)
COPY = re.compile(r"(^|/)(locales?|i18n|translations?|lang)/.+\.(json|ya?ml|po|properties)$", re.I)
OPEN = gate.OPEN


def numstat(repo: str, base: str, head: str) -> dict[str, int]:
    out = {}
    for line in git(repo, "diff", "--numstat", "-M", base, head).stdout.decode("utf-8", "replace").splitlines():
        added, deleted, path = line.split("\t", 2)
        path = path.split(" => ")[-1].rstrip("}") if " => " in path else path
        out[path] = (int(added) if added.isdigit() else 0) + (int(deleted) if deleted.isdigit() else 0)
    return out


def newest_record(repo: str, pid: str, head: str) -> dict | None:
    want = gate.tree(repo, head)
    rounds = [r for r, d in eot.records(gate.common_dir(repo)) if d.parent.name == pid and gate.tree(repo, r["head"]) == want]
    return max(rounds, key=lambda r: (r["round"], r["created_at"])) if rounds else None


def ui_result(repo: str, pid: str, head: str) -> dict | None:
    p = gate.common_dir(repo) / "review-loop" / pid / "ui.json"
    try:
        r = json.loads(p.read_text())
    except (OSError, ValueError):
        return None
    return r if isinstance(r, dict) and gate.tree(repo, str(r.get("head", ""))) == gate.tree(repo, head) else None


def accepted(f: dict) -> bool:
    return str(f.get("body", "")).startswith("accepted until")


def assess(repo: str, base_ref: str | None = None, rev: str = "HEAD") -> dict:
    head = git(repo, "rev-parse", "--verify", f"{rev}^{{commit}}").stdout.decode().strip()
    base = git(repo, "merge-base", base_ref or eot.default_base(repo), head).stdout.decode().strip()
    sizes = numstat(repo, base, head)
    paths = sorted(set(sizes) | {p for _, p, _ in eot.changes(repo, base, head)})
    lines = sum(sizes.values())
    high, medium = [], []
    try:
        pid = eot.patch_id(repo, base, head)
    except eot.EotError:
        pid = None

    for p in paths:
        if eot.SECURITY_PATH.search(p):
            high.append(f"security-relevant path: {p}")
        elif HIGH_PATH.search(p):
            high.append(f"infra, CI, migration or agent/guard config: {p}")
        elif MANIFEST.search(p):
            high.append(f"dependency manifest changed (new or changed dependencies): {p}")
    if eot.sensitive(repo):
        high.append("sensitive repo (real users' data)")
    if lines > LARGE:
        high.append(f"large diff: {lines} changed lines")

    rec = newest_record(repo, pid, head) if pid else None
    if rec is None:
        medium.append("no review record for this content yet (run review-loop eot)")
    else:
        findings = accept.apply(repo, rec.get("findings", []))
        still_open = [f for f in findings if f["status"] in OPEN]
        took = [f for f in findings if accepted(f)]
        if rec["outcome"].get("exit_code") == 3 or still_open:
            medium.append(f"review round {rec['round']} has {len(still_open)} open finding(s) or an error")
        if took:
            high.append(f"{len(took)} finding(s) accepted by a human: " + ", ".join(sorted({f.get('rule_class') or 'review' for f in took})))
        if rec["round"] > 1:
            medium.append(f"needed {rec['round'] - 1} recheck(s)")

    ui_paths = [p for p in paths if UI_FILE.search(p)]
    if ui_paths:
        ui = ui_result(repo, pid, head) if pid else None
        visual = [f for f in (ui or {}).get("findings", []) if f.get("rule_class") == "ui-visual" and f.get("status") != "discarded"]
        if visual:
            high.append(f"visual UI change in {len(visual)} story/stories")
        else:
            medium.append("UI files changed")

    trivial = all(DOC.search(p) or policy.is_test(p) or COPY.search(p) for p in paths)
    if not trivial:
        medium.append("code changed")
    elif lines > SMALL:
        medium.append(f"{lines} changed lines (low is at most {SMALL})")

    tier = "high" if high else "medium" if medium or not paths else "low"
    code = [p for p in paths if not policy.is_test(p) and not DOC.search(p)]
    read = sorted(code, key=lambda p: -sizes.get(p, 0))[:READ_MAX]
    return {"tier": tier, "reasons": high + medium if tier != "low" else ["docs, tests or copy only; small; reviewed clean"],
            "read": read, "patch_id": pid, "head": head, "base": base, "lines": lines, "files": len(paths),
            "review_round": rec["round"] if rec else None}


GUIDANCE = {
    "low": "Safe to merge after a glance. An agent may land it with `review-loop land`.",
    "medium": "Read the files below; the rest is routine.",
    "high": "Needs a real review: start with the reasons, then the files below, and test the risky path by hand.",
}


def markdown(r: dict) -> str:
    out = [f"### Review effort: `risk:{r['tier']}`", "", GUIDANCE[r["tier"]], ""]
    out += [f"- {x}" for x in r["reasons"]]
    if r["read"] and r["tier"] != "low":
        out += ["", "Read first:"] + [f"- `{p}`" for p in r["read"]]
    out += ["", f"<sub>{r['files']} files, {r['lines']} changed lines, review round {r['review_round'] or '—'}, "
                f"patch-id {(r['patch_id'] or '—')[:12]} · decided by `review-loop risk`, not by a model</sub>"]
    return "\n".join(out) + "\n"


def save(repo: str, r: dict) -> None:
    """risk.json next to the eot record, for `stats` (was low really safe?)."""
    if not r.get("patch_id"):
        return
    common = gate.common_dir(repo)
    d = common / "review-loop" / r["patch_id"]
    try:
        d.mkdir(parents=True, exist_ok=True)
        write_safely(d / "risk.json", json.dumps(r, indent=2) + "\n", common)
    except OSError:
        pass


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="review-loop risk")
    ap.add_argument("--base")
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--format", choices=("text", "json", "md"), default="text")
    a = ap.parse_args(argv)
    try:
        r = assess(a.repo, a.base, a.rev)
    except (GitError, eot.EotError, ValueError) as e:
        sys.stderr.write(f"review-loop risk: {e}\n")
        return 3
    save(a.repo, r)
    if a.format == "json":
        print(json.dumps(r, indent=2))
    elif a.format == "md":
        sys.stdout.write(markdown(r))
    else:
        print(f"risk:{r['tier']}")
        for x in r["reasons"]:
            print(f"  - {x}")
        if r["read"] and r["tier"] != "low":
            print("  read first: " + ", ".join(r["read"]))
    return 0
