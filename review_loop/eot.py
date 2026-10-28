"""review-loop eot: end-of-ticket review of merge-base(base, rev)..rev, written as one record.

usage: review-loop eot [--base REF] [--rev REV] [--ticket PATH | --intent TEXT] [--author-family claude|gpt|unknown]
                       [--finder HARNESS[:MODEL]]... [--verifier HARNESS[:MODEL]]... [--format json|text]

Order: eligibility (by file class only) → scan → any scan error or D1 (secret) hit stops before a model sees the
diff → finder(s) → verifier(s) on correctness/security findings with a failure scenario → status in code → record
at $(git rev-parse --git-common-dir)/review-loop/<patch-id>/round-1/. Exit 0 pass, 1 block, 2 needs_human, 3 error.

Workers default to the non-author family (author claude → codex, gpt → claude, unknown → both, and a finding blocks
only if every verifier confirms it). --finder/--verifier override that; the record names the families that ran.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from . import deps, launcher, normalise, scan, workers
from .gitdiff import GitError, git, verify_commit

FAMILY = {"claude": "claude", "codex": "gpt", "copilot": "gpt"}  # copilot runs a GPT model
DEFAULT_MODEL = {"claude": "opus", "codex": None, "copilot": workers.COPILOT_MODEL}
NON_AUTHOR = {"claude": ["copilot"], "gpt": ["claude"], "unknown": ["claude", "copilot"]}  # copilot until Codex quota is back (Decision 14)
CANARY = re.compile(r"REVIEWLOOP_CANARY_[A-Z0-9]{20}")
DOC_SUFFIXES = {".md", ".mdx", ".rst", ".adoc"}  # not .txt: requirements.txt is a manifest
# never skipped, whatever the file class: agent config, CI, and anything named like a security control
SENSITIVE = re.compile(r"(^|/)(AGENTS|CLAUDE|GEMINI)[^/]*\.md$|(^|/)SKILL\.md$|(^|/)prompts?/|"
                       r"(^|/)\.(github|claude|codex|cursor|agents|gemini)/|copilot-instructions|cursorrules|"
                       r"auth|secur|secret|token|crypt|passw|permission|policy|login|session", re.I)
VERIFIED_LENSES = ("correctness", "security")
PARALLEL = 4


class EotError(Exception):
    pass


# ------------------------------------------------------------------ inputs


def skipped(path: str) -> bool:
    """Eligibility skip by file class only (docs, lockfiles), never for a path that looks security-relevant."""
    p = PurePosixPath(path)
    if SENSITIVE.search(path):
        return False
    return p.name in deps.LOCKFILES or p.suffix.lower() in DOC_SUFFIXES


def changes(repo: str, base: str, head: str) -> list[tuple[str, str, str | None]]:
    """(status letter, path at head or deleted path, rename/copy source or None) for every change in the range."""
    parts = git(repo, "diff", "--name-status", "-z", "-M", base, head).stdout.decode("utf-8", "replace").split("\0")
    out, i = [], 0
    while i < len(parts) and parts[i]:
        st = parts[i][0]
        if st in "RC":
            out.append((st, parts[i + 2], parts[i + 1]))
            i += 3
        else:
            out.append((st, parts[i + 1], None))
            i += 2
    return out


def patch_id(repo: str, base: str, head: str) -> str:
    diff = git(repo, "diff", "-U0", "--no-color", "--no-ext-diff", base, head).stdout
    p = subprocess.run(["git", "-C", repo, "patch-id", "--stable"], input=diff, capture_output=True)
    pid = p.stdout.decode().split(" ", 1)[0]
    if p.returncode or not re.fullmatch(r"[0-9a-f]{40}", pid):
        raise EotError("empty diff: nothing to review")
    return pid


def author_family(repo: str, base: str, head: str) -> str:
    """From the commit trailers of the range (the model, not the harness); mixed or none → unknown."""
    log = git(repo, "log", "--format=%B", f"{base}..{head}").stdout.decode("utf-8", "replace")
    found = set()
    for m in re.finditer(r"^co-authored-by:\s*(.+)$", log, re.I | re.M):
        who = m.group(1).lower()
        if "claude" in who or "anthropic" in who:
            found.add("claude")
        elif any(k in who for k in ("codex", "openai", "gpt")):
            found.add("gpt")
    return found.pop() if len(found) == 1 else "unknown"


def intent(repo: str, base: str, head: str, ticket: str | None, text: str | None) -> tuple[str, str]:
    if ticket:
        return Path(ticket).read_text(), "ticket"
    if text:
        return text, "intent"
    return git(repo, "log", "--format=%B", f"{base}..{head}").stdout.decode("utf-8", "replace").strip(), "commits"


def worker_spec(spec: str) -> tuple[str, str | None]:
    harness, _, model = spec.partition(":")
    if harness not in FAMILY:
        raise argparse.ArgumentTypeError(f"unknown harness {harness!r} (claude|codex|copilot)")
    return harness, model or DEFAULT_MODEL[harness]


# ------------------------------------------------------------------ workers


def run_worker(spec, role, prompt, schema, cwd, runner, check=None) -> tuple[dict, dict]:
    """(worker output, record worker entry). write_prompt has already refused a prompt holding the canary."""
    harness, model = spec
    t0 = time.monotonic()
    if harness == "claude":
        res = workers.run_claude(prompt, schema, cwd, model, runner, check)
    elif harness == "copilot":
        res = workers.run_copilot(prompt, schema, cwd, model, runner, check)
    else:
        res = workers.run_codex(prompt, schema, cwd, model, runner, check)
    entry = {"role": role, "family": FAMILY[harness], "harness": harness, "model": model or "default",
             "wall_seconds": round(time.monotonic() - t0, 1),
             "tokens": sum(v for k, v in res["usage"].items() if "tokens" in k and isinstance(v, int))}
    return res["output"], entry


def model_finding(raw: dict) -> dict:
    """A finder finding as a stored finding: id added, nulls dropped (status/verification come later)."""
    key = "|".join((raw["lens"], raw["sites"][0]["path"], raw["title"]))
    f = {"id": f"rev-{normalise.sha1(key)[:12]}"}
    for k in ("reasoning", "lens", "title", "body", "surface", "cwe", "sites", "failure_scenario", "evidence"):
        if raw.get(k) is not None or k == "failure_scenario":
            f[k] = raw.get(k)
    if f["lens"] == "security":
        f.setdefault("surface", "code")
    else:
        f.pop("surface", None)
    f["rule_class"] = None
    f["introduced_by"] = "diff"  # the finder reviews the change, so its findings are about the change
    return f


def needs_verify(f: dict) -> bool:
    return f["lens"] in VERIFIED_LENSES and f["failure_scenario"] is not None


def status(f: dict, verdicts: list[dict]) -> str:
    """blocking = correctness/security ∧ every verifier confirmed ∧ failure scenario; any refuted/unsure → discarded."""
    if not verdicts:
        return "advisory"
    if all(v["verdict"] == "confirmed" for v in verdicts):
        return "blocking" if needs_verify(f) else "advisory"
    return "discarded"


def outcome(findings: list[dict], error: str | None, last_round: bool = False) -> dict:
    """last_round: the recheck cap is reached, so open blocking findings go to a human (exit 2) instead of another fix."""
    statuses = {f["status"] for f in findings}
    if error:
        return {"exit_code": 3, "summary": "error", "error": error}
    if last_round and statuses & {"proven", "blocking"} and "hard" not in statuses:
        return {"exit_code": 2, "summary": "needs_human"}
    if statuses & {"hard", "proven", "blocking"}:
        return {"exit_code": 1, "summary": "blocked"}
    if "needs_human" in statuses:
        return {"exit_code": 2, "summary": "needs_human"}
    shown = [f for f in findings if f["status"] != "discarded"]
    return {"exit_code": 0, "summary": "advisory_only" if shown else "no_findings_reported (unverified)"}


# ------------------------------------------------------------------ run


def run(repo: str, base_ref: str, rev: str = "HEAD", *, ticket=None, intent_text=None, family=None,
        finders=None, verifiers=None, runner=workers.default_runner) -> tuple[dict, Path | None]:
    """(record, round dir). The record is written even on error, once the key is known."""
    repo = git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip()
    head = verify_commit(repo, rev)
    base = git(repo, "merge-base", verify_commit(repo, base_ref), head).stdout.decode().strip()
    pid = patch_id(repo, base, head)
    family = family or author_family(repo, base, head)
    finders = finders or [worker_spec(h) for h in NON_AUTHOR[family]]
    verifiers = verifiers or finders
    common = Path(repo, git(repo, "rev-parse", "--git-common-dir").stdout.decode().strip())
    if any(r["command"] == "recheck" for r, _ in chain(repo, common, base, branch(repo), head)):
        raise EotError("this branch already has recheck rounds; run `review-loop recheck` (the round cap is per branch)")
    round_dir = common / "review-loop" / pid / "round-1"
    shutil.rmtree(round_dir, ignore_errors=True)  # a re-run replaces round-1 whole, stale prompts included
    (round_dir / "prompts").mkdir(parents=True)

    kept = [c for c in changes(repo, base, head) if not skipped(c[1])]
    eligible = sorted(p for st, p, _ in kept if st != "D")  # what the finder must read
    deleted = sorted(p for st, p, _ in kept if st == "D")
    diff_paths = sorted({p for _, p, src in kept for p in (p, src) if p})
    text, source = intent(repo, base, head, ticket, intent_text)
    record = {
        "schema_version": 1, "command": "eot",
        "key": {"patch_id": pid, "base_ref": base_ref, "merge_base": None},
        "round": 1, "created_at": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "head": head, "branch": branch(repo), "author_family": family, "intent_source": source, "workers": [], "tools": {},
        "reviewed_paths": [], "findings": [],
    }
    error = None
    try:
        sc = scan.run(repo, staged=False, rng=f"{base}..{head}", sarif=str(round_dir / "scan.sarif"))
        record["tools"] = sc["tools"]
        record["findings"] = list(sc["findings"])
        if sc.get("error"):
            raise EotError(f"scan: {sc['error']}")
        if any(f["rule_class"] == "secret" and f["introduced_by"] == "diff" for f in sc["findings"]):
            raise StopReview  # D1, any confidence: the diff may hold a secret, so no model may see it
        if diff_paths:
            record["findings"] += review(repo, base, head, text, eligible, deleted, diff_paths, finders, verifiers,
                                         round_dir, record, runner)
    except StopReview:
        pass
    except (EotError, workers.WorkerError, GitError, OSError) as e:
        error = str(e)
    except Exception as e:  # noqa: BLE001 - an unexpected crash is exit 3 with a record, never 0
        error = f"internal error: {type(e).__name__}"
    record["outcome"] = outcome(record["findings"], error)
    write(round_dir / "record.json", record)
    return record, round_dir


class StopReview(Exception):
    pass


def branch(repo: str) -> str | None:
    p = git(repo, "symbolic-ref", "--quiet", "--short", "HEAD", check=False)
    return p.stdout.decode().strip() or None


def records(common: Path):
    for p in (common / "review-loop").glob("*/round-*/record.json"):
        try:
            r = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        if r.get("command") in ("eot", "recheck") and r.get("head"):
            yield r, p.parent


def is_ancestor(repo: str, a: str, b: str) -> bool:
    return git(repo, "merge-base", "--is-ancestor", a, b, check=False).returncode == 0


def branch_created(repo: str, br: str) -> str | None:
    """When this branch ref was created (its oldest reflog entry), UTC ISO; None without a reflog."""
    p = git(repo, "reflog", "show", "--date=iso-strict", "--format=%gd", f"refs/heads/{br}", "--", check=False)
    lines = p.stdout.decode().split()
    if p.returncode or not lines:
        return None
    m = re.search(r"\{(.+)\}", lines[-1])
    return datetime.fromisoformat(m.group(1)).astimezone(timezone.utc).isoformat(timespec="microseconds") if m else None


def chain(repo: str, common: Path, base: str, br: str | None, head: str) -> list[tuple[dict, Path]]:
    """Every eot/recheck record of this branch's ticket, oldest round first. Records whose head is already in base
    belong to a merged ticket. The rest belong here when they were made on this branch since it was created (a
    reused name after a squash merge starts afresh; a rebase keeps the reflog), or when their head is in this
    history and their branch no longer exists (renamed). A stacked branch's parent still exists, so its records
    stay its own."""
    if not br:
        return []
    born = branch_created(repo, br)
    out = []
    for r, d in records(common):
        if is_ancestor(repo, r["head"], base):
            continue
        rb = r.get("branch")
        if rb == br and (born is None or r["created_at"] >= born or is_ancestor(repo, r["head"], head)):
            out.append((r, d))
        elif rb != br and is_ancestor(repo, r["head"], head) and (
                not rb or git(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{rb}", check=False).returncode):
            out.append((r, d))
    return sorted(out, key=lambda x: (x[0]["round"], x[0]["created_at"]))


def completed(r: dict) -> bool:
    """The round reviewed the change: no error and no D1 stop before the models."""
    return r["outcome"]["exit_code"] != 3 and not any(
        f["rule_class"] == "secret" and f["introduced_by"] == "diff" for f in r["findings"])


def review(repo, base, head, text, eligible, deleted, diff_paths, finders, verifiers, round_dir, record, runner,
           prior=(), known=(), verify_diff=None) -> list[dict]:
    """prior: open findings from earlier rounds, verified again (recheck); one stays open unless every verifier
    refutes it, and a proven one is left to its repro. known: earlier advisory findings, never reported again.
    verify_diff: what verifiers see (default: the finder's diff). The finder only runs when there are paths to read."""
    diff = git(repo, "--literal-pathspecs", "diff", "-M", "--no-color", "--no-ext-diff", base, head, "--",
               *diff_paths).stdout.decode("utf-8", "replace")
    verify_diff = diff if verify_diff is None else verify_diff
    prompt = workers.find_prompt(text, diff, eligible + [f"{p} (deleted)" for p in deleted], known=known)
    suppress = {k["id"] for k in known}
    write_prompt(round_dir / "prompts/find.md", prompt)
    find_schema, verify_schema = workers.load_schema("finder-output"), workers.load_schema("verifier-output")
    with launcher.scratch_worktree(repo, head) as wt, ThreadPoolExecutor(PARALLEL) as pool:
        def coverage(output):
            missing = sorted(set(eligible) - set(output["reviewed_paths"]))
            return f"reviewed_paths leaves out changed paths: {', '.join(missing)}" if missing else None

        runs = list(pool.map(lambda s: run_worker(s, "finder", prompt, find_schema, wt, runner, coverage),
                             finders if eligible or deleted else []))
        found: dict[str, dict] = {}
        for output, entry in runs:
            record["workers"].append(entry)
            for raw in output["findings"]:
                f = model_finding(raw)
                if f["id"] not in suppress or needs_verify(f):  # an advisory that now has a failure scenario
                    found.setdefault(f["id"], f)
        prior_status = {f["id"]: f["status"] for f in prior}
        for f in prior:
            found[f["id"]] = {k: v for k, v in f.items() if k not in ("status", "verification")}
        record["reviewed_paths"] = list(eligible)

        jobs = [(f, v) for f in found.values() if needs_verify(f) and prior_status.get(f["id"]) != "proven"
                for v in verifiers]

        def verify(job):
            f, spec = job
            p = workers.verify_prompt(f["id"], {k: v for k, v in f.items() if k != "id"}, verify_diff)
            write_prompt(round_dir / f"prompts/verify-{f['id']}-{spec[0]}.md", p)
            out, entry = run_worker(spec, "verifier", p, verify_schema, wt, runner)
            if out["id"] != f["id"]:
                raise EotError(f"verifier answered for {out['id']}, asked about {f['id']}")
            return f["id"], {**out, "family": entry["family"]}, entry

        verdicts: dict[str, list[dict]] = {}
        for fid, verdict, entry in pool.map(verify, jobs):
            record["workers"].append(entry)
            verdicts.setdefault(fid, []).append(verdict)

    for f in found.values():
        vs = verdicts.get(f["id"], [])
        was = prior_status.get(f["id"])
        if was:  # fixed only when every verifier refutes it; unsure or a missing verdict keeps it open
            f["status"] = "discarded" if vs and all(v["verdict"] == "refuted" for v in vs) else was
        else:
            f["status"] = status(f, vs)
        if vs:  # the deciding verdict: the first that did not confirm, else the first
            v = next((v for v in vs if v["verdict"] != "confirmed"), vs[0])
            f["verification"] = {"verdict": v["verdict"], "reasoning": v["reasoning"],
                                 "counter_evidence": v["counter_evidence"], "family": v["family"]}
    return list(found.values())


def write_prompt(path: Path, text: str) -> None:
    """Every prompt is stored before it is sent, so this is the one place that refuses the canary."""
    if CANARY.search(text):
        raise EotError("canary secret in a worker prompt; refusing to store or send it")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)


def write(path: Path, record: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(record, indent=2) + "\n")


# ------------------------------------------------------------------ CLI


def default_base(repo: str) -> str:
    p = git(repo, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD", check=False)
    ref = p.stdout.decode().strip()
    return ref or ("origin/main" if git(repo, "rev-parse", "--verify", "--quiet", "origin/main", check=False).returncode == 0 else "main")


def text_report(record: dict, round_dir) -> str:
    o = record["outcome"]
    rnd = f" round {record['round']}" if record.get("round", 1) > 1 else ""
    lines = [f"review-loop {record.get('command', 'eot')}{rnd}: {o['summary']}  "
             f"({len(record['reviewed_paths'])} paths reviewed, author {record['author_family']})"]
    if record.get("note"):
        lines.append(f"  {record['note']}")
    for f in record["findings"]:
        if f["status"] == "discarded":
            continue
        s = f["sites"][0]
        lines.append(f"  {f['status']:<11} {f['lens']:<12} {s['path']}:{s['start_line']}  {f['title']}  [{f['id']}]")
    discarded = sum(f["status"] == "discarded" for f in record["findings"])
    if discarded:
        lines.append(f"  ({discarded} discarded by the verifier)")
    if o.get("error"):
        lines.append(f"  error: {o['error']}")
    if round_dir:
        lines.append(f"  record: {round_dir / 'record.json'}")
    return "\n".join(lines) + "\n"


def main(argv: list[str], runner=workers.default_runner, command="eot", run_fn=None) -> int:
    """Also recheck's CLI: same flags, its own run()."""
    ap = scan.Parser(prog=f"review-loop {command}", description=(sys.modules[run_fn.__module__].__doc__ if run_fn
                                                                  else __doc__).splitlines()[0])
    ap.add_argument("--base", help="base ref (default origin/HEAD, else origin/main, else main)")
    ap.add_argument("--rev", default="HEAD")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--ticket", metavar="PATH")
    src.add_argument("--intent", metavar="TEXT")
    ap.add_argument("--author-family", choices=tuple(NON_AUTHOR))
    ap.add_argument("--finder", action="append", type=worker_spec, metavar="HARNESS[:MODEL]")
    ap.add_argument("--verifier", action="append", type=worker_spec, metavar="HARNESS[:MODEL]")
    ap.add_argument("--format", choices=["json", "text"], default="json")
    args = ap.parse_args(argv)
    round_dir = None
    try:
        record, round_dir = (run_fn or run)(".", args.base or default_base("."), args.rev, ticket=args.ticket,
                                intent_text=args.intent, family=args.author_family, finders=args.finder,
                                verifiers=args.verifier, runner=runner)
    except (EotError, GitError, OSError) as e:
        record = {"findings": [], "reviewed_paths": [], "author_family": "unknown",
                  "outcome": {"exit_code": 3, "summary": "error", "error": str(e)}}
    except Exception as e:  # noqa: BLE001 - an unexpected crash must be exit 3, never 0
        record = {"findings": [], "reviewed_paths": [], "author_family": "unknown",
                  "outcome": {"exit_code": 3, "summary": "error", "error": f"internal error: {type(e).__name__}"}}
    if args.format == "text":
        sys.stdout.write(text_report(record, round_dir))
    else:
        json.dump({**record, "record_path": str(round_dir / "record.json") if round_dir else None}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return record["outcome"]["exit_code"]
