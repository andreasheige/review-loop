"""review-loop sweep: the whole-repo checks no diff scan sees. Report only, no model.

usage: review-loop sweep [--if-due] [--repo DIR]
       review-loop sweep --digest [ROOT]...        (default roots: ~/Dev ~/Knowit)

Checks, each recorded with its own status (ok, findings, skipped, error):
  osv        osv-scanner over the repo's lockfiles; client repos (origin not ours, Decision 8) only with the
             offline database, never a network call
  gitleaks   the commits since the last sweep (all history on the first), pinned binary, no values stored
  workflows  zizmor (offline: no token is given) and actionlint over .github/workflows
  hooks      executables in the repo's hooks dir whose sha256 isn't in ~/.config/review-loop/hooks-allow.txt
             (`<sha256> <name> <why>` per line, written by a human: a protected path for agents), and a
             repo-local core.hooksPath (it turns the global hooks off for that repo)
  sast       skipped until there are own Semgrep rules (Decision 7)
  machine    at most once per 7 days: the global core.hooksPath still points at the global hooks dir

--if-due runs only when this repo's last sweep is over 7 days old (or there is none), no other sweep of it is
running, and no usage window is over its usage-guard limit; callers start it in the background
(`taskpolicy -b ... &`), so it never delays a session start or a push. The result goes to
<git-common-dir>/review-loop/sweep.json; --digest lists every repo's last sweep date and counts.
"""
from __future__ import annotations

import datetime
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from . import deps, gitdiff
from .secret_scan import Gitleaks, state_dir
from .tools import SAFE_PATH, ToolError, resolve

DUE_DAYS = 7
LOCK_STALE_S = 3600
HOOKS_ALLOW = Path(os.environ.get("REVIEW_LOOP_HOOKS_ALLOW") or Path.home() / ".config/review-loop/hooks-allow.txt")
GLOBAL_HOOKS = str(Path.home() / "Dev/git-config/hooks")


def now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def common_dir(repo: str) -> Path:
    return Path(repo, gitdiff.git(repo, "rev-parse", "--git-common-dir").stdout.decode().strip()).resolve()


def last_sweep(common: Path) -> dict | None:
    try:
        return json.loads((common / "review-loop" / "sweep.json").read_text())
    except (OSError, ValueError):
        return None


def due(common: Path) -> bool:
    last = last_sweep(common)
    if not last:
        return True
    try:
        return now() - datetime.datetime.fromisoformat(last["ts"]) > datetime.timedelta(days=DUE_DAYS)
    except (KeyError, ValueError):
        return True


def usage_over() -> bool:
    """usage-guard's own snapshot and limits: a window at/over its limit that hasn't reset yet."""
    base = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
    try:
        snap = json.loads((base / "hooks/usage-guard/.state/usage.json").read_text())
    except (OSError, ValueError):
        return False
    limits = {"five_hour": float(os.environ.get("USAGE_GUARD_5H", 90)), "seven_day": float(os.environ.get("USAGE_GUARD_7D", 95))}
    for key, limit in limits.items():
        w = snap.get(key) or {}
        try:
            resets = datetime.datetime.fromisoformat(str(w["resets_at"]).replace("Z", "+00:00"))
            if float(w["used_percentage"]) >= limit and resets > now():
                return True
        except (KeyError, TypeError, ValueError):
            continue
    return False


def run_tool(argv: list[str], cwd: str, timeout: int = 120) -> subprocess.CompletedProcess:
    # no GitHub token reaches the scanners: zizmor then runs offline audits only
    env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_TOKEN", "GH_TOKEN", "ZIZMOR_GITHUB_TOKEN")}
    return subprocess.run(argv, cwd=cwd, capture_output=True, timeout=timeout, env={**env, "PATH": SAFE_PATH})


def check_osv(repo: str) -> dict:
    online = deps.is_online(gitdiff.origin(repo))
    try:
        exe, version = resolve("osv-scanner")
    except ToolError as e:
        return {"status": "error", "error": str(e)}
    argv = [exe, "scan", "source", "--recursive", "--format", "json"]
    if not online:
        if not any(deps.osv_db_dir().glob("*/all.zip")):
            return {"status": "skipped", "why": "client repo and no offline OSV database"}
        argv.append("--offline")
    p = run_tool(argv + [repo], repo, timeout=300)
    if p.returncode not in (0, 1):
        no_lockfiles = b"No package sources found" in p.stderr or b"no package sources" in p.stderr.lower()
        return {"status": "ok", "vulns": []} if no_lockfiles else {"status": "error", "error": f"osv-scanner exited {p.returncode}"}
    try:
        report = json.loads(p.stdout or b"{}")
    except ValueError:
        return {"status": "error", "error": "osv-scanner output is not JSON"}
    vulns = []
    for res in report.get("results") or []:
        source = os.path.relpath(res.get("source", {}).get("path", ""), repo)
        for pk in res.get("packages") or []:
            ids = sorted(v["id"] for v in pk.get("vulnerabilities") or [])
            if ids:
                vulns.append({"package": pk["package"]["name"], "version": pk["package"].get("version"),
                              "ecosystem": pk["package"].get("ecosystem"), "lockfile": source, "ids": ids})
    return {"status": "findings" if vulns else "ok", "tool": f"osv-scanner@{version}", "online": online, "vulns": vulns}


def check_gitleaks(repo: str, since: str | None, head: str) -> dict:
    if since and gitdiff.git(repo, "merge-base", "--is-ancestor", since, head, check=False).returncode != 0:
        since = None  # history was rewritten under the last sweep: look at all of it again
    if since == head:
        return {"status": "ok", "range": "nothing new", "hits": []}
    try:
        leaks = Gitleaks(repo, False, since, head)
        found = leaks.collect()
    except (ToolError, OSError) as e:
        return {"status": "error", "error": str(e)}
    hits = [{"rule": f["reasoning"], "path": f["sites"][0]["path"], "line": f["sites"][0]["start_line"], "id": f["id"]}
            for f in found]
    return {"status": "findings" if hits else "ok", "range": f"{since[:12]}..{head[:12]}" if since else "all history",
            "tool": f"gitleaks@{leaks.version}", "hits": hits}


def check_workflows(repo: str) -> dict:
    wf = Path(repo, ".github/workflows")
    if not wf.is_dir():
        return {"status": "ok", "why": "no workflows"}
    out, errors = [], []
    try:
        exe, _ = resolve("zizmor")
        p = run_tool([exe, "--format", "json", str(wf)], repo)
        if not p.stdout.strip() and p.returncode:
            raise ValueError(f"exited {p.returncode} with no output")
        for f in json.loads(p.stdout or b"[]"):
            key = (f.get("locations") or [{}])[0].get("symbolic", {}).get("key", {}).get("Local", {})
            loc = key.get("verbatim_path") or key.get("given_path")
            out.append({"tool": "zizmor", "rule": f.get("ident"), "severity": f.get("determinations", {}).get("severity"),
                        "path": loc if loc and not os.path.isabs(loc) else os.path.relpath(loc, repo) if loc else ".github/workflows"})
    except (ToolError, ValueError, subprocess.TimeoutExpired) as e:
        errors.append(f"zizmor: {e}")
    try:
        exe, _ = resolve("actionlint")
        p = run_tool([exe, "-format", "{{json .}}"], repo)
        for f in json.loads(p.stdout or b"[]"):
            out.append({"tool": "actionlint", "rule": f.get("kind"), "path": f.get("filepath"), "line": f.get("line")})
    except (ToolError, ValueError, subprocess.TimeoutExpired) as e:
        errors.append(f"actionlint: {e}")
    status = "error" if errors else "findings" if out else "ok"
    return {"status": status, "items": out, **({"error": "; ".join(errors)} if errors else {})}


def allowed_hooks() -> set[str]:
    try:
        return {line.split()[0] for line in HOOKS_ALLOW.read_text().splitlines() if line.strip() and not line.startswith("#")}
    except OSError:
        return set()


def check_hooks(repo: str, common: Path) -> dict:
    import hashlib

    allow, unknown = allowed_hooks(), []
    hooks = common / "hooks"
    for p in sorted(hooks.iterdir()) if hooks.is_dir() else []:
        if p.is_file() and not p.name.endswith(".sample") and os.access(p, os.X_OK):
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            if digest not in allow:
                unknown.append({"name": p.name, "sha256": digest})
    local = gitdiff.git(repo, "config", "--local", "--get", "core.hooksPath", check=False).stdout.decode().strip()
    status = "findings" if unknown or local else "ok"
    return {"status": status, "unknown": unknown, "local_hooks_path": local or None}


def check_machine() -> dict | None:
    """At most once per 7 days, machine-wide."""
    path = state_dir() / "machine-sweep.json"
    try:
        last = json.loads(path.read_text())
        if now() - datetime.datetime.fromisoformat(last["ts"]) <= datetime.timedelta(days=DUE_DAYS):
            return None
    except (OSError, ValueError, KeyError):
        pass
    p = subprocess.run(["git", "config", "--global", "--get", "core.hooksPath"], capture_output=True,
                       env={**os.environ, "PATH": SAFE_PATH})
    got = os.path.expanduser(p.stdout.decode().strip())
    result = {"ts": now().isoformat(timespec="seconds"), "global_hooks_path": got or None,
              "status": "ok" if got.rstrip("/") == GLOBAL_HOOKS else "findings"}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result) + "\n")
    except OSError:
        pass
    return result


def sweep(repo: str) -> dict:
    start = time.monotonic()
    repo = gitdiff.git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip()
    common = common_dir(repo)
    head = gitdiff.git(repo, "rev-parse", "HEAD", check=False).stdout.decode().strip()
    last = last_sweep(common) or {}
    checks = {
        "osv": check_osv(repo),
        "gitleaks": check_gitleaks(repo, last.get("head"), head) if head else {"status": "skipped", "why": "no commits"},
        "workflows": check_workflows(repo),
        "hooks": check_hooks(repo, common),
        "sast": {"status": "skipped", "why": "no own Semgrep rules yet (Decision 7)"},
    }
    machine = check_machine()
    if machine:
        checks["machine"] = machine
    result = {"schema_version": 1, "ts": now().isoformat(timespec="seconds"), "repo": Path(repo).name, "head": head,
              "checks": checks, "ms": round((time.monotonic() - start) * 1000)}
    (common / "review-loop").mkdir(parents=True, exist_ok=True)
    tmp = common / "review-loop" / "sweep.json.tmp"
    tmp.write_text(json.dumps(result, indent=2) + "\n")
    os.replace(tmp, common / "review-loop" / "sweep.json")
    return result


def counts(result: dict) -> dict:
    c = result.get("checks", {})
    return {"osv": len(c.get("osv", {}).get("vulns", [])), "gitleaks": len(c.get("gitleaks", {}).get("hits", [])),
            "workflows": len(c.get("workflows", {}).get("items", [])), "hooks": len(c.get("hooks", {}).get("unknown", []))
            + bool(c.get("hooks", {}).get("local_hooks_path")),
            "errors": sum(1 for v in c.values() if isinstance(v, dict) and v.get("status") == "error")}


def repos_under(roots: list[Path]):
    for root in roots:
        if not root.is_dir():
            continue
        for git in sorted(root.rglob(".git")):
            if git.is_dir() and not any(part in ("node_modules", ".worktrees") for part in git.parts):
                yield git.parent


def digest(roots: list[Path]) -> str:
    lines = ["repo\tlast sweep\tosv\tgitleaks\tworkflows\thooks\terrors"]
    for repo in repos_under(roots):
        last = last_sweep(repo / ".git")
        if not last:
            lines.append(f"{repo}\tnever\t\t\t\t\t")
            continue
        c = counts(last)
        lines.append(f"{repo}\t{last['ts'][:10]}\t{c['osv']}\t{c['gitleaks']}\t{c['workflows']}\t{c['hooks']}\t{c['errors']}")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if "--digest" in argv:
        roots = [Path(a) for a in argv if a != "--digest"] or [Path.home() / "Dev", Path.home() / "Knowit"]
        sys.stdout.write(digest(roots))
        return 0
    repo = argv[argv.index("--repo") + 1] if "--repo" in argv else "."
    try:
        common = common_dir(repo)
    except gitdiff.GitError:
        sys.stderr.write("review-loop sweep: not a git repository\n")
        return 3
    if "--if-due" in argv:
        if not due(common) or usage_over():
            return 0
        lock = common / "review-loop" / "sweep.lock"
        lock.parent.mkdir(parents=True, exist_ok=True)
        try:
            if lock.exists() and time.time() - lock.stat().st_mtime > LOCK_STALE_S:
                lock.unlink()
            fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        except FileExistsError:
            return 0  # another sweep of this repo is running
        try:
            result = sweep(repo)
        finally:
            lock.unlink(missing_ok=True)
    else:
        result = sweep(repo)
    c = counts(result)
    sys.stdout.write(f"review-loop sweep {result['repo']}: osv {c['osv']}, gitleaks {c['gitleaks']}, workflows "
                     f"{c['workflows']}, hooks {c['hooks']}, errors {c['errors']} ({result['ms']} ms)\n")
    return 0
