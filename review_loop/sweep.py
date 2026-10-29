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
  image      repos with a Dockerfile: the newest `trivy-report` artifact of the repo's CI (Azure DevOps via `az`,
             GitHub via `gh api`), its vulnerabilities minus those osv already lists for the same (package, id);
             default-branch runs only; an empty, unreadable or non-Trivy report is an error (a scan that writes
             nothing passes silently otherwise);
             no Dockerfile -> not_applicable
  sast       skipped until there are own Semgrep rules (Decision 7)
  machine    at most once per 7 days: the global core.hooksPath still points at the global hooks dir

--if-due runs only when this repo's last sweep is over 7 days old (or there is none), no other sweep of it is
running, and no usage window is over its usage-guard limit; callers start it in the background
(`taskpolicy -b ... &`), so it never delays a session start or a push. The result goes to
<git-common-dir>/review-loop/sweep.json; --digest lists every repo's last sweep date and counts.

Known limits: sweep.json lives in .git, so the code under review can make a sweep look recent or covered (report
only, nothing blocks on it); the --if-due lock is best effort (two sweeps can rarely overlap); zizmor and
actionlint read the repo's own config, which can turn rules off.
"""
from __future__ import annotations

import datetime
import json
import os
import subprocess
import sys
import re
import tempfile
import urllib.parse
import time
import zipfile
from pathlib import Path

from . import deps, gitdiff
from .secret_scan import Gitleaks, state_dir
from .tools import SAFE_PATH, ToolError, resolve, write_safely

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
            found = pk.get("vulnerabilities") or []
            ids = sorted(v["id"] for v in found)
            if ids:
                aliases = sorted({a for v in found for a in v.get("aliases") or []} - set(ids))
                vulns.append({"package": pk["package"]["name"], "version": pk["package"].get("version"),
                              "ecosystem": pk["package"].get("ecosystem"), "lockfile": source, "ids": ids,
                              "aliases": aliases})
    return {"status": "findings" if vulns else "ok", "tool": f"osv-scanner@{version}", "online": online, "vulns": vulns}


# Which repos get an image check: a Dockerfile within 4 levels, outside dependency/vendor dirs.
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "dist", "build"}
ADO = re.compile(r"(?:dev\.azure\.com/([^/]+)/([^/]+)/_git/([^/?#]+)|ssh\.dev\.azure\.com:v3/([^/]+)/([^/]+)/([^/?#]+))")
GITHUB = re.compile(r"github\.com[:/]([^/]+)/([^/.]+?)(?:\.git)?$")
ADO_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798"  # Azure DevOps, for `az rest`
ADO_HOSTS = re.compile(r"^(dev\.azure\.com|([a-z0-9-]+\.)+visualstudio\.com)$")
MAX_REPORT = 50 * 1024 * 1024


def dockerfiles(repo: str) -> list[str]:
    out = []
    for root, dirs, files in os.walk(repo):
        depth = Path(root).relative_to(repo).parts
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and len(depth) < 4]
        out += [os.path.relpath(Path(root, f), repo) for f in files if f == "Dockerfile" or f.startswith("Dockerfile.")]
    return sorted(out)


def parse_trivy(raw: bytes, osv_vulns: list[dict]) -> dict:
    """Trivy JSON -> {status, vulns, deduped}; an empty or unreadable report is an error."""
    if not raw.strip():
        return {"status": "error", "error": "trivy-report is empty (the scan step wrote nothing)"}
    try:
        report = json.loads(raw)
    except ValueError:
        return {"status": "error", "error": "trivy-report is not JSON"}
    if not isinstance(report, dict) or "SchemaVersion" not in report or "ArtifactName" not in report:
        return {"status": "error", "error": "trivy-report is not a Trivy JSON report (no SchemaVersion/ArtifactName)"}
    known = {(v["package"], i) for v in osv_vulns for i in v["ids"] + v.get("aliases", [])}
    vulns, deduped = [], 0
    for res in report.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            key = (v.get("PkgName"), v.get("VulnerabilityID"))
            if key in known:
                deduped += 1
                continue
            vulns.append({"package": key[0], "version": v.get("InstalledVersion"), "id": key[1],
                          "severity": v.get("Severity"), "fixed": v.get("FixedVersion") or None, "target": res.get("Target")})
    by_severity = {}
    for v in vulns:
        by_severity[v["severity"]] = by_severity.get(v["severity"], 0) + 1
    return {"status": "findings" if vulns else "ok", "vulns": vulns, "by_severity": by_severity, "deduped": deduped}


def az(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return run_tool(["az", *args], os.getcwd(), timeout=timeout)


def fetch_ado(org: str, project: str, name: str) -> tuple[bytes | None, str]:
    """(newest trivy-report.json of the repo's pipelines, run label) via az; az attaches the token itself."""
    base = ["--detect", "false", "--org", f"https://dev.azure.com/{org}", "--project", project]
    d = az("repos", "show", *base, "--repository", name, "--query", "defaultBranch", "-o", "tsv")
    default = d.stdout.decode().strip() or "refs/heads/main"
    p = az("pipelines", "list", *base, "--query", "[].id", "-o", "json")
    runs = []
    for pid in json.loads(p.stdout or b"[]") if p.returncode == 0 else []:
        show = az("pipelines", "show", *base, "--id", str(pid), "--query", "repository.name", "-o", "tsv")
        if show.stdout.decode().strip() != name:
            continue
        # the default branch only: a PR run can publish a trivy-report of its own making
        r = az("pipelines", "runs", "list", *base, "--pipeline-ids", str(pid), "--branch", default, "--top", "5",
               "--query", "[?result=='succeeded'].{id:id, finish:finishTime}", "-o", "json")
        runs += json.loads(r.stdout or b"[]") if r.returncode == 0 else []
    for run in sorted(runs, key=lambda r: r["finish"] or "", reverse=True):
        a = az("pipelines", "runs", "artifact", "list", *base, "--run-id", str(run["id"]), "--query",
               "[?name=='trivy-report'].resource.downloadUrl | [0]", "-o", "tsv")
        url = a.stdout.decode().strip()
        if not url or a.returncode:
            continue
        if not ADO_HOSTS.match(urllib.parse.urlparse(url).hostname or ""):
            raise ToolError("trivy-report download URL is not an Azure DevOps host; not sending a token there")
        with tempfile.TemporaryDirectory(prefix="review-loop-trivy-") as tmp:
            z = Path(tmp, "a.zip")
            d = az("rest", "--method", "get", "--url", url, "--resource", ADO_RESOURCE, "--output-file", str(z), timeout=120)
            if d.returncode or not z.is_file():
                raise ToolError(f"downloading trivy-report of run {run['id']} failed")
            return report_from_zip(z), f"ado run {run['id']} ({(run['finish'] or '')[:10]})"
    return None, "no succeeded run with a trivy-report artifact"


def fetch_github(owner: str, name: str) -> tuple[bytes | None, str]:
    info = run_tool(["gh", "api", f"repos/{owner}/{name}"], os.getcwd())
    default = json.loads(info.stdout or b"{}").get("default_branch", "main") if info.returncode == 0 else "main"
    p = run_tool(["gh", "api", f"repos/{owner}/{name}/actions/artifacts?name=trivy-report&per_page=20"], os.getcwd())
    # default-branch runs of this repo only: a PR (or a fork's run) could upload a report of its own making
    arts = [a for a in (json.loads(p.stdout or b"{}").get("artifacts") or []) if not a.get("expired")
            and (a.get("workflow_run") or {}).get("head_branch") == default
            and (a.get("workflow_run") or {}).get("head_repository_id") == (a.get("workflow_run") or {}).get("repository_id")
            ] if p.returncode == 0 else []
    if not arts:
        return None, "no trivy-report artifact"
    newest = max(arts, key=lambda a: a["created_at"])
    with tempfile.TemporaryDirectory(prefix="review-loop-trivy-") as tmp:
        z = Path(tmp, "a.zip")
        d = run_tool(["gh", "api", f"repos/{owner}/{name}/actions/artifacts/{newest['id']}/zip"], os.getcwd(), timeout=120)
        if d.returncode:
            raise ToolError("downloading the trivy-report artifact failed")
        z.write_bytes(d.stdout)
        return report_from_zip(z), f"github artifact {newest['id']} ({newest['created_at'][:10]})"


def report_from_zip(z: Path) -> bytes:
    with zipfile.ZipFile(z) as zf:
        names = [n for n in zf.namelist() if n.endswith(".json")]
        if names and zf.getinfo(names[0]).file_size > MAX_REPORT:
            raise ValueError("trivy-report is larger than 50 MB")
        return zf.read(names[0]) if names else b""


def check_image(repo: str, osv: dict) -> dict:
    files = dockerfiles(repo)
    if not files:
        return {"status": "not_applicable", "why": "no Dockerfile"}
    origin = gitdiff.origin(repo) or ""
    try:
        if m := ADO.search(origin):
            org, project, name = [g for g in m.groups() if g is not None]
            raw, source = fetch_ado(org, urllib_unquote(project), urllib_unquote(name))
        elif m := GITHUB.search(origin):
            raw, source = fetch_github(*m.groups())
        else:
            return {"status": "skipped", "why": "origin is neither Azure DevOps nor GitHub", "dockerfiles": files}
    except (ToolError, OSError, ValueError, zipfile.BadZipFile, subprocess.TimeoutExpired) as e:
        return {"status": "error", "error": str(e), "dockerfiles": files}
    if raw is None:
        return {"status": "findings", "why": f"Dockerfile but {source}", "dockerfiles": files, "vulns": []}
    return {**parse_trivy(raw, osv.get("vulns", [])), "source": source, "dockerfiles": files}


def urllib_unquote(s: str) -> str:
    from urllib.parse import unquote
    return unquote(s)


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
        if p.returncode not in (0, 1):  # 2/3: bad flags or a fatal error, with nothing on stdout
            raise ValueError(f"exited {p.returncode}")
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
    head = gitdiff.git(repo, "rev-parse", "--verify", "--quiet", "HEAD", check=False).stdout.decode().strip()
    last = last_sweep(common) or {}
    # where the last gitleaks run that worked got to: a failed one must not make its commits look covered
    since = (last.get("checks", {}).get("gitleaks", {}).get("through") or None)
    osv = check_osv(repo)
    checks = {
        "osv": osv,
        "gitleaks": check_gitleaks(repo, since, head) if head else {"status": "skipped", "why": "no commits"},
        "workflows": check_workflows(repo),
        "hooks": check_hooks(repo, common),
        "image": check_image(repo, osv),
        "sast": {"status": "skipped", "why": "no own Semgrep rules yet (Decision 7)"},
    }
    if checks["gitleaks"]["status"] != "error" and head:
        checks["gitleaks"]["through"] = head
    elif since:
        checks["gitleaks"]["through"] = since
    machine = check_machine()
    if machine:
        checks["machine"] = machine
    result = {"schema_version": 1, "ts": now().isoformat(timespec="seconds"), "repo": Path(repo).name, "head": head,
              "checks": checks, "ms": round((time.monotonic() - start) * 1000)}
    (common / "review-loop").mkdir(parents=True, exist_ok=True)
    write_safely(common / "review-loop" / "sweep.json", json.dumps(result, indent=2) + "\n", common)
    return result


def counts(result: dict) -> dict:
    c = result.get("checks", {})
    return {"osv": len(c.get("osv", {}).get("vulns", [])), "gitleaks": len(c.get("gitleaks", {}).get("hits", [])),
            "workflows": len(c.get("workflows", {}).get("items", [])),
            "image": c.get("image", {}).get("status", "-") if c.get("image", {}).get("status") != "findings"
            else len(c["image"].get("vulns", [])) or "no report",
            "hooks": len(c.get("hooks", {}).get("unknown", []))
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
    from .ui import optins
    answers = {k: v.get("answer") for k, v in optins().items()}
    lines = ["repo\tlast sweep\tosv\tgitleaks\tworkflows\timage\thooks\terrors\tui opt-in"]
    for repo in repos_under(roots):
        ui = answers.get(gitdiff.origin(str(repo)) or str(repo.resolve()), "")
        last = last_sweep(repo / ".git")
        if not last:
            lines.append(f"{repo}\tnever\t\t\t\t\t\t\t{ui}")
            continue
        c = counts(last)
        lines.append(f"{repo}\t{last['ts'][:10]}\t{c['osv']}\t{c['gitleaks']}\t{c['workflows']}\t{c['image']}\t{c['hooks']}\t{c['errors']}\t{ui}")
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
                     f"{c['workflows']}, image {c['image']}, hooks {c['hooks']}, errors {c['errors']} ({result['ms']} ms)\n")
    return 0
