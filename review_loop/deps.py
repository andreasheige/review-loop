"""D3: added/changed resolved versions in package-lock.json (v2/v3) and uv.lock.

Online (origin github.com/andreasheige/* or no origin): OSV MAL-* → hard dep-mal; missing from the public
registry → hard dep-nonexistent; any lookup error or timeout → needs_human. Other origins (client repos,
Decision 8) make no network call: osv-scanner --offline against its local DB if present, else needs_human.
The network layer is injectable (Net) so tests run offline.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import VERSION
from .normalise import finding, sha1
from .tools import ToolError, resolve

LOCKFILES = {"package-lock.json": "npm", "uv.lock": "PyPI"}
OWN_ORIGIN = re.compile(r"github\.com[:/]andreasheige/")
NPM_PUBLIC = "https://registry.npmjs.org/"
PYPI_PUBLIC = {"https://pypi.org/simple", "https://pypi.org/simple/"}
TIMEOUT = 3.0
REF = f"review-loop@{VERSION}"


class Net:
    """Real network. Returns (status, parsed JSON or None); raises OSError/ValueError on failure or timeout."""

    def request(self, url: str, body: dict | None = None, timeout: float = TIMEOUT) -> tuple[int, object]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                     headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, None


def parse_npm(text: str) -> dict[tuple[str, str], tuple[int, bool]]:
    """{(name, version): (line, public)} from a v2/v3 lockfile's "packages"; ValueError if not v2/v3."""
    doc = json.loads(text)
    if not isinstance(doc.get("packages"), dict):
        raise ValueError("package-lock.json without a v2/v3 packages map")
    lines = {m.group(1): n for n, m in enumerate((re.match(r'\s*"(node_modules/[^"]+)": \{', l) for l in text.split("\n")), 1) if m}
    out = {}
    for key, entry in doc["packages"].items():
        if not key or not isinstance(entry, dict) or entry.get("link") or "version" not in entry or "resolved" not in entry:
            continue
        name = entry.get("name") or key.rsplit("node_modules/", 1)[-1]
        out[(name, entry["version"])] = (lines.get(key, 1), entry["resolved"].startswith(NPM_PUBLIC))
    return out


def parse_uv(text: str) -> dict[tuple[str, str], tuple[int, bool]]:
    """Minimal uv.lock reader (no tomllib on 3.9): top-level name/version/source keys of each [[package]]."""
    out, pkg = {}, None

    def close(p):
        if p and "version" in p and p.get("registry"):
            out[(p["name"], p["version"])] = (p["line"], p["registry"] in PYPI_PUBLIC)

    for n, line in enumerate(text.split("\n"), 1):
        if line.strip() == "[[package]]":
            close(pkg)
            pkg = {"line": n}
        elif pkg is not None and (m := re.match(r'(name|version) = "([^"]*)"', line)):
            pkg[m.group(1)] = m.group(2)
            if m.group(1) == "name":
                pkg["line"] = n
        elif pkg is not None and (m := re.match(r'source = \{ registry = "([^"]*)"', line)):
            pkg["registry"] = m.group(1)
    close(pkg)
    return out


PARSERS = {"npm": parse_npm, "PyPI": parse_uv}


def changed(old: str | None, new: str, eco: str) -> dict:
    new_pkgs = PARSERS[eco](new)
    try:
        old_pkgs = PARSERS[eco](old) if old else {}
    except ValueError:
        old_pkgs = {}
    return {k: v for k, v in new_pkgs.items() if k not in old_pkgs}


def is_online(origin: str | None) -> bool:
    return origin is None or bool(OWN_ORIGIN.search(origin))


def registry_url(eco: str, name: str, version: str) -> str:
    q = urllib.parse.quote
    if eco == "npm":
        return f"{NPM_PUBLIC}{q(name, safe='@/')}/{q(version, safe='')}"
    return f"https://pypi.org/pypi/{q(name, safe='')}/{q(version, safe='')}/json"


def _dep_finding(kind, path, eco, name, version, line, status, rule_class, title, reasoning, ref, tool):
    return finding(tool=tool, rule=kind, path=path, k=f"{eco}:{name}@{version}", lines=(line, line), status=status,
                   rule_class=rule_class, surface="dep", title=title, reasoning=reasoning, ref=ref)


def check_online(path: str, eco: str, pkgs: dict, net: Net) -> list[dict]:
    def osv(name, version):
        status, body = net.request("https://api.osv.dev/v1/query",
                                   {"version": version, "package": {"name": name, "ecosystem": eco}})
        if status != 200 or not isinstance(body, dict):
            raise ValueError(f"OSV status {status}")
        return sorted(v["id"] for v in body.get("vulns", []) if str(v.get("id", "")).startswith("MAL-"))

    def exists(name, version):
        status, _ = net.request(registry_url(eco, name, version))
        if status not in (200, 404):
            raise ValueError(f"registry status {status}")
        return status == 200

    with ThreadPoolExecutor(max_workers=min(32, 2 * len(pkgs)) or 1) as pool:
        jobs = {(k, "osv"): pool.submit(osv, *k) for k in pkgs}
        jobs.update({(k, "exists"): pool.submit(exists, *k) for k, (_, public) in pkgs.items() if public})
        results = {}
        for key, fut in jobs.items():
            try:
                results[key] = fut.result()
            except Exception as e:  # noqa: BLE001 - any lookup failure (timeout, DNS, bad JSON) is needs_human, never pass
                results[key] = e
    findings = []
    for (name, version), (line, _) in pkgs.items():
        label = f"{name}@{version}"
        mal = results[((name, version), "osv")]
        if isinstance(mal, Exception):
            findings.append(_dep_finding("dep-mal-unverified", path, eco, name, version, line, "needs_human", "dep-mal",
                                         f"OSV lookup failed for {label}", f"OSV lookup failed ({type(mal).__name__}).",
                                         f"{REF}:dep-mal-unverified", "osv"))
        elif mal:
            findings.append(_dep_finding("dep-mal", path, eco, name, version, line, "hard", "dep-mal",
                                         f"Malicious package {label} ({', '.join(mal)})",
                                         f"OSV lists {', '.join(mal)} for {eco} {label}.", f"osv.dev@v1:{mal[0]}", "osv"))
        found = results.get(((name, version), "exists"), True)
        if isinstance(found, Exception):
            findings.append(_dep_finding("dep-nonexistent-unverified", path, eco, name, version, line, "needs_human",
                                         "dep-nonexistent", f"Registry lookup failed for {label}",
                                         f"Registry lookup failed ({type(found).__name__}).",
                                         f"{REF}:dep-nonexistent-unverified", "registry"))
        elif not found:
            findings.append(_dep_finding("dep-nonexistent", path, eco, name, version, line, "hard", "dep-nonexistent",
                                         f"{label} does not exist in the {eco} registry",
                                         f"The public {eco} registry returns 404 for {label}.",
                                         f"{REF}:dep-nonexistent", "registry"))
    return findings


def osv_db_dir() -> Path:
    env = os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY")
    if env:
        return Path(env)
    cache = Path.home() / ("Library/Caches" if sys.platform == "darwin" else ".cache")
    return cache / "osv-scanner"


def unverified(path: str, pkgs: dict, why: str) -> dict:
    names = sorted(f"{n}@{v}" for n, v in pkgs)
    first = min(line for line, _ in pkgs.values())
    return finding(tool="osv", rule="dep-unverified-offline", path=path, k=sha1("\n".join(names)), lines=(first, first),
                   status="needs_human", rule_class="dep-mal", surface="dep",
                   title=f"{len(names)} dependency version(s) not verified offline in {path}",
                   reasoning=f"Dependency not verified offline: {why}.", ref=f"{REF}:dep-unverified-offline",
                   body="Unverified: " + ", ".join(names))


def check_offline(path: str, eco: str, pkgs: dict, new_text: str) -> list[dict]:
    if not (osv_db_dir() / eco / "all.zip").is_file():
        return [unverified(path, pkgs, "no local OSV database")]
    try:
        exe, version = resolve("osv-scanner")
    except ToolError as e:
        return [unverified(path, pkgs, str(e))]
    with tempfile.TemporaryDirectory(prefix="review-loop-osv-") as tmp:
        lock = Path(tmp) / Path(path).name
        lock.write_text(new_text)
        p = subprocess.run([exe, "scan", "source", "--offline", "--format", "json", "--lockfile", str(lock)],
                           capture_output=True, timeout=30)
    try:
        if p.returncode not in (0, 1):
            raise ValueError(f"osv-scanner exited {p.returncode}")
        report = json.loads(p.stdout)
    except ValueError as e:
        return [unverified(path, pkgs, str(e))]
    findings = []
    for res in report.get("results", []):
        for pk in res.get("packages", []):
            key = (pk["package"]["name"], pk["package"]["version"])
            mal = sorted(v["id"] for v in pk.get("vulnerabilities", []) if v["id"].startswith("MAL-"))
            if key in pkgs and mal:
                findings.append(_dep_finding("dep-mal", path, eco, *key, pkgs[key][0], "hard", "dep-mal",
                                             f"Malicious package {key[0]}@{key[1]} ({', '.join(mal)})",
                                             f"OSV offline DB lists {', '.join(mal)}.",
                                             f"osv-scanner@{version}:{mal[0]}", "osv"))
    return findings


def scan(lockfiles: list[tuple[str, str | None, str]], origin: str | None, net: Net | None = None) -> list[dict]:
    """lockfiles: [(repo-relative path, old text or None, new text)]."""
    online = is_online(origin)
    findings = []
    for path, old, new in lockfiles:
        eco = LOCKFILES[Path(path).name]
        try:
            pkgs = changed(old, new, eco)
        except ValueError as e:
            findings.append(finding(tool="osv", rule="dep-unparsed", path=path, k=sha1(path), lines=(1, 1),
                                    status="needs_human", rule_class="dep-mal", surface="dep",
                                    title=f"Lockfile not parsed: {path}", reasoning=f"Dependency not verified: {e}.",
                                    ref=f"{REF}:dep-unparsed"))
            continue
        if not pkgs:
            continue
        findings += check_online(path, eco, pkgs, net or Net()) if online else check_offline(path, eco, pkgs, new)
    return findings
