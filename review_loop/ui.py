"""review-loop ui: the UI lens. axe, keyboard and screenshots on the stories a change touches, base vs head.

usage: review-loop ui [--base REF] [--rev REV] [--static-base DIR --static-head DIR]

Runs only when the change touches UI files (components, styles, stories, .storybook/); otherwise not_applicable.
It builds a static Storybook of the merge-base and of head in scratch worktrees (node_modules linked from the
checkout; the checkout itself is never touched), serves both on 127.0.0.1, and runs ui/runner.mjs with the
repo's own Playwright and axe-core: for each story near a changed file, at mobile and desktop width in light and
dark, an axe WCAG 2.0-2.2 A/AA pass, a Tab-sequence keyboard-trap check and a screenshot. Every request to a
host other than localhost is aborted. --static-base/--static-head take two already built sites instead.

Compared with base: a new serious or critical axe violation, or a new keyboard trap -> hard (a11y); a new
minor or moderate one -> needs_human; a story whose screenshot changed -> needs_human (ui-visual: maybe
intended, a human looks); anything already on base -> advisory, pre-existing (backlog). The result goes to
<git-common-dir>/review-loop/<patch-id>/ui.json for the push gate (plan 7.5). Exit 0 pass, 1 block,
2 needs_human, 3 error.
"""
from __future__ import annotations

import contextlib
import functools
import http.server
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from . import eot, gitdiff, normalise

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "ui" / "runner.mjs"
UI_FILE = re.compile(r"\.(tsx|jsx|vue|svelte|css|scss|sass|less|html|mdx)$|(^|/)\.storybook/", re.I)
VIEWPORTS = [{"name": "mobile", "width": 390, "height": 844}, {"name": "desktop", "width": 1280, "height": 800}]
SCHEMES = ["light", "dark"]
MAX_STORIES = 30
BLOCKING_IMPACT = {"serious", "critical"}


class UiError(Exception):
    pass


def node_modules(repo: str) -> Path | None:
    nm = Path(os.environ.get("REVIEW_LOOP_UI_NODE_MODULES") or Path(repo, "node_modules"))
    return nm if (nm / "playwright").is_dir() and (nm / "axe-core/axe.min.js").is_file() else None


def ui_paths(repo: str, base: str, head: str) -> list[str]:
    return [p for _, p, _ in eot.changes(repo, base, head) if UI_FILE.search(p)]


@contextlib.contextmanager
def serve(directory: Path):
    handler = functools.partial(QuietHandler, directory=str(directory))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def build_storybook(repo: str, sha: str, nm: Path, work: Path, side: str) -> Path:
    tree, out = work / side, work / f"{side}-storybook"
    gitdiff.git(repo, "worktree", "add", "--detach", "--force", str(tree), sha)
    try:
        (tree / "node_modules").symlink_to(nm)
        p = subprocess.run([str(nm / ".bin/storybook"), "build", "-o", str(out), "--quiet", "--disable-telemetry"],
                           cwd=tree, capture_output=True, timeout=900,
                           env={**os.environ, "CI": "1", "STORYBOOK_DISABLE_TELEMETRY": "1"})
        if p.returncode != 0 or not (out / "index.json").is_file():
            raise UiError(f"storybook build of {side} failed ({p.returncode}): {p.stderr.decode('utf-8', 'replace')[-300:]}")
        return out
    finally:
        gitdiff.git(repo, "worktree", "remove", "--force", str(tree), check=False)


def stories(site: Path) -> dict[str, str]:
    """{story id: import path} from a static Storybook's index.json."""
    index = json.loads((site / "index.json").read_text())
    return {e["id"]: e.get("importPath", "") for e in index.get("entries", {}).values() if e.get("type") == "story"}


def pick(head_stories: dict[str, str], changed: list[str]) -> list[str]:
    """Stories next to a changed file (same directory, or the story file itself); a change to .storybook/ or a
    stylesheet outside any component directory picks the first stories of the index instead."""
    dirs = {str(Path(p).parent) for p in changed}
    near = [sid for sid, imp in head_stories.items()
            if str(Path(imp.removeprefix("./")).parent) in dirs or imp.removeprefix("./") in changed]
    if not near and any(p.startswith(".storybook/") or p.endswith((".css", ".scss")) for p in changed):
        near = list(head_stories)
    return near[:MAX_STORIES]


def run_side(nm: Path, site: Path, ids: list[str], work: Path, side: str) -> dict:
    cfg, out = work / f"{side}.json", work / f"{side}-results.json"
    with serve(site) as url:
        cfg.write_text(json.dumps({"nodeModules": str(nm), "baseUrl": url, "stories": ids, "viewports": VIEWPORTS,
                                   "schemes": SCHEMES, "shots": str(work / f"{side}-shots"), "out": str(out)}))
        p = subprocess.run(["node", str(RUNNER), str(cfg)], capture_output=True, timeout=1800)
    if p.returncode != 0 or not out.is_file():
        raise UiError(f"ui runner ({side}) failed: {p.stderr.decode('utf-8', 'replace')[-300:]}")
    return {(r["story"], r["viewport"], r["scheme"]): r for r in json.loads(out.read_text())}


def ui_finding(rule, rule_class, story, where, k, status, title, introduced=True):
    f = normalise.finding(tool="reviewloop", rule=rule, path=f"<story:{story}>", k=k, lines=(1, 1), status=status,
                          rule_class=rule_class, surface="code", title=title, reasoning=f"{rule} at {where}",
                          ref=f"review-loop:{rule}", introduced=introduced)
    f["lens"] = "ui"
    return f


def compare(base: dict, head: dict) -> list[dict]:
    out = []
    for key, h in sorted(head.items()):
        story, vp, scheme = key
        where = f"{vp}/{scheme}"
        b = base.get(key)
        if h["error"]:
            out.append(ui_finding("ui-error", "a11y", story, where, normalise.sha1(f"{key}"), "needs_human",
                                  f"Story {story} did not load at {where}: {h['error'][:80]}"))
            continue
        before = {(v["id"], t) for v in (b or {}).get("violations", []) for t in v["targets"]}
        for v in h["violations"]:
            for t in v["targets"]:
                k = normalise.sha1(f"{story}|{v['id']}|{t}")
                if (v["id"], t) in before:
                    out.append(ui_finding(f"axe-{v['id']}", "a11y", story, where, k, "advisory",
                                          f"{v['help']} ({v['id']}, {t}) — already on base", introduced=False))
                else:
                    status = "hard" if v["impact"] in BLOCKING_IMPACT else "needs_human"
                    out.append(ui_finding(f"axe-{v['id']}", "a11y", story, where, k, status,
                                          f"{v['help']} ({v['id']}, {v['impact']}, {t}) at {where}"))
        if h["trap"] and not (b and b.get("trap")):
            out.append(ui_finding("keyboard-trap", "a11y", story, where, normalise.sha1(f"{story}|trap|{h['trap']}"),
                                  "hard", f"Keyboard trap on {h['trap']} at {where}: Tab can't leave it"))
        if b and b.get("shot") and h.get("shot") and Path(b["shot"]).read_bytes() != Path(h["shot"]).read_bytes():
            out.append(ui_finding("visual-change", "ui-visual", story, where, normalise.sha1(f"{story}|{where}|shot"),
                                  "needs_human", f"Story {story} looks different at {where}: intended?"))
    return normalise.merge(out)


def run(repo: str, base_ref: str, rev: str = "HEAD", static: tuple[str, str] | None = None) -> dict:
    repo = gitdiff.git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip()
    head = gitdiff.verify_commit(repo, rev)
    base = gitdiff.git(repo, "merge-base", gitdiff.verify_commit(repo, base_ref), head).stdout.decode().strip()
    changed = ui_paths(repo, base, head)
    result = {"schema_version": 1, "head": head, "base": base, "changed_ui": changed, "findings": []}
    if not changed:
        return {**result, "status": "not_applicable", "outcome": {"exit_code": 0, "summary": "not_applicable"}}
    nm = node_modules(repo)
    if not nm:
        return {**result, "status": "no_playwright",
                "outcome": {"exit_code": 3, "summary": "error", "error": "no Playwright + axe-core in node_modules"}}
    error = None
    try:
        with tempfile.TemporaryDirectory(prefix="review-loop-ui-") as tmp:
            work = Path(tmp)
            if static:
                sites = (Path(static[0]), Path(static[1]))
            else:
                sites = (build_storybook(repo, base, nm, work, "base"), build_storybook(repo, head, nm, work, "head"))
            ids = pick(stories(sites[1]), changed)
            result["stories"] = ids
            base_ids = [i for i in ids if i in stories(sites[0])]
            before = run_side(nm, sites[0], base_ids, work, "base") if base_ids else {}
            after = run_side(nm, sites[1], ids, work, "head")
            result["findings"] = compare(before, after)
    except (UiError, OSError, ValueError, subprocess.TimeoutExpired, gitdiff.GitError) as e:
        error = str(e)
    code, summary = normalise.outcome(result["findings"], [error] if error else [])
    result["outcome"] = {"exit_code": code, "summary": summary, **({"error": error} if error else {})}
    result["status"] = "ran"
    try:
        pid = eot.patch_id(repo, base, head)
        common = Path(repo, gitdiff.git(repo, "rev-parse", "--git-common-dir").stdout.decode().strip())
        (common / "review-loop" / pid).mkdir(parents=True, exist_ok=True)
        (common / "review-loop" / pid / "ui.json").write_text(json.dumps(result, indent=2) + "\n")
    except (eot.EotError, OSError):
        pass
    return result


def main(argv: list[str]) -> int:
    def opt(name, default=None):
        return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else default

    base_ref = opt("--base") or eot.default_base(".")
    static = (opt("--static-base"), opt("--static-head")) if "--static-head" in argv else None
    try:
        result = run(".", base_ref, opt("--rev", "HEAD"), static)
    except Exception as e:  # noqa: BLE001 - a crash is exit 3, never a pass
        result = {"findings": [], "outcome": {"exit_code": 3, "summary": "error", "error": f"internal error: {type(e).__name__}"}}
    lines = [f"review-loop ui: {result['outcome']['summary']}"]
    for f in result["findings"]:
        if f["status"] != "advisory":
            lines.append(f"  {f['status']:<11} {f['rule_class']:<9} {f['title']}  [{f['id']}]")
    backlog = sum(1 for f in result["findings"] if f["status"] == "advisory")
    if backlog:
        lines.append(f"  {backlog} pre-existing finding(s) to backlog")
    if result["outcome"].get("error"):
        lines.append(f"  error: {result['outcome']['error']}")
    sys.stdout.write("\n".join(lines) + "\n")
    return result["outcome"]["exit_code"]
