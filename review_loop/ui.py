"""review-loop ui: the UI lens. axe, keyboard and screenshots on the stories a change touches, base vs head.

usage: review-loop ui [--base REF] [--rev REV] [--static-base DIR --static-head DIR]

Runs only when the change touches UI files (components, styles, stories, .storybook/); otherwise not_applicable.
It builds a static Storybook of the merge-base and of head in scratch worktrees (node_modules linked from the
checkout; the checkout itself is never touched), serves both on 127.0.0.1, and runs ui/runner.mjs with the
repo's own Playwright and axe-core: for each story near a changed file, at mobile and desktop width in light and
dark, an axe WCAG 2.0-2.2 A/AA pass, a Tab-sequence keyboard-trap check and a screenshot. Every request to a
host other than localhost is aborted. --static-base/--static-head take two already built sites instead.

Without Playwright + axe-core in the repo it asks once, at a terminal (/dev/tty, which an agent's shell
lacks, so an agent can't answer): yes (prints the install command; review-loop installs nothing), not now
(asked again on a UI change after 7 days) or never. Answers live in <state dir>/ui-optin.json keyed by the
remote URL; `sweep --digest` shows them, "never" included. Until then the run is skipped with exit 0.

Compared with base: a new serious or critical axe violation, or a new keyboard trap -> hard (a11y); a new
minor or moderate one -> needs_human; where base didn't load, needs_human; no nearby story, or more than
MAX_STORIES -> needs_human (ui-coverage), never a silent pass; a story whose screenshot changed -> needs_human (ui-visual: maybe
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
from .secret_scan import state_dir
from .tools import write_safely

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "ui" / "runner.mjs"
UI_FILE = re.compile(r"\.(tsx|jsx|vue|svelte|css|scss|sass|less|html|mdx)$|\.stories\.[cm]?[jt]s$|\.css\.[jt]s$|"
                     r"(^|/)\.storybook/", re.I)
VIEWPORTS = [{"name": "mobile", "width": 390, "height": 844}, {"name": "desktop", "width": 1280, "height": 800}]
SCHEMES = ["light", "dark"]
MAX_STORIES = 30
BLOCKING_IMPACT = {"serious", "critical"}


SNOOZE_DAYS = 7
INSTALL = "npm i -D playwright axe-core && npx playwright install chromium"


class UiError(Exception):
    pass


def optin_path() -> Path:
    return state_dir() / "ui-optin.json"


def optin_key(repo: str) -> str:
    return gitdiff.origin(repo) or str(Path(repo).resolve())


def optins() -> dict:
    try:
        data = json.loads(optin_path().read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def ask_on_tty(question: str) -> str | None:
    """y / n / v typed at the terminal, or None without one (an agent's shell)."""
    try:
        with open("/dev/tty", "r+") as tty:
            tty.write(f"{question} [y]es / [n]ot now / ne[v]er: ")
            tty.flush()
            return tty.readline().strip().lower()[:1] or None
    except OSError:
        return None


def optin(repo: str, ask=ask_on_tty) -> str:
    """'yes', 'snoozed', 'never' or 'unanswered' for running without Playwright here."""
    import datetime

    key, data = optin_key(repo), optins()
    now = datetime.datetime.now(datetime.timezone.utc)
    prior = data.get(key) or {}
    if prior.get("answer") == "never":
        return "never"
    if prior.get("answer") == "not_now":
        try:
            if now - datetime.datetime.fromisoformat(prior["at"]) < datetime.timedelta(days=SNOOZE_DAYS):
                return "snoozed"
        except (KeyError, ValueError):
            pass
    reply = ask(f"The UI lens needs Playwright and axe-core in {Path(repo).name}. Install them?")
    answer = {"y": "yes", "n": "not_now", "v": "never"}.get(reply or "")
    if not answer:
        return "unanswered"
    data[key] = {"answer": answer, "at": now.isoformat(timespec="seconds"), "tty": True}
    optin_path().parent.mkdir(parents=True, exist_ok=True)
    optin_path().write_text(json.dumps(data, indent=1) + "\n")
    return {"yes": "yes", "not_now": "snoozed", "never": "never"}[answer]


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


def nearby(head_stories: dict[str, str], changed: list[str]) -> list[str]:
    """Stories next to a changed file (same directory, or the story file itself); a change to .storybook/ or a
    stylesheet or mdx outside any component directory means every story."""
    dirs = {str(Path(p).parent) for p in changed}
    near = [sid for sid, imp in head_stories.items()
            if str(Path(imp.removeprefix("./")).parent) in dirs or imp.removeprefix("./") in changed]
    if not near and any(p.startswith(".storybook/") or p.endswith((".css", ".scss", ".sass", ".less", ".mdx"))
                        for p in changed):
        near = list(head_stories)
    return near


def pick(head_stories: dict[str, str], changed: list[str]) -> list[str]:
    return nearby(head_stories, changed)[:MAX_STORIES]


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
    """One finding per (story, rule, target) across viewports and schemes: new if it is new in any variant (with the
    variants listed), pre-existing only if base had it wherever head has it. A variant whose base didn't load can't
    show what is new, so its head violations go to a human instead of blocking."""
    out, changed_looks, axe = [], {}, {}
    for key, h in sorted(head.items()):
        story, vp, scheme = key
        where = f"{vp}/{scheme}"
        b = base.get(key)
        if h["error"]:
            out.append(ui_finding("ui-error", "a11y", story, where, normalise.sha1(f"{key}"), "needs_human",
                                  f"Story {story} did not load at {where}: {h['error'][:80]}"))
            continue
        base_broken = bool(b and b.get("error"))
        before = {(v["id"], t) for v in (b or {}).get("violations", []) for t in v["targets"]}
        for v in h["violations"]:
            for t in v["targets"]:
                a = axe.setdefault((story, v["id"], t), {"help": v["help"], "impact": v["impact"], "new": [],
                                                         "old": [], "unknown": []})
                bucket = "unknown" if base_broken else "old" if (v["id"], t) in before else "new"
                a[bucket].append(where)
        if h["trap"] and not (b and b.get("trap")):
            status = "needs_human" if base_broken else "hard"
            out.append(ui_finding("keyboard-trap", "a11y", story, where, normalise.sha1(f"{story}|trap|{h['trap']}|{where}"),
                                  status, f"Keyboard trap on {h['trap']} at {where}: Tab can't leave it"))
        if b and b.get("shot") and h.get("shot") and Path(b["shot"]).read_bytes() != Path(h["shot"]).read_bytes():
            changed_looks.setdefault(story, []).append(where)
    for (story, rule, target), a in sorted(axe.items()):
        k = normalise.sha1(f"{story}|{rule}|{target}")
        if a["new"]:
            status = "hard" if a["impact"] in BLOCKING_IMPACT else "needs_human"
            out.append(ui_finding(f"axe-{rule}", "a11y", story, ", ".join(a["new"]), k, status,
                                  f"{a['help']} ({rule}, {a['impact']}, {target}) — new at {', '.join(a['new'])}"))
        elif a["unknown"]:
            out.append(ui_finding(f"axe-{rule}", "a11y", story, ", ".join(a["unknown"]), k, "needs_human",
                                  f"{a['help']} ({rule}, {a['impact']}, {target}) — base could not be checked"))
        else:
            out.append(ui_finding(f"axe-{rule}", "a11y", story, ", ".join(a["old"]), k, "advisory",
                                  f"{a['help']} ({rule}, {target}) — already on base", introduced=False))
    for story, wheres in sorted(changed_looks.items()):  # one finding per story, not per viewport and scheme
        out.append(ui_finding("visual-change", "ui-visual", story, ", ".join(wheres), normalise.sha1(f"{story}|shot"),
                              "needs_human", f"Story {story} looks different ({', '.join(wheres)}): intended?"))
    return normalise.merge(out)


def coverage_finding(changed: list[str], picked: int, available: int) -> dict | None:
    """UI files changed but no story (or not every nearby story) was looked at: a human decides, never a pass."""
    if picked and available <= MAX_STORIES:
        return None
    why = (f"no story is next to the changed UI files ({', '.join(changed[:3])}{', …' if len(changed) > 3 else ''})"
           if not picked else f"only the first {MAX_STORIES} of {available} nearby stories were checked")
    return ui_finding("ui-coverage", "a11y", "-", "-", normalise.sha1("|".join(changed)), "needs_human",
                      f"UI change not fully checked: {why}")


def run(repo: str, base_ref: str, rev: str = "HEAD", static: tuple[str, str] | None = None, ask=None) -> dict:
    repo = gitdiff.git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip()
    head = gitdiff.verify_commit(repo, rev)
    base = gitdiff.git(repo, "merge-base", gitdiff.verify_commit(repo, base_ref), head).stdout.decode().strip()
    changed = ui_paths(repo, base, head)
    result = {"schema_version": 1, "head": head, "base": base, "changed_ui": changed, "findings": []}
    if not changed:
        return {**result, "status": "not_applicable", "outcome": {"exit_code": 0, "summary": "not_applicable"}}
    nm = node_modules(repo)
    if not nm:
        state = optin(repo, ask) if ask is not None else optin(repo)
        message = {"yes": f"install them, then run again: {INSTALL}", "snoozed": "asked recently: not now",
                   "never": "this repo opted out of the UI lens (never)",
                   "unanswered": "no Playwright + axe-core here; a human answers the opt-in at a terminal"}[state]
        return {**result, "status": f"no_playwright:{state}", "message": message,
                "outcome": {"exit_code": 0, "summary": "skipped"}}
    error = None
    try:
        with tempfile.TemporaryDirectory(prefix="review-loop-ui-") as tmp:
            work = Path(tmp)
            if static:
                sites = (Path(static[0]), Path(static[1]))
                result["static"] = True  # a test hook: the gate never counts a static result
            else:
                sites = (build_storybook(repo, base, nm, work, "base"), build_storybook(repo, head, nm, work, "head"))
            near = nearby(stories(sites[1]), changed)
            ids = near[:MAX_STORIES]
            result["stories"] = ids
            base_ids = [i for i in ids if i in stories(sites[0])]
            before = run_side(nm, sites[0], base_ids, work, "base") if base_ids else {}
            after = run_side(nm, sites[1], ids, work, "head")
            result["findings"] = compare(before, after)
            gap = coverage_finding(changed, len(ids), len(near))
            if gap:
                result["findings"].append(gap)
    except (UiError, OSError, ValueError, subprocess.TimeoutExpired, gitdiff.GitError) as e:
        error = str(e)
    code, summary = normalise.outcome(result["findings"], [error] if error else [])
    result["outcome"] = {"exit_code": code, "summary": summary, **({"error": error} if error else {})}
    result["status"] = "ran"
    try:
        pid = eot.patch_id(repo, base, head)
        common = Path(repo, gitdiff.git(repo, "rev-parse", "--git-common-dir").stdout.decode().strip())
        (common / "review-loop" / pid).mkdir(parents=True, exist_ok=True)
        write_safely(common / "review-loop" / pid / "ui.json", json.dumps(result, indent=2) + "\n", common)
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
    if result.get("message"):
        lines.append(f"  {result['message']}")
    if result["outcome"].get("error"):
        lines.append(f"  error: {result['outcome']['error']}")
    sys.stdout.write("\n".join(lines) + "\n")
    return result["outcome"]["exit_code"]
