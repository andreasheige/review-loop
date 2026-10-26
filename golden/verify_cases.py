#!/usr/bin/env python3
"""Check every case in cases.jsonl against git history.

bug       every expect range holds a line, introduced by `head`, that the later fix
          commit (first token of `source`) changed: blame of the fix's removed/modified
          lines at fix^ must land inside the range.
clean     no later fix commit (subject starts with "fix") changed a line `head` introduced.
security,
injection synthetic: rebuild with synthetic/build.sh into a temp dir, base/head SHAs must
          match, and every expect range must lie inside the head diff.

Prints one line per case; exits 0 only if all pass. Stdlib only.
"""
import json
import re
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path

HERE = Path(__file__).resolve().parent
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
BLAME_HEADER = re.compile(r"^([0-9a-f]{40}) (\d+) (\d+)")
FIX_SUBJECT = re.compile(r"(?i)^fix")


def git(repo, *args):
    result = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def hunks(repo, old, new):
    """{(side, path): [(start, end)]} for old-side (removed) and new-side (added) lines."""
    out = git(repo, "diff", "-U0", "--no-renames", "--no-color", "--no-ext-diff", old, new)
    res, old_path, new_path = {}, None, None
    for line in out.splitlines():
        if line.startswith("--- "):
            old_path = None if line[4:] == "/dev/null" else line[6:]
        elif line.startswith("+++ "):
            new_path = None if line[4:] == "/dev/null" else line[6:]
        elif (m := HUNK.match(line)):
            os_, on = int(m[1]), int(m[2] if m[2] is not None else 1)
            ns, nn = int(m[3]), int(m[4] if m[4] is not None else 1)
            if old_path and on:
                res.setdefault(("old", old_path), []).append((os_, os_ + on - 1))
            if new_path:
                # A pure deletion has no new lines; its position is the line after it.
                res.setdefault(("new", new_path), []).append((ns, ns + max(nn, 1) - 1))
    return res


@lru_cache(maxsize=None)
def fix_origins(repo, fix):
    """{(origin sha, origin path, origin line)} for every line the fix removed or changed."""
    origins = set()
    for (side, path), ranges in hunks(repo, fix + "^", fix).items():
        if side != "old":
            continue
        for start, end in ranges:
            out = git(repo, "blame", "-w", "--line-porcelain", "-L", f"{start},{end}", fix + "^", "--", path)
            sha = line_no = None
            for line in out.splitlines():
                if (m := BLAME_HEADER.match(line)):
                    sha, line_no = m[1], int(m[2])
                elif line.startswith("filename "):
                    origins.add((sha, line[9:], line_no))
    return frozenset(origins)


def check_bug(case):
    repo, head = case["repo"], case["head"]
    fix = git(repo, "rev-parse", case["source"].split()[0]).strip()
    if git(repo, "rev-parse", head + "^").strip() != case["base"]:
        return "base is not head^"
    if not case["expect"]:
        return "bug case with empty expect"
    hit = {(p, n) for sha, p, n in fix_origins(repo, fix) if sha == head}
    for e in case["expect"]:
        if not any(p == e["path"] and e["start_line"] <= n <= e["end_line"] for p, n in hit):
            return f"{e['path']}:{e['start_line']}-{e['end_line']} not changed by fix {fix[:10]}"
    return None


def later_fixes(repo, head):
    out = git(repo, "log", "--no-merges", "--format=%H %s", f"{head}..HEAD")
    return [l.split(" ", 1)[0] for l in out.splitlines() if FIX_SUBJECT.match(l.split(" ", 1)[1] if " " in l else "")]


def check_clean(case):
    repo, head = case["repo"], case["head"]
    if case["expect"]:
        return "clean case with non-empty expect"
    if git(repo, "rev-parse", head + "^").strip() != case["base"]:
        return "base is not head^"
    fixes = later_fixes(repo, head)
    for fix in fixes:
        if any(sha == head for sha, _, _ in fix_origins(repo, fix)):
            return f"later fix {fix[:10]} touched its lines"
    return None, len(fixes)


def check_synthetic(case, built, root):
    name = case["repo"].split(":", 1)[1]
    if name not in built:
        return f"build.sh did not produce {name}"
    if built[name] != (case["base"], case["head"]):
        return f"SHA mismatch: built {built[name][0][:10]}..{built[name][1][:10]}"
    if not case["expect"]:
        return "synthetic case with empty expect"
    diff = hunks(str(root / name), case["base"], case["head"])
    for e in case["expect"]:
        ranges = diff.get(("new", e["path"]), [])
        lines = range(e["start_line"], e["end_line"] + 1)
        if not all(any(s <= n <= t for s, t in ranges) for n in lines):
            return f"{e['path']}:{e['start_line']}-{e['end_line']} outside head diff"
    return None


def build_synthetic(tmp):
    root = Path(tmp) / "synthetic"
    out = subprocess.run(["bash", str(HERE / "synthetic" / "build.sh"), str(root)],
                         capture_output=True, text=True, check=True).stdout
    built = {}
    for line in out.splitlines():
        name, base, head = line.split()
        built[name] = (base, head)
    return root, built


def main():
    cases = [json.loads(l) for l in (HERE / "cases.jsonl").read_text().splitlines() if l.strip()]
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        root, built = build_synthetic(tmp)
        for case in cases:
            note = ""
            try:
                if case["repo"].startswith("synthetic:"):
                    err = check_synthetic(case, built, root)
                elif case["kind"] == "bug":
                    err = check_bug(case)
                elif case["kind"] == "clean":
                    res = check_clean(case)
                    err, note = (res, "") if isinstance(res, str) else (None, f" ({res[1]} later fixes checked)")
                else:
                    err = f"unknown kind/repo combination {case['kind']}"
            except (RuntimeError, KeyError, ValueError) as exc:
                err = f"error: {exc}"
            failed += err is not None
            print(f"{'FAIL' if err else 'ok  '} {case['kind']:<9} {case['id']}{note}{': ' + err if err else ''}")
    print(f"{len(cases) - failed}/{len(cases)} cases pass")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
