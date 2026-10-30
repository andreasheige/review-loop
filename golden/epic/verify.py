#!/usr/bin/env python3
"""Check the golden toy epic against expected.json.

Rebuilds the fixture with build.sh into a temp dir and checks:
- every ref's SHA matches expected.json (the build is reproducible),
- every bug site lies inside the epic diff main..epic (new side),
- the clean twin's epic differs from the buggy epic in a file of every bug's sites.

Prints one line per check; exits 0 only if all pass. Stdlib only.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from verify_cases import git, hunks  # noqa: E402 - needs the sys.path entry above


def main():
    exp = json.loads((HERE / "expected.json").read_text())
    refs = exp["refs"]
    clean = exp["clean_twin"]
    want = {refs["base"]["ref"]: refs["base"]["sha"], refs["epic"]["ref"]: refs["epic"]["sha"],
            clean["epic"]["ref"]: clean["epic"]["sha"]}
    for t in refs["tickets"] + clean["tickets"]:
        want[t["ref"]] = t["sha"]
    failed = 0

    def report(ok, what):
        nonlocal failed
        failed += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {what}")

    with tempfile.TemporaryDirectory() as tmp:
        out = subprocess.run(["bash", str(HERE / "build.sh"), tmp], capture_output=True, text=True, check=True).stdout
        built = dict(line.split() for line in out.splitlines())
        repo = str(Path(tmp) / exp["slug"])
        for ref, sha in want.items():
            report(built.get(ref) == sha, f"sha {ref} {sha[:10]}" + ("" if built.get(ref) == sha else f" (built {built.get(ref)})"))
        diff = hunks(repo, refs["base"]["sha"], refs["epic"]["sha"])
        changed = set(git(repo, "diff", "--name-only", refs["epic"]["sha"], clean["epic"]["sha"]).split())
        for bug in exp["bugs"]:
            for s in bug["sites"]:
                ranges = diff.get(("new", s["path"]), [])
                inside = all(any(a <= n <= b for a, b in ranges) for n in range(s["start_line"], s["end_line"] + 1))
                report(inside, f"{bug['id']}: {s['path']}:{s['start_line']}-{s['end_line']} inside epic diff")
            report(any(s["path"] in changed for s in bug["sites"]), f"{bug['id']}: clean twin differs at a site file")
            report(len(bug["tickets"]) >= 2, f"{bug['id']}: spans tickets {'+'.join(bug['tickets'])}")
    print("all checks pass" if not failed else f"{failed} check(s) failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
