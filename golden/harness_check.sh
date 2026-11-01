#!/usr/bin/env bash
# Run the same `review-loop eot` from each harness on the synthetic sqli case and compare the records.
# usage: harness_check.sh <out-dir> <harness>...   (claude codex copilot pi antigravity)
# Each harness gets its own `git clone --shared` of the case, so every record survives. Pass: one patch-id, the same
# workers (role, harness, model) and a record from every harness. Workers are pinned to claude:sonnet. Harness flags
# match redteam/live_check.sh; the prompt only runs the one eot command in a throwaway clone.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$1"; shift
mkdir -p "$out"
synth="$out/synthetic"
[ -d "$synth/sqli" ] || bash "$here/synthetic/build.sh" "$synth" >/dev/null
base="$(git -C "$synth/sqli" rev-parse HEAD^)"
cmd="$here/../bin/review-loop eot --base $base --intent 'Add user search' --finder claude:sonnet --verifier claude:sonnet --format json"
prompt="Run this shell command exactly once, from the current directory, and change nothing else: $cmd
Then reply with only the value of record_path from its JSON output."

for h in "$@"; do
  repo="$out/$h"
  rm -rf "$repo"
  git clone -q --shared "$synth/sqli" "$repo"
  case "$h" in
    claude)      (cd "$repo" && printf "%s" "$prompt" | claude -p --model haiku --allowedTools Bash) ;;
    copilot)     (cd "$repo" && copilot -p "$prompt" --allow-all-tools --add-dir "$here/..") ;;
    pi)          (cd "$repo" && pi -p "$prompt") ;;
    antigravity) (cd "$repo" && agy -p "$prompt" --dangerously-skip-permissions) ;;
    # outside Codex's sandbox, as an approved escalation would be: workspace-write makes .git read-only and has no
    # network, so eot can't write its record or reach a worker. The user's hooks (the guard) still load.
    codex)       (cd "$repo" && codex exec --dangerously-bypass-approvals-and-sandbox "$prompt") ;;
    *) echo "unknown harness $h" >&2; exit 3 ;;
  esac >"$out/$h.out" 2>&1 || true
done

python3 - "$out" "$@" <<'EOF'
import json, sys, glob
out, harnesses = sys.argv[1], sys.argv[2:]
rows = {}
for h in harnesses:
    recs = glob.glob(f"{out}/{h}/.git/review-loop/*/round-1/record.json")
    if not recs:
        print(f"{h:12} NO RECORD (see {out}/{h}.out)")
        continue
    r = json.load(open(recs[0]))
    rows[h] = (r["key"]["patch_id"], tuple(sorted({(w["role"], w["harness"], w["model"]) for w in r["workers"]})))
    print(f"{h:12} {r['key']['patch_id'][:12]}  {r['outcome']['summary']:12} {recs[0]}")
ok = len(rows) == len(harnesses) and len({v[0] for v in rows.values()}) == 1 and len({v[1] for v in rows.values()}) == 1
print("SAME patch-id and workers across all" if ok else "MISMATCH or missing record")
sys.exit(0 if ok else 1)
EOF
