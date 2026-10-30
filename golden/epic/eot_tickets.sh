#!/usr/bin/env bash
# Run `review-loop eot` on each ticket of the toy epic alone (buggy T1-T3, clean T2/T3; T1 is shared).
# usage: eot_tickets.sh <out-dir> [finder] [verifier]   (default claude:opus for both)
# Builds the fixture into <out-dir>, writes golden/results/epic-doc-sharing/<ticket>.json (gitignored).
# A run that exits 3 (worker error) is retried up to twice; if one still fails, the script exits 3 at the end.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
bin="$here/../../bin/review-loop"
out="${1:?usage: eot_tickets.sh <out-dir> [finder] [verifier]}"
finder="${2:-claude:opus}"
verifier="${3:-$finder}"
res="$here/../results/epic-doc-sharing"
mkdir -p "$res"

bash "$here/build.sh" "$out" >/dev/null 2>&1 || { echo "eot_tickets.sh: build failed" >&2; exit 1; }
repo="$out/doc-sharing"
errors=0

for spec in T1:ticket/DS-1-workspaces:T1 T2:ticket/DS-2-versions:T2 T3:ticket/DS-3-share-links:T3 \
            T2-clean:ticket/DS-2-versions-clean:T2 T3-clean:ticket/DS-3-share-links-clean:T3; do
  IFS=: read -r name ref ticket <<<"$spec"
  for attempt in 1 2 3; do
    (cd "$repo" && "$bin" eot --base main --rev "$ref" --ticket "$here/tickets/$ticket.md" \
      --finder "$finder" --verifier "$verifier") >"$res/$name.json" 2>"$res/$name.stderr"
    rc=$?
    [ "$rc" -ne 3 ] && break
  done
  printf '%s exit=%s attempts=%s\n' "$name" "$rc" "$attempt"
  [ "$rc" -eq 3 ] && errors=$((errors + 1))
done

# exit 1/2 are review outcomes (blocked / needs_human); exit 3 after every retry means no result for that ticket
if [ "$errors" -gt 0 ]; then
  echo "eot_tickets.sh: $errors ticket(s) still failed with exit 3 after retries" >&2
  exit 3
fi
