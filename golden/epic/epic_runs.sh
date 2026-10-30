#!/usr/bin/env bash
# Run `review-loop epic doc-sharing` on the buggy epic and its clean twin (in parallel), then score both.
# usage: epic_runs.sh <out-dir> [finder] [verifier] [tag]   (default finder copilot, verifier claude:sonnet)
# Builds the fixture into <out-dir>, writes golden/results/epic-review/<tag>-{buggy,clean}.json (gitignored).
# A run that exits 3 (worker error) is retried up to twice.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
bin="$here/../../bin/review-loop"
out="${1:?usage: epic_runs.sh <out-dir> [finder] [verifier] [tag]}"
finder="${2:-copilot}"
verifier="${3:-claude:sonnet}"
tag="${4:-run}"
res="$here/../results/epic-review"
mkdir -p "$res"

bash "$here/build.sh" "$out" >/dev/null 2>&1 || { echo "epic_runs.sh: build failed" >&2; exit 1; }
repo="$out/doc-sharing"
# the clean twin is epic/doc-sharing-clean, so its slug is doc-sharing-clean
one() {
  local name="$1" slug="$2" rc attempt
  for attempt in 1 2 3; do
    (cd "$repo" && "$bin" epic "$slug" --base main --prd "$here/PRD.md" --tickets "$here/tickets" \
      --finder "$finder" --verifier "$verifier") >"$res/$tag-$name.json" 2>"$res/$tag-$name.stderr"
    rc=$?
    [ "$rc" -ne 3 ] && break
  done
  printf '%s exit=%s attempts=%s\n' "$name" "$rc" "$attempt"
}
one buggy doc-sharing &
one clean doc-sharing-clean &
wait
python3 "$here/score.py" "$res/$tag-buggy.json" "$res/$tag-clean.json" | tee "$res/$tag-score.txt"
