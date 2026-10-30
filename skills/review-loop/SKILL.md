---
name: review-loop
description: End-of-ticket review with the review-loop CLI — `eot` after the ticket's work is committed, then `recheck` after each fix. Use when finishing a ticket or feature branch, before opening a PR, or when asked to review a branch's changes. Also `scan` for a quick deterministic secret/Unicode/dependency check of staged changes or a range.
---

# review-loop

CLI: `$REVIEW_LOOP_BIN`, else `review-loop` on `PATH`, else `~/Dev/review-loop/bin/review-loop`. Python 3.9+.

## Finishing a ticket

1. Commit the ticket's work on its feature branch, with an honest `Co-Authored-By` trailer that names the **model**,
   not only the harness, e.g. `Co-Authored-By: GPT-6.1 Sol (Copilot) <noreply@github.com>` or
   `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. The reviewers are picked from the other model family
   than the one that wrote the code; a trailer like `Co-authored-by: Copilot` alone says nothing about the model, so
   both families review, the author's own included.
2. `review-loop eot --ticket <ticket.md> --format text` (or `--intent "<one line>"`; default base is
   `origin/HEAD`, pass `--base <ref>` for an epic branch). It scans first, then a finder and a verifier from the other
   model family review `merge-base..HEAD` in a read-only scratch worktree.
3. Act on the exit code:
   - `0` — done. It means no finding was reported, never "secure".
   - `1` — fix each `blocking`/`hard` finding test-first, run the tests, commit, then
     `review-loop recheck --ticket <ticket.md> --format text`. Recheck reads only what changed since the last round,
     checks again whether the earlier findings still hold, and doesn't repeat advisory ones. `advisory` findings are
     your call.
   - `2` — stop and show the user the findings. Recheck also returns 2 after its second round with findings still
     open. Don't start a fresh `eot` to get around it (it is refused on a branch that has rechecks).
   - `3` — stop and report the error. A failed review never counts as a pass.
4. Before pushing (after any rebase): `review-loop recheck` again. With an unchanged patch-id it only rescans.
5. Opening the PR: put `review-loop risk --format md` in the PR body (how much review it needs: low, medium or high,
   decided in code). Then `review-loop land <pr>`: it merges only a risk:low PR that is reviewed clean and green, and
   otherwise refuses with the reasons. On a refusal, stop and give the user the PR link: they merge. Never run
   `gh pr merge` yourself (the guard denies it), and never add a `risk:` label by hand.

Never edit, delete or write anything under `$(git rev-parse --git-common-dir)/review-loop/`.

## Scan only (no model)

```
review-loop scan --staged --format text
review-loop scan --range origin/main..HEAD
```

D1 secrets (gitleaks, history included), D2 hidden Unicode, D3 new or changed dependency versions. Same exit codes.
Scanners are pinned in `~/.config/review-loop/tools.lock`; if it is missing, say so — don't create or edit it.
