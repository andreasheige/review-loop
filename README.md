# review-loop

One CLI for the review and security loops. Start with `contract/README.md`.

Plan: `~/.autograph/vault/deep_dives/2026-10-26-review-security-plan.md`.

## What never goes in this repo

Private and local for now, but written to be publishable.

- No client repos in `golden/`: cases come from personal repos and synthetic seeded cases only.
- Red-team results (`redteam/results/`) stay out of git: they list which bypasses work.

## Commands

- `bin/review-loop scan (--staged | --range A..B)`: deterministic D1–D3 checks, no model.
- `bin/review-loop eot [--base REF] [--ticket PATH | --intent TEXT]`: end-of-ticket review of `merge-base(base, HEAD)..HEAD`. Scan first; a secret hit or scan error stops before any model sees the diff. Then a non-author finder and verifier (Claude-authored work goes to Copilot until the Codex quota is back; `--finder`/`--verifier HARNESS[:MODEL]` to override) and a record under `$(git rev-parse --git-common-dir)/review-loop/<patch-id>/round-1/`. Docs and lockfiles are skipped by file class, never paths that look security-relevant.
- `bin/review-loop recheck` (same flags): after fixing, reviews what changed since the last completed round of this branch, verifies the open findings again (open until every verifier refutes), never repeats an advisory one. Two rechecks at most; then exit 2 for a human. Fixes that change existing test lines, or more than 200 lines in all since eot, go to a human (`control-weakening`, exit 2); adding tests is fine.
- `bin/review-loop scan --policy` (used by eot/recheck, not by the pre-commit hook): adds NEEDS_HUMAN `control-weakening` hits for agent/CI/scanner/git-hook/`.review-loop.toml` changes, new suppression comments and removed test assertions; exempts young deps in lockfile-only bot commits; applies accepts.
- `bin/review-loop gate <remote> [<url>] [--block]` (the global pre-push hook's call, pre-push ref lines on stdin): `scan --policy` on each pushed ref's new commits, against the remote's old sha from the hook's stdin or the remote's default branch from `git ls-remote` (never a local tracking ref). Warn mode prints and allows; `block` in `~/.config/review-loop/gate-mode` (or `--block`) refuses on any block, needs_human or tool error. One line per run in `<state>/gate.jsonl`. In repos with `git config review-loop.gate true` it also needs an eot/recheck record for each pushed change (same patch-id) whose newest round has nothing open; `REVIEW_LOOP_SKIP=1` skips only that check and is logged to `skips.log`.
- `bin/review-loop sweep [--if-due]` and `sweep --digest [ROOT]...`: whole-repo checks no diff scan sees, report only: osv-scanner (client repos offline only), gitleaks on commits since the last sweep, zizmor + actionlint on workflows, hooks not in `~/.config/review-loop/hooks-allow.txt` and a local `core.hooksPath`, and weekly the global `core.hooksPath`. `--if-due`: only when the last sweep is over 7 days old, nothing else is sweeping the repo and usage-guard isn't over a limit. Result in `<git-common-dir>/review-loop/sweep.json`; the digest lists every repo's last sweep.
- `bin/review-loop ui [--base REF]`: the UI lens, only when UI files change. Static Storybook of base and head (scratch worktrees), the repo's own Playwright + axe-core on the stories near the changes at mobile/desktop × light/dark, network limited to localhost: new serious/critical axe violations and keyboard traps are hard, changed screenshots needs_human, anything already on base goes to backlog. Result in `<git-common-dir>/review-loop/<patch-id>/ui.json`. Tests need `REVIEW_LOOP_UI_NODE_MODULES`.
- `bin/review-loop accept <finding-id> --reason … [--expires YYYY-MM-DD] [--rule-class …]`: a human's override, typed at a terminal; per (finding id, rule class), security classes expire within 90 days.
- `bin/review-loop label <finding-id> fixed|wrong|intentional|noise` (human labels need a `y` at the terminal; an agent may give `fixed`/`noise` with `--evidence`, counted apart) and `bin/review-loop stats [--repo PATH]... [--csv PATH]` (counts only; `--csv` appends `date,metric,key,value` rows like the agent-safety metrics.csv).
- `bin/review-loop worker …`: one finder or verifier run, for debugging prompts.
