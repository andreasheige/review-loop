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
- `bin/review-loop worker …`: one finder or verifier run, for debugging prompts.
