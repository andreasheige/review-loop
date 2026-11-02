# review-loop

One CLI for the review and security loops. Start with `contract/README.md`.

What it is, why, and measured results: [the review-loop gist](https://gist.github.com/andreasheige/3af8ad9b0c12e6fbf34692ed5bf5bc8d).
The server-side half is [security-floor](https://github.com/andreasheige/security-floor).

## Setup

- **Python 3.9+** and **git**. No packages: the CLI is stdlib only (`contract/validate.py` needs `uv` for `jsonschema`).
- **Agent CLIs from at least two model families** for the reviewers: `claude`, `codex` and/or `copilot` on `PATH`.
  The finder and verifier come from the other family than the commit's `Co-Authored-By` trailer names.
- **Pinned scanners** in `~/.config/review-loop/tools.lock` (TSV: tool, version, absolute path, sha256; `#`
  comments allowed). Binaries are never taken from `PATH`; a missing or changed one fails closed for secrets and
  Unicode, and becomes needs_human for dependency lookups. `scan` needs `gitleaks` and `osv-scanner`; `sweep` also
  uses `zizmor` and `actionlint`. Write one line per tool, e.g.
  `printf 'gitleaks\t8.30.1\t%s\t%s\n' "$(realpath "$(command -v gitleaks)")" "$(shasum -a 256 "$(realpath "$(command -v gitleaks)")" | cut -d' ' -f1)"`.
- **Who owns which repo** (optional), in `~/.config/review-loop/`: `owner-origins.txt` (origin prefixes of your own
  repos, e.g. `github.com/<you>/`, whose dependency names may go to online lookups) and `client-roots.txt`
  (directories of client repos: sensitive, offline only). Without them, only repos with no remote count as yours.
- **Hooks:** call `bin/review-loop scan --staged` from pre-commit and `bin/review-loop gate "$@"` from pre-push
  (stdin passed through). Repos with their own `core.hooksPath` (husky, lefthook) need the call in their own hook.
- **Agents:** `skills/review-loop/SKILL.md` tells an agent when to run `eot` and `recheck`.

Tests: `python3 -m unittest discover -s tests`.

## What never goes in this repo

- No client repos in `golden/`: cases come from personal repos and synthetic seeded cases only.
- Red-team results (`redteam/results/`) stay out of git: they list which bypasses work.

## Commands

- `bin/review-loop scan (--staged | --range A..B)`: deterministic D1–D3 checks, no model.
- `bin/review-loop eot [--base REF] [--ticket PATH | --intent TEXT]`: end-of-ticket review of `merge-base(base, HEAD)..HEAD`. Scan first; a secret hit or scan error stops before any model sees the diff. Then a non-author finder and verifier (Claude-authored work goes to Copilot by default; `--finder`/`--verifier HARNESS[:MODEL]` to override) and a record under `$(git rev-parse --git-common-dir)/review-loop/<patch-id>/round-1/`. Docs and lockfiles are skipped by file class, never paths that look security-relevant.
- `bin/review-loop recheck` (same flags): after fixing, reviews what changed since the last completed round of this branch, verifies the open findings again (open until every verifier refutes), never repeats an advisory one. Two rechecks at most; then exit 2 for a human. Fixes that change existing test lines, or more than 200 lines in all since eot, go to a human (`control-weakening`, exit 2); adding tests is fine.
- `bin/review-loop epic <slug> [--base REF] [--prd PATH | --intent TEXT] [--tickets DIR]`: end-of-epic review of `merge-base(base, epic/<slug>)..epic/<slug>`, for defects between tickets (a contract one ticket sets and another breaks). Preflight, full-epic scan (a secret stops the models), the repo's journey/e2e script if it has one, tickets from first-parent history, seams from git (files two tickets change, symbols one ticket changes and another uses; `graphify affected` when the repo has a graph), chunks of at most 300 changed lines that cover `git diff --name-only` exactly, a finder per chunk (`prompts/epic-find.md`), a verifier of the other model family, a follow-up ticket per kept finding, and threat-model delta (sensitive repos), UI run + manual a11y checklist (UI changes) and image check (Dockerfile) where they apply, else `not_applicable`. Record under `<patch-id>/epic-<merge-base>/`, keyed by `(patch-id, merge-base)`. Measured on `golden/epic/` (`epic_runs.sh`, `score.py`).
- `bin/review-loop scan --policy` (used by eot/recheck, not by the pre-commit hook): adds NEEDS_HUMAN `control-weakening` hits for agent/CI/scanner/git-hook/`.review-loop.toml` changes, new suppression comments and removed test assertions; exempts young deps in lockfile-only bot commits; applies accepts.
- `bin/review-loop risk [--base REF] [--rev REV] [--format text|json|md]`: how much human review a change needs (`low` / `medium` / `high`), decided in code from the diff, the eot/recheck record for exactly that content, the UI result and the repo's sensitivity — never from a label. `--format md` is the PR-body section. Writes `risk.json` next to the record; `stats` counts the tiers. Always exit 0 (3 on a tool error).
- `bin/review-loop land <pr>`: the only way an agent merges. Recomputes `risk` on the PR head as origin has it (never a label), against a fresh base; lands with `gh pr merge --rebase --match-head-commit <head>` only when the tier is low, the review record is clean, the PR is open, mergeable and its checks are green. Anything else exits 1 with the reasons ("waiting for a human"). Every run is a line in `<state>/land.jsonl`.
- `bin/review-loop gate <remote> [<url>] [--block]` (the global pre-push hook's call, pre-push ref lines on stdin): `scan --policy` on each pushed ref's new commits, against the remote's old sha from the hook's stdin or the remote's default branch from `git ls-remote` (never a local tracking ref). Warn mode prints and allows; `block` in `~/.config/review-loop/gate-mode` (or `--block`) refuses on any block, needs_human or tool error. One line per run in `<state>/gate.jsonl`. In repos with `git config review-loop.gate true` it also needs an eot/recheck record for each pushed change (same patch-id) whose newest round has nothing open; `REVIEW_LOOP_SKIP=1` skips only that check and is logged to `skips.log`.
- `bin/review-loop sweep [--if-due]` and `sweep --digest [ROOT]...`: whole-repo checks no diff scan sees, report only: osv-scanner (client repos offline only), gitleaks on commits since the last sweep, zizmor + actionlint on workflows, hooks not in `~/.config/review-loop/hooks-allow.txt` and a local `core.hooksPath`, and weekly the global `core.hooksPath`. `--if-due`: only when the last sweep is over 7 days old, nothing else is sweeping the repo and usage-guard isn't over a limit. Result in `<git-common-dir>/review-loop/sweep.json`; the digest lists every repo's last sweep.
- `bin/review-loop ui [--base REF]`: the UI lens, only when UI files change. Static Storybook of base and head (scratch worktrees), the repo's own Playwright + axe-core on the stories near the changes at mobile/desktop × light/dark, network limited to localhost: new serious/critical axe violations and keyboard traps are hard, changed screenshots needs_human, anything already on base goes to backlog. Result in `<git-common-dir>/review-loop/<patch-id>/ui.json`. Tests need `REVIEW_LOOP_UI_NODE_MODULES`.
- `bin/review-loop accept <finding-id> --reason … [--expires YYYY-MM-DD] [--rule-class …]`: a human's override, typed at a terminal; per (finding id, rule class), security classes expire within 90 days.
- `bin/review-loop label <finding-id> fixed|wrong|intentional|noise` (human labels need a `y` at the terminal; an agent may give `fixed`/`noise` with `--evidence`, counted apart) and `bin/review-loop stats [--repo PATH]... [--csv PATH]` (counts only; `--csv` appends `date,metric,key,value` rows).
- `bin/review-loop worker …`: one finder or verifier run, for debugging prompts.

## License

MIT, see [LICENSE](LICENSE).
