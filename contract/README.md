# review-loop contract

The shared contract between the review loop and the security loop: one CLI, one record, one status set, one gate. Written before any code. Design: `~/.autograph/vault/deep_dives/2026-10-26-review-security-integration.md` ("Shared contract").

| File | What it is |
|---|---|
| `finding.schema.json` | one finding as stored in a record (tool hit or model finding) |
| `record.schema.json` | one record per patch-id and round |
| `accept.schema.json` | one line of `accepts.jsonl` |
| `finder-output.schema.json` | what a finder worker returns: findings without `id`/`status`/`rule_class`/`introduced_by`/`verification`, plus `reviewed_paths`; all keys required, optional ones nullable (Codex strict output) |
| `verifier-output.schema.json` | what a verifier worker returns for one finding: `{id, reasoning, counter_evidence, verdict}` |
| `examples/` | hand-written examples; `validate.py` checks them |

Check: `uv run --offline --script contract/validate.py` (exit 0 = all examples behave as expected; worker-output examples are also checked against the stdlib validator in `review_loop/workers.py`).

## Status

One finding, one status, computed in code:

```
hard > needs_human > proven > blocking > advisory > discarded
```

- `hard`: tool hit (`evidence.kind=tool`), `introduced_by=diff`, rule class D1–D6 (`secret`, `unicode`, `dep-nonexistent`, `dep-mal`, `dep-kev`, `sast`, `workflow`).
- `needs_human`: a NEEDS_HUMAN class (`control-weakening`, `dep-young`, generic-entropy `secret`, …).
- `proven`: `blocking` and the repro (`evidence.kind=repro`) fails on HEAD.
- `blocking`: `lens ∈ {correctness, security}` ∧ non-author verifier `confirmed` ∧ `failure_scenario`.
- `advisory`: everything else, including all `pre-existing` hits.
- `discarded`: verifier `refuted` or `unsure`.

Invariants: tool hits never go to the model verifier, so they have no `verification`. No model verdict removes `hard` or `needs_human`. `REVIEW_LOOP_SKIP` skips review findings only, never `scan`.

`evidence.kind` is `tool | repro | trace | none`. The integration doc's `proven` is a status, not an evidence kind; its evidence is `repro`.

## Finding ids

Stable across `--staged`, `--range` and rebase: no line number or commit SHA.

- Tool hit: `sec-<tool>-<sha1(ruleId|path|K)[:12]>`. K = `HMAC(local key, normalised match)` for secrets (the match is never stored), `sha1(normalised snippet)` for SAST.
- Model finding: `rev-<sha1(lens|path|title)[:12]>`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | pass (`no_findings_reported (unverified)` or `advisory_only`, never "secure") |
| 1 | block |
| 2 | needs_human |
| 3 | tool error: treated as block for D1/D2 (local), as needs_human for D3/D4 (network lookups); malformed worker output is 3, never 0 |

## Accepts

`review-loop accept <finding-id> --reason … [--expires YYYY-MM-DD]`, TTY only. Format `(finding_id, rule_class, reason, expires)` plus `accepted_at` and `tty: true`.

- Keyed per `(finding_id, rule_class)`, never per patch-id. Re-evaluated live by `gate`.
- Every security class needs `expires`. Only `rule_class=review` may have `expires: null`.
- A `review` accept never clears a `hard` or `needs_human` finding.
- Applied only in policy mode (`scan --policy`, eot, recheck, later gate), never by the pre-commit `scan --staged`, so a line written to `accepts.jsonl` cannot weaken the commit-time D1–D3 check. `tty: true` is written by the CLI after the terminal prompt; like the records, the file itself is agent-editable (see Rounds, Known limits). The terminal check is a speed bump, not a boundary: an agent can fake a terminal (`script`, `expect`, `pty`); a guardrail rule against running `review-loop accept|label` under those is a possible later step. The young-dependency exemption for bot commits trusts the author email, which whoever commits sets, so it only ever downgrades `dep-young`.

## Record layout

```
$(git rev-parse --git-common-dir)/review-loop/      never committed
  <patch-id>/round-<n>/record.json                   record.schema.json
  <patch-id>/round-<n>/{sarif,prompts,repro}/        raw artifacts, scrubbed of secrets
  <patch-id>/ui.json                                 `review-loop ui` result: {head, base, findings, outcome[, static]}
  accepts.jsonl                                      accept.schema.json, one per line
  sweep.json                                         last `review-loop sweep`: {ts, head, checks, ms} (report only)

<state dir> = $REVIEW_LOOP_STATE_DIR or ~/.config/review-loop/state   (a protected path for agents)
  gate.jsonl                                         one line per push: mode, exit, rule classes, ms, review states
  skips.log                                          REVIEW_LOOP_SKIP uses (each confirmed at a terminal)
  ui-optin.json                                      per remote: yes / not_now (7 days) / never, TTY only
  machine-sweep.json                                 the weekly machine-wide sweep check
~/.config/review-loop/gate-mode                      `block` turns the push gate from warn to block
~/.config/review-loop/hooks-allow.txt                `<sha256> <name> <why>`: repo hooks a human has looked at
```

The push gate counts a review record or UI result only for the exact pushed content: same patch-id, and the
record's head has the pushed tree (a UI result also the same merge-base, and never a `--static` one). A patch-id
alone ignores whitespace and context, so two different changes can share one.

Rounds: `eot` is round 1, `recheck` rounds 2–3. The rounds of one ticket are chained by branch (a renamed branch keeps its chain; a name reused after a merge starts afresh). Known limits: the records are local files the agent under review can edit or delete, so the cap and the open findings hold against mistakes, not against a hostile agent (signing records with the local HMAC key is a possible later step); a copied branch (`git switch -c` from a ticket branch) starts a new chain; two branches with the same patch-id share `<patch-id>/round-<n>/`.

Keys: EOT records use the `-U0` patch-id against `origin/<base>` (`merge_base: null`). EOE records use `(patch_id, merge_base)`, so any move of main forces a re-run.

## Config split

| Where | Who writes | Holds |
|---|---|---|
| `~/.config/review-loop/config.toml` | the human owner only | security policy, roles → `{harness, model}`, per-remote vendor allow-list, rule classes and their block/warn mode |
| `~/.config/review-loop/tools.lock` | the human owner only | scanner absolute paths, versions, sha256 |
| `~/.config/review-loop/owner-origins.txt` | the human owner only | origin prefixes that count as yours (e.g. `github.com/<you>/`); other origins never get online dependency lookups. Missing: only repos without a remote |
| `~/.config/review-loop/client-roots.txt` | the human owner only | directories holding client repos: treated as sensitive and swept by default. Missing: none |
| `<repo>/.review-loop.toml` | repo | test/lint commands, protected test globs, base branch, `vendors` restriction (planned: no TOML reader on Python 3.9 yet) |
| `<repo>/.git/config` `review-loop.*` | the human owner | opt-ins, read with `--local` only: `gate` (review records at push), `ui-required` (UI result at push), `design-tokens` (lint), `sensitive` (personal-data line; repos under a client root are sensitive anyway) |

`.review-loop.toml` can only add strictness. Any change to it is itself NEEDS_HUMAN (`control-weakening`). So a repo can narrow `vendors` but never widen them. Allowing a new vendor for a client repo (e.g. OpenAI as the non-author family) is a global-config entry keyed by remote URL.

## Decisions this contract assumes

From the plan's Phase 0 decisions (2026-10-26):

- Client repos: dependency lookups use the offline OSV DB only. Model workers are limited to vendors already used on that client.
- Young dependencies (`dep-young`, < 7 days) are `needs_human`, not `hard`.
- KEV-with-fix (`dep-kev`) is `hard`.
