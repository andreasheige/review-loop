# review-loop contract

The shared contract between the review loop and the security loop: one CLI, one record, one status set, one gate. Written before any code. Design: `~/.autograph/vault/deep_dives/2026-10-26-review-security-integration.md` ("Shared contract").

| File | What it is |
|---|---|
| `finding.schema.json` | one finding as stored in a record (tool hit or model finding) |
| `record.schema.json` | one record per patch-id and round |
| `accept.schema.json` | one line of `accepts.jsonl` |
| `examples/` | hand-written examples; `validate.py` checks them |

Check: `uv run --offline --script contract/validate.py` (exit 0 = all examples behave as expected).

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

## Record layout

```
$(git rev-parse --git-common-dir)/review-loop/      never committed
  <patch-id>/round-<n>/record.json                   record.schema.json
  <patch-id>/round-<n>/{sarif,prompts,repro}/        raw artifacts, scrubbed of secrets
  accepts.jsonl                                      accept.schema.json, one per line
  skips.log                                          REVIEW_LOOP_SKIP uses
```

Keys: EOT records use the `-U0` patch-id against `origin/<base>` (`merge_base: null`). EOE records use `(patch_id, merge_base)`, so any move of main forces a re-run.

## Config split

| Where | Who writes | Holds |
|---|---|---|
| `~/.config/review-loop/config.toml` | Andreas only | security policy, roles → `{harness, model}`, per-remote vendor allow-list, rule classes and their block/warn mode |
| `~/.config/review-loop/tools.lock` | Andreas only | scanner absolute paths, versions, sha256 |
| `<repo>/.review-loop.toml` | repo | test/lint commands, protected test globs, base branch, `gate`/`ui` opt-ins, `vendors` restriction |

`.review-loop.toml` can only add strictness. Any change to it is itself NEEDS_HUMAN (`control-weakening`). So a repo can narrow `vendors` but never widen them. Allowing a new vendor for a client repo (e.g. OpenAI as the non-author family) is a global-config entry keyed by remote URL (Decision 8 in the plan).

## Decisions this contract assumes

From the plan's Phase 0 decisions (2026-10-26):

- Client repos: dependency lookups use the offline OSV DB only. Model workers are limited to vendors already used on that client.
- Young dependencies (`dep-young`, < 7 days) are `needs_human`, not `hard`.
- KEV-with-fix (`dep-kev`) is `hard`.
