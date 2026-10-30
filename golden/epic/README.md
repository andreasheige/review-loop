# Golden toy epic: `doc-sharing`

A synthetic epic for measuring a cross-ticket (epic) reviewer. It has a PRD, three tickets and four
seeded bugs that only exist where tickets meet: each ticket diff is correct on its own, so
`review-loop eot` on any one ticket cannot see them. A clean twin has the same tickets with the four
bugs fixed. Synthetic content only, no secrets.

| File | What it is |
|---|---|
| `build.sh <out-dir>` | builds the repo at `<out-dir>/doc-sharing` and prints `<ref> <sha>` per ref |
| `PRD.md`, `tickets/T1.md`…`T3.md` | the epic's PRD and the three tickets (intent + definition of done) |
| `expected.json` | refs and SHAs, the four bugs (sites at the epic head, lens, rule class, tickets involved), the clean twin's `expect: []` |
| `verify.py` | rebuilds, checks SHAs match, every site lies in the epic diff, the clean twin differs at every bug |
| `eot_tickets.sh <out-dir>` | runs `review-loop eot` on each ticket alone (the 13.1 check) |

## The app and the epic

`docs-service` is a small Express 5 + Prisma API: users create, read, edit and delete their own
documents. The epic adds workspaces (T1), version history (T2) and public share links (T3).

```
main ── T1 (ticket/DS-1-workspaces)  ─┐
   ├─── T2 (ticket/DS-2-versions)     ─┼─ merged --no-ff into epic/doc-sharing, in order T1, T2, T3
   └─── T3 (ticket/DS-3-share-links)  ─┘
```

The tickets were developed in parallel, each branched from `main`, so ticket `Tn`'s diff is
`main..ticket/...`. Every merge is textually clean. That is what makes the bugs cross-ticket: each
one is a contract that one ticket relies on and another ticket changes, and the two never meet
before the epic branch.

The four bugs are listed in `expected.json` (one IDOR, one data exposure, one revocation bypass, one
weak token), each touching two tickets. All are `lens: security` with `rule_class: null`, since
model findings carry no deterministic class (see `../../contract/README.md`). Line numbers refer to
the epic head.

The clean twin (`epic/doc-sharing-clean`) merges T1, `ticket/DS-2-versions-clean` and
`ticket/DS-3-share-links-clean`. Three fixes sit in the tickets. The IDOR fix sits in the T2 merge
commit, because only the integrator sees both T1's access loader and T2's routes.

## Build and verify

```sh
golden/epic/build.sh /tmp/golden-epic      # fresh directory
golden/epic/verify.py                      # stdlib only; exit 0 = all checks pass
```

## EOT alone misses them (item 13.1)

```sh
golden/epic/eot_tickets.sh /tmp/golden-epic-eot [finder] [verifier]   # default claude:opus
```

This runs `eot` on each ticket on its own (`--base main --rev <ticket ref> --ticket tickets/Tn.md`):
the buggy T1–T3, plus the clean T2 and T3 (T1 is the same in both). A bug counts as caught only if a
finding overlaps one of its sites and describes that bug. Outputs go to
`golden/results/epic-doc-sharing/` (gitignored).

Result on 2026-10-30 on the final fixture, `claude:opus` finder and verifier, each ticket run at least
twice: no finding describes any of the four bugs.

| ticket | findings (last run) | seeded bugs caught |
|---|---|---|
| T1 | 1 blocking (creating a workspace document races with member removal) | 0/4 |
| T2 | 1 blocking (version order depends on host clocks), 1 advisory (WORKER_ID required at startup) | 0/4 |
| T3 | none | 0/4 |
| T2 clean | the same two as T2 | n/a |
| T3 clean | none | n/a |

Some findings land on a bug's site but describe something else. T2's clock-order finding sits in
`src/lib/ids.ts`, and one T1 run flagged the `sharedWith` roster being shown to a removed member.
Neither describes the seeded bug there, so neither counts.

Earlier runs found real single-ticket defects in a previous version of the fixture: races on save
and share, an owner who could demote themselves, a removed member who kept seeing the roster, and a
`WORKER_ID` silently defaulting. Those were fixed in both twins so that a 13.2 run on the clean twin
is not dominated by them. They also caught none of the four bugs. What is left (the two races and
nits above) is the same in both twins.

## Scoring the epic reviewer (item 13.2)

Run `review-loop epic doc-sharing` on `epic/doc-sharing` (base `main`) and on `epic/doc-sharing-clean`.

- Recall: a bug is found if a non-discarded finding has a site overlapping any of the bug's sites
  (same path, line ranges overlap within the `TOLERANCE` that `eot_eval.py` uses) and describes that
  bug. Target: at least 3 of the 4.
- False positives: on the clean twin, every `blocking`/`proven`/`hard` finding is a false
  positive. Target: at most 1.
