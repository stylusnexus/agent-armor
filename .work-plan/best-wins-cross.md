---
track: best-wins-cross
status: active
launch_priority: P0
milestone_alignment: v1.0.0
github:
  repo: stylusnexus/agent-armor
  issues: []
  references:
    - 308
    - 359
    - 306
    - 303
    - 178
    - 68
    - 358
    - 305
    - 274
    - 337
    - 307
    - 360
    - 107
    - 106
    - 304
    - 275
    - 332
    - 37
    - 40
    - 25
    - 32
    - 38
    - 245
    - 232
    - 31
    - 35
  branches: []
depends_on:
  - scan-performance
  - runtime-hardening
  - fiction-false-positives
  - detection-hardening
  - transport-integrity
  - ml-v2-retrain
  - enterprise-readiness
  - systemic-traps
  - human-in-the-loop
last_touched: 2026-10-20T03:00
last_handoff: 2026-10-20T03:00
next_up:
  - 308
  - 359
  - 306
blockers: []
---

# Best Wins (convergence track)

**This track owns nothing.** `github.issues` is deliberately empty and every issue below sits in
`github.references` — the toolkit's cross-track construct for surfacing scope without claiming
ownership. Status, session logs, and issue-table upkeep stay in each issue's home track; this
file answers one question the topic tracks can't answer individually: _what should we pick
up next?_

Rules of the road:

- **Never `slot` an issue here.** Use `batch-slot <issues> best-wins-cross --reference` so the
  home track keeps ownership. `demote-to-reference` is the repair if one lands here by mistake.
- **Re-rank, don't append.** When something ships or a new issue is filed, redo the ordering
  rather than tacking the new item onto the end.
- **Don't run `canonicalize` on this file** — it would prepend an auto-managed issue table and
  overwrite the hand-written ranking below.
- Re-ranked 2026-10-20 against the live repo (36 open issues, after filing #358–#360) and live
  source. Every open issue now has a home track. After the housekeeping below (2026-10-20 03:00),
  33 issues are open.

## Context

As of 2026-10-20: **7 stars, 0 forks**, and npm downloads for 2026-09-19 to 2026-10-18 of
**3,981** for the core package and **929** for the ML package, up from 614 and 73 at the
2026-08-05 ranking. There is now a named downstream consumer, CritForge, on `^0.2.23`. Its
evaluation produced the fiction false-positive cluster (#303–#307).

That changes the weighting. In August the ranking optimised for legible credibility before
launch. Now **don't break real consumers** comes first: false positives on honest text, scan
latency on request paths, and runtime footguns outrank new detectors.

The repo now has a `dev` branch (reversing the 2026-08-05 decision): branch from `dev`,
squash-merge to `dev`, and promote `dev` → `main` with a merge commit. After each release,
merge `main` back into `dev`.

## Housekeeping (done 2026-10-20)

| Issue    | Outcome                                                                                                                                           |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| #309     | Closed as a duplicate of #302.                                                                                                                    |
| #98, #99 | Closed as completed at `strict` (#329). `balanced` regex flagged honest text, so the remaining coverage is ML work, now a data item on #25.       |
| #35      | Rescoped to the retrain step only and moved to `ml-v2-retrain`. Depends on #25.                                                                   |
| #38      | Unblocked. The "do not start" line is replaced, and all three dependencies (audit records, multi-turn scanning, eval gate) are ticked as shipped. |

## Ranking

| Rank  | Issue                                  | Home track                        | Depends on                         | Why now                                                                                                   | Effort   |
| ----- | -------------------------------------- | --------------------------------- | ---------------------------------- | --------------------------------------------------------------------------------------------------------- | -------- |
| 1     | #308 scan latency and time bounds      | scan-performance                  | —                                  | `scanSync` blocks the event loop; latency grows faster than input size; CI timing tests fail now and then | Med      |
| 2     | #359 checksum shape before download    | runtime-hardening                 | —                                  | A bad `modelChecksums` costs a ~165MB download on every start. Small, contained fix                       | Low      |
| 3     | #306 fiction eval set                  | fiction-false-positives           | —                                  | Lets the gate catch fiction false positives. Unblocks #303, #305 and #307                                 | Low–Med  |
| 4     | #303 `ex-read-env` flags fiction       | fiction-false-positives           | #306                               | Critical false positive at `permissive` for a real consumer                                               | Low      |
| 5     | #178 instruction window (remainder)    | detection-hardening               | —                                  | Mostly shipped. Finish before #305, which changes the same check                                          | Med      |
| 6     | #68 action-gate rule hygiene           | detection-hardening               | —                                  | The bare-rule footgun gets worse with every new rule type (#106)                                          | Low–Med  |
| 7     | #358 CLI fails closed on missing paths | runtime-hardening                 | —                                  | Scan gates currently pass on a mistyped path. Minor bump; batch with #307                                 | Low      |
| 8     | #305 messages addressed to the AI      | fiction-false-positives           | #306, #303, #178                   | Real detection gap ("Note to the AI…", persona resets), once the fiction guardrails exist                 | Med      |
| 9     | #274 ML reads only 512 tokens          | runtime-hardening                 | long-document eval set             | The ML layer misses instructions late in a document. Needs a long-document set to measure fixes           | Med–High |
| 10    | #337 rescan each decoded reading       | scan-performance                  | encoded-payload timing work (#357) | Same detector as the in-flight timing work; sequence after it                                             | Low–Med  |
| 11    | #307 suppress or re-weight patterns    | fiction-false-positives           | #303                               | Adds a pattern id to `Threat` (API change → `0.3.0`)                                                      | Med      |
| 12    | #360 document `AGENTARMOR_MODEL_DIR`   | runtime-hardening                 | —                                  | Documents the existing env var and the custom-model checksum rule. Ships with #359                        | Low      |
| 13    | #107 dependency-install content risk   | detection-hardening               | —                                  | Zero coverage of install commands; this repo was targeted (`pip install vulnledger` on #73)               | Med      |
| 14    | #106 package-install policy            | detection-hardening               | #68                                | Release-age floor for installs an agent runs                                                              | Med      |
| 15    | #304 markdown image leaks (output)     | detection-hardening               | #308                               | Zero-click leak path; needs a caller allow list and new time-bound tests                                  | Med      |
| 16    | #275 NotInject over-defense            | ml-v2-retrain                     | —                                  | Run 6 at 89% vs a 90% goal: decide ship or retrain                                                        | Decision |
| 17    | #332 tool-call shapes                  | transport-integrity               | #308                               | Each shape needs honest-text probes and time-bound tests                                                  | Med      |
| 18    | #37 attention dilution                 | detection-hardening               | long-document eval set             | Shares the long-document set with #274                                                                    | Med      |
| 19    | #38 SOC 2 / ISO crosswalk              | enterprise-readiness              | —                                  | Unblocked 2026-10-20. Writing work against the shipped audit schema; ahead of the High-effort ML items    | Med      |
| 20    | #40 eval-gated feed ingestion          | ml-v2-retrain                     | —                                  | Mechanism behind future pattern feeds and #25's data                                                      | High     |
| 21    | #25 ML v2 retrain data                 | ml-v2-retrain                     | #40 (data)                         | The big lift (~5,400 labelled samples). Now also carries the C2/persistence variants from #98/#99         | High     |
| 22    | #32, #35 retrain-riding samples        | ml-v2-retrain                     | #25                                | #32: transport-integrity samples. #35: cross-turn accumulation (the `mt-mem`/`mt-ctx` blind spots)        | Med      |
| 23    | #245 multilingual language packs       | detection-hardening               | #25                                | Design first; ML coverage needs the retrain                                                               | High     |
| 24    | #232 community break-the-scan          | detection-hardening               | —                                  | Ongoing; no dependency                                                                                    | —        |
| 25    | #31 provider response signing          | transport-integrity               | providers                          | Needs provider cooperation that doesn't exist yet                                                         | High     |
| 26–32 | #7–#13 systemic and human-in-the-loop  | systemic-traps, human-in-the-loop | real incidents                     | Deferred. Build only with real incident signal from users                                                 | High     |

## Dependency graph

```
#306 ─► #303 ─► #305 ◄─ #178
  └───► #307 ─┐
#358 ─────────┴─► 0.3.0 (minor bump: CLI default + Threat API)

#308 ─► #304, #332            (new time-bound tests after the latency work)
#357 (encoded-payload timing) ─► #337

#359 + #360 ─► ML patch release
#68 ─► #106        #107 (parallel to #106)
long-document eval set ─► #274, #37

#40 ─► #25 ─► #32, #35 (retrain step), #245
#38 (unblocked; no dependencies)
```

## Release batching

- **Next core patch (0.2.27):** #356 (already on `dev`, needs its after-the-fact review), #303, and
  #308 if its fix is ready. Patch releases may change detection results per the versioning policy.
- **Next ML patch (0.1.11):** #359 and #360.
- **0.3.0 (minor):** #358 (CLI default changes) and #307 (pattern id on `Threat`). Batch them so
  consumers see one behaviour-changing release, not two.
- Everything else ships as patches in whatever release it's ready for.

## Corrections to the backlog

Checked against the live repo on 2026-10-20. The 2026-08-05 corrections are all resolved
(#26 closed with #28; launch-infra shipped; #69 closed). Items 1–3 below were resolved the same day
(see Housekeeping).

1. ✅ **#309 duplicates #302.** #310 shipped the README `## Versioning` section and closed #302.
2. ✅ **#98 and #99 are partly shipped.** #329 (0.2.25) added strict-only C2 and persistence
   patterns. The issues are still open, and nothing says whether `balanced` coverage is wanted.
3. ✅ **#35 is still open** although detection-hardening marks it shipped. That keeps #38 blocked
   on paper.
4. **Transport integrity is done except #31.** #27, #29 and #30 are closed, so #32 waits only on
   #25.
5. **Two #345 review findings are deliberate, not bugs.** Re-hashing the model at every start and
   requiring checksums for custom model directories both follow AGENTS.md. They're recorded in
   runtime-hardening, and the docs gap is #360.

## Session log

### Session — 2026-08-05 22:07

- Track created as a convergence track after reading all seven `.work-plan/` tracks, all 22 open
  GitHub issues, and the relevant source, then ranking the backlog by value-per-unit-effort.
- Ranking weighted toward demoable credibility because the repo is public-but-unlaunched
  (4 stars, 614 downloads/month) and the stated near-term goal is credibility, not revenue.
- Five backlog corrections found by checking live code rather than issue text. The #26 finding
  moves the ranking most: it promotes #28 from "blocked behind a taxonomy change" to "rank 1,
  low effort".
- Nothing implemented — analysis and ordering only.

### Session — 2026-08-05 22:55 (rank 1 shipped, re-ranked)

- #28 merged (PR #94, `0505bc7`), closing #26 with it. Ranking re-derived rather than appended to,
  per this track's own rule: **#71 is now rank 1**, then #69 item 1, then #68 items 1+3.
- Correction 1 is now confirmed rather than predicted — the #26 finding held up under implementation.
- Reusable output from #28 that changes later estimates: `BaseDetector.redactEvidence()` +
  `PatternDetector.maskEvidence` exist now, so #27 and #30 get secret-safe evidence for free; and
  `scripts/eval/samples.ts` has a `fake()` helper for building secret-shaped fixtures that don't
  trip push protection.
- Release PR #93 (0.2.14) carries #28 and is deliberately left unmerged — npm publish is the real
  deploy gate, and more work is batching into it first. Site already deployed and verified live.
- Decided against adding a `dev` branch (CritForge-style): CritForge's `dev` maps to a real Render
  staging deployment, agent-armor has no second environment, and release PR #93 already is the
  staging gate. Retargeting release-please — which only started working end-to-end at 0.2.13 after
  three separate bug fixes (#81, #85, #88) — is asymmetric downside for a queue that isn't needed.
  Revisit if external contributors arrive post-launch or a hosted Pro API appears.

### Session — 2026-08-06 (three shipped; re-ranked around a demonstrated bypass)

Shipped since the last ranking: **#28** (credential exposure, closing #26), **#71** (model integrity),
**#69 item 1** (steganographic-payload), plus #101/#103 ML test coverage and fixes. Released as
v0.2.15 (core). Ranks 1-3 of the previous ordering are done.

**Re-ranked, not appended** — the new top is:

1. **#68 items 1+3** — action-gate bare-rule footgun. Now more urgent than before: **#106 proposes
   an `npm.install` rule shape, and a bare `{ tool: 'npm.install' }` rule would admit any package at
   any version.** The footgun gets worse with every new rule type, so fix it before adding one.
2. **#98** — C2 / drop-service endpoints. Zero pattern coverage today; `rw-011` is a standing miss.
3. **#107** — dependency-install risk. Zero coverage of install commands, lockfiles, `ignore-scripts`,
   `postinstall` in ANY ecosystem. This repo has already been targeted (PR #73's `pip install
vulnledger` comment), which makes it grounded rather than speculative.
4. **#99** — persistence + logging suppression (`rw-014` is a standing miss).
5. **#106** — action-gate package policy. After #68, since it depends on the rule hygiene.
6. **#37**, then **#69 items 2+3**, then #29 / #38 / #40 as previously ranked.

**Method note worth keeping.** #69 item 1 was going to be resolved by argument — one advisor said
REMOVE on API-hygiene grounds, one said IMPLEMENT. Reproducing the claim took minutes and settled it
outright: the type named a live bypass that shipped in every released version. **When advisors
disagree about whether a gap is real, measure the gap.** The same move is available for #98, #99 and
#107 — each names a concrete payload shape that can be run through `scanSync` today to confirm the
miss before any pattern is written.

### Session — 2026-10-20 00:45 (full re-rank: 36 open issues, 3 new tracks)

- Re-ranked every open issue, not just the August shortlist, after the 0.2.26 and ml 0.1.10 releases and the #345 review.
- Created three home tracks so every open issue has an owner:
  - `scan-performance` (P0): #308 and #337
  - `fiction-false-positives` (P1): #303 and #305–#307
  - `runtime-hardening` (P1): #274 and #358–#360
- Slotted the remaining untracked issues into existing tracks:
  - #98, #99, #106, #107, #178, #232, #245 and #304 → detection-hardening
  - #332 → transport-integrity
  - #275 → ml-v2-retrain
- Filed #358, #359 and #360 from the #345 review. Two other findings follow AGENTS.md rules, so they're recorded as design notes rather than bugs.
- Weighting moved from "legible credibility before launch" to "don't break real consumers": downloads are up about 6x since August, and CritForge depends on the package.
- Added a dependency graph and release batching, so the two behaviour-changing items (#358 and #307) ship together in `0.3.0`.
- Nothing implemented. Analysis, ordering and issue filing only.

### Session — 2026-10-20 03:00 (housekeeping decisions applied)

- All four housekeeping items are resolved:
  - #309 closed as a duplicate of #302.
  - #98 and #99 closed at `strict`. The `balanced` measurement in #329 showed honest-text false flags, so that coverage moved to #25's data checklist.
  - #35 rescoped to the retrain step and moved from detection-hardening to `ml-v2-retrain`.
  - #38 unblocked on GitHub.
- Re-ranked rather than appended: #38 moves from 22 to 19, ahead of the High-effort ML chain, because it now has no dependencies. #32 and #35 share rank 22, since both ride #25.
- Dropped closed issues (#98, #99, #309) from `references`. 33 issues are open.
- The top of the ranking is unchanged: #308, #359, #306.
