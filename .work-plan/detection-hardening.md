---
track: detection-hardening
status: active
launch_priority: P1
milestone_alignment: v1.0.0
github:
  repo: stylusnexus/agent-armor
  issues:
    - 34
    - 37
    - 57
    - 68
    - 69
    - 98
    - 99
    - 106
    - 107
    - 178
    - 232
    - 245
    - 304
  references:
    - 35
  branches: []
depends_on: []
last_touched: 2026-10-20T03:00
last_handoff: 2026-10-20T03:00
next_up:
  - 178
  - 68
  - 107
blockers: []
---

# Detection Hardening

Near-term core detection + SDK improvements: risk roll-up, multi-turn scanning, long-context dilution, pre-execution action gate

Reprioritized 2026-07-07 (down from P0, alongside a value pass across all tracks): #34/#57 shipped, so remaining work is a real-but-non-blocking detection gap and hardening/maintenance items — valuable, but the launch-infra track now carries the P0 near-term-highest-leverage work.

## Issues

| #    | Title                                                                                                                    | Assignee | Status                                                             |
| ---- | ------------------------------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------------------ |
| #34  | Add computed riskLevel roll-up to ScanResult                                                                             | —        | ✅ Shipped                                                         |
| #35  | ML retrain: cross-turn semantic accumulation (mt-mem/mt-ctx) — structural half shipped via #50/#53, ML windowing via #62 | —        | ➡️ Retrain step moved to `ml-v2-retrain` (2026-10-20)              |
| #37  | Long-context attention-dilution detection                                                                                | —        | 🔲 Open                                                            |
| #57  | feat: allowlist-based pre-execution action gate (`checkAction`)                                                          | —        | ✅ Shipped                                                         |
| #68  | feat(action-gate): policy ergonomics and hardening                                                                       | —        | 🔲 Open                                                            |
| #69  | test(eval): cover zero/thin-coverage trap types; extract multi-turn gate thresholds                                      | —        | ✅ Shipped                                                         |
| #98  | Detector: C2 / drop-service channel endpoints in scanned content                                                         | —        | ✅ Closed: shipped at `strict` (#329); `balanced` is ML work (#25) |
| #99  | Detector: cross-environment persistence and logging suppression                                                          | —        | ✅ Closed: shipped at `strict` (#329); `balanced` is ML work (#25) |
| #106 | feat(action-gate): package-install policy — release-age floor and pin enforcement                                        | —        | 🔲 Open (after #68)                                                |
| #107 | Detector: dependency-install risk in scanned content (lockfile bypass, lifecycle scripts)                                | —        | 🔲 Open                                                            |
| #178 | fix(patterns): exfiltration instruction check reads only the matched words                                               | —        | 🟡 Partly shipped (#334, #339)                                     |
| #232 | Help wanted: try to break the reference-image scan with your own markdown                                                | —        | 🔲 Open (community)                                                |
| #245 | design: multilingual detection with opt-in language packs                                                                | —        | 🔲 Open (after #25)                                                |
| #304 | feat(output): flag markdown images that leak data to outside hosts                                                       | —        | 🔲 Open (after #308)                                               |

## Session log

### Session — 2026-06-20 17:59

- Touched: (no git activity attributed; 4 open from GitHub)
- Next: #34 Add computed riskLevel roll-up to ScanResult
- Next: #57 feat: allowlist-based pre-execution action gate (`checkAction`)
- Next: #35 Stateful multi-turn conversation scanning (cross-turn decomposition)

### Session — 2026-06-21 10:46

- Touched: feat: add computed riskLevel roll-up to ScanResult (#34) (#60) (1a63340)
- Touched: feat: add computed riskLevel roll-up to ScanResult (#34) (1a6ca0b)
- Touched: chore: add work-plan planning tracks for open issues (#59) (588b77b)
- Touched: docs: add deterministic-vs-probabilistic positioning to README and llms.txt (#58) (637a4d4)
- Touched: chore: add work-plan planning tracks for open issues (02badf0)
- Next: #57 feat: allowlist-based pre-execution action gate (`checkAction`)
- Next: #35 Stateful multi-turn conversation scanning (cross-turn decomposition)
- Next: #37 Long-context attention-dilution detection

### Session — 2026-06-21 11:25

- Touched: feat: allowlist-based pre-execution action gate (#57) (#61) (766af56)
- Touched: feat: add allowlist-based pre-execution action gate (#57) (96a901a)
- Touched: feat: add computed riskLevel roll-up to ScanResult (#34) (#60) (1a63340)
- Next: #35 Stateful multi-turn conversation scanning (cross-turn decomposition)
- Next: #37 Long-context attention-dilution detection

### Session — 2026-07-07 21:07 (value reprioritization + slotting)

- Slotted #68 (action-gate ergonomics) and #69 (eval coverage) into this track — both extend already-shipped work here rather than belonging in the new launch-infra track.
- #35 retitled/rescoped per its 2026-06-13 status comment: structural half shipped (#50/#53), remaining scope is ML-only semantic accumulation, blocked on the #25 retrain.
- Reordered next_up by leverage: #37 (real open detection gap) > #68 (security-relevant hardening of a freshly-shipped feature) > #69 (protects regression-test integrity) > #35 (blocked, lowest near-term actionability).
- Track priority P0 → P1: the two shippable P0 items landed; launch-infra now carries the highest-leverage near-term work.

### Session — 2026-07-09 02:00

- Touched: feat: cross-turn ML accumulation windowing in session scan (#35 step 1) (#62) (b83ed1b) — rebased 6-week-stale PR onto main, reconciling with #24 (diagnostics events) and #75 (audit records) which had modified the same two functions (`warnIfAccumulationRequested`, `scanSessionAsync`) since #62 was authored.
- #35 marked shipped: ML-based cross-turn semantic accumulation now runs via `scanSessionAsync` when `session.accumulation` + ML classifier are both enabled. Only the cross-turn-structured model retrain (#35 step 2) remains, and that rides with #25, not this track.
- Removed #35 from next_up (shipped).

### Session — 2026-08-06 (#69 item 1 shipped as a security fix, not a cleanup)

- #69 item 1 asked whether to implement `steganographic-payload` or delete it as a dead type. Two advisory passes disagreed, so the question was settled empirically rather than by argument — and the answer was neither "dead type" nor "nice to have".
- **It named a live bypass of every detector in the product.** Measured on main before any code was written: the same jailbreak that fires `jb-ignore-instructions` at 0.95 in plain ASCII returned `clean: true` with ZERO threats when re-encoded into the Unicode Tags block (U+E0000-E007F) or a variation-selector run, and passed through `sanitize()` byte-for-byte intact. Shipped in v0.2.15 (PR #102).
- **Normalization was making it worse, not better.** The Tags block is absent from `src/normalize/unicode.ts` entirely; variation selectors are stripped only from the detection skeleton, while `sanitize()` operates on raw content — so nothing flagged meant nothing removed. Normalization was silently converting a detection problem into a clean pass-through. There is now a test asserting the detector runs on RAW input; if anyone moves it onto the normalized skeleton, that test fails.
- **Gotcha for anyone touching these patterns:** they deliberately carry no `requireInstructions`/`boostOnInstructions`. `findPatterns` tests instruction signals against the MATCHED text, which by construction contains no ASCII, so `hasInstruction` is always false and either flag would permanently suppress them. Presence of the carrier is the signal.
- Items 2 (thin per-type coverage) and 3 (multi-turn threshold extraction) remain open. Reordered `next_up`: #68 and #69 now lead #37.

### Session — 2026-10-20 00:45 (backlog review: untracked issues slotted)

- Gave this track the detection and action-gate issues that had no home track: #98, #99, #106, #107 (previously only referenced from `best-wins-cross`), plus #178, #232, #245 and #304.
- Status corrections: #69 is closed (all items shipped). #35 is still open on GitHub. Its remaining step is a retrain, which rides with #25 in `ml-v2-retrain`. Closing or rescoping it unblocks #38 (`enterprise-readiness`).
- #98 and #99 got strict-only patterns in #329 (0.2.25). Decide whether `balanced` coverage is worth more work, or close both.
- Dependencies:
  - **#178 before #305** (`fiction-false-positives`). Both change the instruction-signal check.
  - **#68 before #106.** A bare `{ tool: 'npm.install' }` rule would admit any package, so fix the rule hygiene before adding the rule type.
  - **#107** can run in parallel with #106. It's the content-scanning side of the same threat.
  - **#304 after #308** (`scan-performance`), because it adds time-bound tests.
  - **#245 after #25.** Multilingual needs tokenizer and training data that the retrain brings.
  - **#37** shares a long-document eval set with #274 (`runtime-hardening`). Build it once.
- next_up re-ranked: #178 (unblocks the fiction track), #68 (rule hygiene before new rule types), #107.

### Session — 2026-10-20 03:00 (housekeeping decisions applied)

- **#98 and #99 closed as completed.** On current `main`, `rw-011` and `rw-014` are caught at `strict` and missed at `permissive` and `balanced`. #329 already tried `balanced` versions and found they flagged honest text with the same wording (for example "Never send credentials to https://webhook.site"), so AGENTS.md's strict-only rule applies. Getting `balanced` coverage is now ML work: #25's data checklist has a line for training variants of both shapes, never the `rw-*` eval samples.
- **#35 rescoped to the retrain step and moved to `ml-v2-retrain`.** It's kept here as a reference because the shipped halves (#50, #53, #62) are logged in this track.
- next_up unchanged: #178, #68, #107.
