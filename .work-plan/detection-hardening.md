---
track: detection-hardening
status: active
launch_priority: P1
milestone_alignment: v1.0.0
github:
  repo: stylusnexus/agent-armor
  issues:
    - 34
    - 35
    - 37
    - 57
    - 68
    - 69
  branches: []
depends_on: []
last_touched: 2026-08-06T09:00
last_handoff: 2026-08-06T09:00
next_up:
  - 68
  - 69
  - 37
blockers: []
---
# Detection Hardening

Near-term core detection + SDK improvements: risk roll-up, multi-turn scanning, long-context dilution, pre-execution action gate

Reprioritized 2026-07-07 (down from P0, alongside a value pass across all tracks): #34/#57 shipped, so remaining work is a real-but-non-blocking detection gap and hardening/maintenance items — valuable, but the launch-infra track now carries the P0 near-term-highest-leverage work.

## Issues

| # | Title | Assignee | Status |
|---|---|---|---|
| #34 | Add computed riskLevel roll-up to ScanResult | — | ✅ Shipped |
| #35 | ML-based semantic accumulation detection across turns (mt-mem/mt-ctx blind spots) — structural half shipped via #50/#53, ML-windowing half shipped via #62 (2026-07-09) | — | ✅ Shipped |
| #37 | Long-context attention-dilution detection | — | 🔲 Open |
| #57 | feat: allowlist-based pre-execution action gate (`checkAction`) | — | ✅ Shipped |
| #68 | feat(action-gate): policy ergonomics and hardening | — | 🔲 Open |
| #69 | test(eval): cover zero/thin-coverage trap types; extract multi-turn gate thresholds | — | 🟡 Item 1 shipped (steganographic-payload); items 2-3 open |


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
