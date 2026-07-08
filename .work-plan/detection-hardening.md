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
last_touched: 2026-07-07T21:07
last_handoff: 2026-07-07T21:07
next_up:
  - 37
  - 68
  - 69
  - 35
blockers: []
---
# Detection Hardening

Near-term core detection + SDK improvements: risk roll-up, multi-turn scanning, long-context dilution, pre-execution action gate

Reprioritized 2026-07-07 (down from P0, alongside a value pass across all tracks): #34/#57 shipped, so remaining work is a real-but-non-blocking detection gap and hardening/maintenance items — valuable, but the launch-infra track now carries the P0 near-term-highest-leverage work.

## Issues

| # | Title | Assignee | Status |
|---|---|---|---|
| #34 | Add computed riskLevel roll-up to ScanResult | — | ✅ Shipped |
| #35 | ML-based semantic accumulation detection across turns (mt-mem/mt-ctx blind spots) — rescoped 2026-07-07, structural half shipped via #50/#53 | — | 🔲 Open (blocked on #25 ML retrain) |
| #37 | Long-context attention-dilution detection | — | 🔲 Open |
| #57 | feat: allowlist-based pre-execution action gate (`checkAction`) | — | ✅ Shipped |
| #68 | feat(action-gate): policy ergonomics and hardening | — | 🔲 Open |
| #69 | test(eval): cover zero/thin-coverage trap types; extract multi-turn gate thresholds | — | 🔲 Open |


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
