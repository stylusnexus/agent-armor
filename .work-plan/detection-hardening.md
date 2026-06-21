---
track: detection-hardening
status: active
launch_priority: P0
milestone_alignment: v1.0.0
github:
  repo: stylusnexus/agent-armor
  issues:
    - 34
    - 35
    - 37
    - 57
  branches: []
depends_on: []
last_touched: 2026-06-21T11:25
last_handoff: 2026-06-21T11:25
next_up:
  - 35
  - 37
blockers: []
---
# Detection Hardening

Near-term core detection + SDK improvements: risk roll-up, multi-turn scanning, long-context dilution, pre-execution action gate

## Issues

| # | Title | Assignee | Status |
|---|---|---|---|
| #34 | Add computed riskLevel roll-up to ScanResult | — | ✅ Shipped |
| #35 | Stateful multi-turn conversation scanning (cross-turn decomposition) | — | 🔲 Open |
| #37 | Long-context attention-dilution detection | — | 🔲 Open |
| #57 | feat: allowlist-based pre-execution action gate (`checkAction`) | — | ✅ Shipped |


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
