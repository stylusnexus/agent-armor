---
track: ml-v2-retrain
status: active
launch_priority: P1
milestone_alignment: v1.0.0
github:
  repo: stylusnexus/agent-armor
  issues:
    - 25
    - 32
    - 40
    - 71
  branches: []
depends_on: [transport-integrity]
last_touched: 2026-07-07T21:07
last_handoff: 2026-07-07T21:07
next_up:
  - 71
  - 40
  - 25
blockers: []
---
# ML v2 Retrain

Next model retrain: data requirements, transport-integrity training samples, eval-gated external-feed ingestion

## Issues

| # | Title | Assignee | Status |
|---|---|---|---|
| #25 | ML v2: data requirements for next model retrain | — | 🔲 Open |
| #32 | ML v2: Add transport-integrity attack samples to training data | — | 🔲 Open (blocked on #26) |
| #40 | Eval-gated external-feed ingestion (patterns + ML training data) | — | 🔲 Open |
| #71 | ci(ml): scheduled integrity check of MODEL_CHECKSUM against the HuggingFace artifact | — | 🔲 Open |


## Session log

### Session — 2026-06-20 17:59

- Touched: (no git activity attributed; 3 open from GitHub)
- Next: #25 ML v2: data requirements for next model retrain
- Next: #40 Eval-gated external-feed ingestion (patterns + ML training data)

### Session — 2026-07-07 21:07 (value reprioritization + slotting)

- Slotted #71 (scheduled model-checksum integrity check) here — it's ML supply-chain integrity, ships independently of the retrain.
- Reordered next_up by leverage: #71 (dependency-free quick win) > #40 (design-stage, already verified accurate against shipped #36) > #25 (the big data lift). #32 stays out of next_up — blocked on #26 landing in the transport-integrity track first.
