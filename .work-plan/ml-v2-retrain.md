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
    - 275
  references:
    - 35
    - 245
  branches: []
depends_on: [transport-integrity]
last_touched: 2026-07-07T21:07
last_handoff: 2026-07-07T21:07
next_up:
  - 275
  - 40
  - 25
blockers: []
---

# ML v2 Retrain

Next model retrain: data requirements, transport-integrity training samples, eval-gated external-feed ingestion

## Issues

| #    | Title                                                                                | Assignee | Status                     |
| ---- | ------------------------------------------------------------------------------------ | -------- | -------------------------- |
| #25  | ML v2: data requirements for next model retrain                                      | —        | 🔲 Open                    |
| #32  | ML v2: Add transport-integrity attack samples to training data                       | —        | 🔲 Open                    |
| #40  | Eval-gated external-feed ingestion (patterns + ML training data)                     | —        | 🔲 Open                    |
| #71  | ci(ml): scheduled integrity check of MODEL_CHECKSUM against the HuggingFace artifact | —        | ✅ Shipped                 |
| #275 | ml: cut over-defense on short benign text with attack words (NotInject)              | —        | 🟡 Run 6 at 89% (goal 90%) |

## Session log

### Session — 2026-06-20 17:59

- Touched: (no git activity attributed; 3 open from GitHub)
- Next: #25 ML v2: data requirements for next model retrain
- Next: #40 Eval-gated external-feed ingestion (patterns + ML training data)

### Session — 2026-07-07 21:07 (value reprioritization + slotting)

- Slotted #71 (scheduled model-checksum integrity check) here — it's ML supply-chain integrity, ships independently of the retrain.
- Reordered next_up by leverage: #71 (dependency-free quick win) > #40 (design-stage, already verified accurate against shipped #36) > #25 (the big data lift). #32 stays out of next_up — blocked on #26 landing in the transport-integrity track first.

### Session — 2026-10-20 00:45 (backlog review)

- Slotted #275 (NotInject over-defense). Its latest results comment (PR #282) puts run 6 at 89% accuracy on NotInject against a 90% goal, with eval-suite AUC 0.89. Next step is a decision, not new work: ship run 6, or do one more retrain aimed at the gap. Per AGENTS.md, never push a retrained model without the maintainer.
- #32 is unblocked: every transport-integrity detector (#26–#30) has shipped. It still rides on #25.
- Referenced, owned elsewhere: #35 (detection-hardening). Its only remaining step is a cross-turn retrain that rides with #25. #245 (multilingual) needs the tokenizer and training data from #25.
- Model loading and integrity at runtime (#274, #359, #360) belong to `runtime-hardening`, not this track.
- next_up: #275 (decision), #40, #25.
