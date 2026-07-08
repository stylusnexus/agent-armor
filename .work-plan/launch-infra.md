---
track: launch-infra
status: active
launch_priority: P0
milestone_alignment: v1.0.0
github:
  repo: stylusnexus/agent-armor
  issues:
    - 64
    - 65
    - 66
    - 67
    - 70
  branches: []
depends_on: []
last_touched: 2026-07-07T21:07
last_handoff: 2026-07-07T21:07
next_up:
  - 65
  - 64
  - 66
blockers: []
---
# Launch Infra & Adoption

Pre-launch credibility polish (CI gates the security fuzz test doesn't run yet, README/site drift) plus the biggest adoption lever identified in the 2026-07-07 backlog grooming: a CLI with SARIF output for CI/pre-commit integration. Also covers generated API docs and automated npm publishing.

## Issues

| # | Title | Assignee | Status |
|---|---|---|---|
| #64 | ci: run action-gate fuzz, lint, ML package tests, and build in CI | — | 🔲 Open |
| #65 | chore(docs): fix README/site drift and add a doc-consistency gate to CI | — | 🔲 Open |
| #66 | feat: agentarmor CLI with JSON/SARIF output for CI scanning | — | 🔲 Open |
| #67 | docs: generated API reference (TypeDoc) published to agentarmor.dev | — | 🔲 Open |
| #70 | ci: automated npm publish with provenance via release-please (trusted publishing) | — | 🔲 Open |

## Session log

### Session — 2026-07-07 (initial slotting)

- Track created during backlog-grooming pass: 8 new issues filed (numbers 64 through 71) after reviewing all 20 open issues for duplicates. This track groups the launch-readiness + adoption cluster; the action-gate hardening, eval-coverage, and model-integrity issues went to existing detection-hardening/ml-v2-retrain tracks instead since they extend work already tracked there.
- Next: #65 doc drift (cheap, protects launch credibility)
- Next: #64 CI hardening (cheap, closes a real gap — the action-gate security fuzz test doesn't run in CI)
- Next: #66 CLI + SARIF (biggest single adoption lever — larger effort, do after the quick wins)
