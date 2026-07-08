---
track: transport-integrity
status: active
launch_priority: P1
milestone_alignment: v1.0.0
github:
  repo: stylusnexus/agent-armor
  issues:
    - 26
    - 27
    - 28
    - 29
    - 30
    - 31
  branches: []
depends_on: []
last_touched: 2026-07-07T21:07
last_handoff: 2026-07-07T21:07
next_up:
  - 26
  - 27
blockers: []
---
# Transport Integrity

New taxonomy category for malicious-intermediary attacks and its detectors (tool-call tampering, credential exposure, dependency substitution, response anomaly, response signing)

Confirmed P1 on 2026-07-07's value pass: already correctly ordered — #26 is the taxonomy/type-system prerequisite blocking #27-#30 in this track plus #32 in ml-v2-retrain, so it stays first regardless of anything else.

## Issues

| # | Title | Assignee | Status |
|---|---|---|---|
| #26 | New taxonomy category: Transport Integrity (malicious intermediary attacks) | — | 🔲 Open |
| #27 | Detector: Tool-call tampering (AC-1 payload injection) | — | 🔲 Open |
| #28 | Detector: Credential exposure scanning (AC-2 secret exfiltration) | — | 🔲 Open |
| #29 | Detector: Dependency substitution (AC-1.a typosquat injection) | — | 🔲 Open |
| #30 | Detector: Response anomaly screening for intermediary manipulation | — | 🔲 Open |
| #31 | Future: Provider response-envelope verification (response signing) | — | 🔲 Open |


## Session log

### Session — 2026-06-20 17:59

- Touched: (no git activity attributed; 6 open from GitHub)
- Next: #26 New taxonomy category: Transport Integrity (malicious intermediary attacks)
- Next: #27 Detector: Tool-call tampering (AC-1 payload injection)
