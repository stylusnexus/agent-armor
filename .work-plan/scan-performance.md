---
track: scan-performance
status: active
launch_priority: P0
milestone_alignment: v1.0.0
github:
  repo: stylusnexus/agent-armor
  issues:
    - 308
    - 337
  references:
    - 304
    - 332
  branches: []
depends_on: []
last_touched: 2026-10-20T00:45
last_handoff: 2026-10-20T00:45
next_up:
  - 308
  - 337
blockers: []
---

# Scan Performance

Scan latency and time bounds: `scanSync` blocks the event loop, so time per call is a correctness property for consumers on a request path, not only a benchmark number.

Created P0 on 2026-10-20. Latency grows faster than input size (#308). The time-bound tests in CI fail now and then. Work that adds more time-bound tests should land after this track's investigation, not alongside it.

## Issues

| #    | Title                                                       | Assignee | Status  |
| ---- | ----------------------------------------------------------- | -------- | ------- |
| #308 | perf: scan time grows sharply between 1k and 10k characters | —        | 🔲 Open |
| #337 | fix(detectors): rescan each decoded reading on its own      | —        | 🔲 Open |

## Dependencies

- **#308 first.** Profile the growth between 1k and 10k characters and fix any pass that grows faster than linear. The issue also asks for an optional time budget per call (`maxScanMs`) that returns a result marked as truncated. Treat the budget as a separate decision, because a truncated scan has to fail closed (AGENTS.md).
- **#337 after the encoded-payload timing investigation.** #337 changes how the `encoded-payload` detector joins and rescans decoded readings. #357 adds CPU-time logging to that detector's time-bound tests. Let that work finish first so the two changes don't collide in the same code.
- **Referenced, owned elsewhere:** #332 (transport-integrity) and #304 (detection-hardening) each add detection with new time-bound tests. Land them after #308 so new tests don't inherit a flaky baseline.

## Context: CI timing tests

The repo's time-bound tests run on shared CI runners, and three kinds of failure have shown up:

- **First-call compile time counted as scan time.** `pattern-time-budget` timed V8 compiling a 15,367-character regex. Fixed in #347 by running each pattern twice untimed first.
- **Tight wall-clock limits under runner load.** The `tool-call-tampering` whole-scan limit was raised from 6s to 15s in #350. The scan is linear: about 1.0s for 2.5M characters locally.
- **Intermittent slow cases in `encoded-payload` time-bound tests.** These aren't explained by runner load. Diagnostic logging is in #357.

When a timing test fails, find the cause before raising its limit. A limit is only safe to raise when the scan is shown to be linear and the overshoot comes from the environment.

## Session log

### Session — 2026-10-20 00:45 (track created)

- Created from the 2026-10-20 backlog review (see `best-wins-cross`). #308 and #337 had no home track.
- Ordering: #308, then #337. #304 and #332 are referenced because their new time-bound tests should land after #308.
