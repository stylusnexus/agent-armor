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
last_touched: 2026-08-06T09:00
last_handoff: 2026-08-06T09:00
next_up:
  - 27
  - 29
blockers: []
---
# Transport Integrity

New taxonomy category for malicious-intermediary attacks and its detectors (tool-call tampering, credential exposure, dependency substitution, response anomaly, response signing)

Confirmed P1 on 2026-07-07's value pass: already correctly ordered — #26 is the taxonomy/type-system prerequisite blocking #27-#30 in this track plus #32 in ml-v2-retrain, so it stays first regardless of anything else.

## Issues

| # | Title | Assignee | Status |
|---|---|---|---|
| #26 | New taxonomy category: Transport Integrity (malicious intermediary attacks) | — | ✅ Shipped |
| #27 | Detector: Tool-call tampering (AC-1 payload injection) | — | 🔲 Open |
| #28 | Detector: Credential exposure scanning (AC-2 secret exfiltration) | — | ✅ Shipped |
| #29 | Detector: Dependency substitution (AC-1.a typosquat injection) | — | 🔲 Open |
| #30 | Detector: Response anomaly screening for intermediary manipulation | — | 🔲 Open |
| #31 | Future: Provider response-envelope verification (response signing) | — | 🔲 Open |


## Session log

### Session — 2026-06-20 17:59

- Touched: (no git activity attributed; 6 open from GitHub)
- Next: #26 New taxonomy category: Transport Integrity (malicious intermediary attacks)
- Next: #27 Detector: Tool-call tampering (AC-1 payload injection)

### Session — 2026-08-05 22:50 (#26 + #28 shipped)

- #28 (credential-exposure detector) implemented and merged via PR #94 (`0505bc7`), squash-merged with `--admin` after explicit user authorization. All 8 CI checks green on the first run — `docs-api` included, so regenerating under Node 20 avoided the compressed-asset trap that bit #74.
- **#26 closed by the same PR, and it was mostly already done.** Found before starting: `TrapCategory` already carried `'transport-integrity'`, `TransportIntegrityType` was fully defined and unioned into `TrapType`, the `transportIntegrity` config block existed with all four toggles defaulting to `true`, and `DetectorRegistration.configGroup` already accepted `'transportIntegrity'`. The only outstanding acceptance item was a `DETECTOR_REGISTRY` entry — which cannot exist without a detector to attach it to. Doing #26 "first" would have been an empty commit. Anyone picking up #27/#29/#30 should know the taxonomy work is not a blocker.
- 16 patterns added under the `credential-exposure` pattern-DB key; pattern DB v0.6.0 → v0.7.0 (83 → 99 entries).
- **New shared mechanism worth reusing for #27/#30:** `BaseDetector.redactEvidence()` (identity by default) + `PatternDetector`'s `maskEvidence` flag. `scan()` was copying matched text verbatim into `Threat.evidence`, which flows into `ScanResult`, CLI JSON/SARIF, audit records, and caller logs — fine everywhere until the match IS a secret. #27's "unexpected secret pattern" feature and #30's secret-in-tool-args signal will want the same flag.
- **Eval fixtures assemble fake credentials from fragments**, not inline literals — a contiguous `AKIA…`/`ghp_…`/PEM string in a public repo trips GitHub push protection over test data. Dogfooding the built CLI against the diff caught one literal that had slipped into a unit test. Push went through clean, confirming the approach. Reuse the `fake()` helper in `scripts/eval/samples.ts` for any future secret-shaped fixture.
- Eval: 115 samples (73 adversarial / 42 benign), credential-exposure 6/6 at every strictness, FP 0.0% held. Thresholds re-baselined 0.818→0.835 permissive, 0.909→0.917 balanced/strict.
- Site auto-deployed on merge and verified live (`Credential Exposure` card, `v0.7.0 patterns, 115 samples` in llms.txt, `/api/` still 200). npm still serves 0.2.13 — release PR #93 (0.2.14) carries this and is deliberately unmerged while more work batches in.
- Next in this track: #27 (tool-call tampering) then #29 (dependency substitution). Both now unblocked with no taxonomy prerequisite.

### Session — 2026-08-06 (#29 gains real-world grounding; two adjacent issues filed)

- Commented on #29 with the July 2026 OpenAI sandbox escape: the models escaped containment via a zero-day in **self-hosted Artifactory**, a package-registry cache proxy. That widens #29's motivation — the resolver redirection is itself an **egress path**, not only a substitution vector. Severity framing should reflect that; the detection shapes in the issue body already cover the observable form. Eval sample `rw-013` models it and is a ready-made acceptance test (currently a documented miss).
- Filed #107 (dependency-install risk in scanned content: lockfile bypass, lifecycle scripts) and #106 (action-gate package policy: release-age floor, pin enforcement). Both are adjacent to #29 but distinct: #29 is *which package you get*, #107 is *how it is installed*, #106 is *whether the install is admissible at all*.
- **Precedent worth remembering:** this repo already received this attack. PR #73 (2026-07-08) carried a comment recommending `pip install vulnledger` — a package whose claimed source repo 404s. A human investigated and declined. An agent triaging that PR would have had nothing stopping it. #107 asks for an eval sample modelled on it.
