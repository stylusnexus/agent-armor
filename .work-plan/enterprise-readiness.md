---
track: enterprise-readiness
status: active
launch_priority: P1
milestone_alignment: v1.0.0
github:
  repo: stylusnexus/agent-armor
  issues:
    - 24
    - 38
    - 75
  branches: [feat/24-diagnostics-events]
depends_on: []
last_touched: 2026-07-08T17:28
last_handoff: 2026-07-08T17:28
next_up:
  - 75
blockers: []
---
# Enterprise Readiness

Enterprise/observability surface: extensible diagnostics + audit-evidence records, compliance control mapping (SOC2/ISO crosswalk)

Reprioritized P3 → P1 on 2026-07-07: #24 is the most actively-discussed open issue (a substantive external-contributor design comment landed 2026-06-18), it unblocks #38, and it's the natural foundation for a durable audit trail behind the new launch-infra CLI (#66). No longer a someday-enterprise-tier item — it has real design momentum now.

## Issues

| # | Title | Assignee | Status |
|---|---|---|---|
| #24 | feat: extensible diagnostics/event system (warn, error, detectorSkipped) | — | ✅ Shipped |
| #38 | Compliance control mapping (SOC 2 / ISO 27001 crosswalk) — deferred | — | 🔲 Open |
| #75 | feat: audit-evidence records (AuditRecord + evidence-package aggregation) | — | 🔲 Open (unblocked, ready to plan) |


## Session log

### Session — 2026-06-20 17:59

- Touched: (no git activity attributed; 2 open from GitHub)
- Next: #24 Extensible diagnostics/event system + audit-evidence records

### Session — 2026-07-08 22:30 (rescoped #24, filed #75)

- User asked to look at #24 next. Before implementing, split scope with user input (AskUserQuestion): diagnostics system (this session) ships first as a standalone PR; the audit-evidence record (AuditRecord + evidence-package aggregation with digest/tamper-evidence, built together per user's choice) is real but separable — split out to **#75**, blocked on #24.
- Rescoped #24's title/body to diagnostics-only; corrected a stale claim in the original text (packages/ml no longer uses console.warn anywhere — verified live, every failure mode now throws a typed AgentArmorModelError; that refactor happened after the issue was filed in April).
- Audit granularity decided (carried into #75): the `audit` event fires once per scan decision at the finest grain — once per RAG chunk, once per turn — not once per top-level API call.
- Design for #24 grounded in live code reading: 4 console.warn sites in agent-armor.ts (ML-unavailable at line 518, detector-threw sync/async at 603/676, accumulation-requested at 751) map to `on.warn`/`on.error`; `loadDetectors()`'s silent config-toggle skip (line 531) maps to the new `detectorSkipped` event. Fully backward compatible — no `on` config means byte-identical behavior to today.
- Implementation of #24 itself starts next.

### Session — 2026-07-08 17:28 (#24 implemented, not yet merged)

- Implemented #24 per `docs/superpowers/plans/2026-07-08-diagnostics-events.md` on branch `feat/24-diagnostics-events`.
- New `on` config on `AgentArmorConfig`: `warn`, `error`, `detectorSkipped` callbacks. All 4 existing `console.warn` sites (ML-unavailable, detector-threw sync/async, accumulation-requested) redirect through the matching callback when provided, `console.warn` unchanged when not — verified as a real backward-compat property via dedicated tests (no `on` config → byte-identical `console.warn` output) plus a live CLI end-to-end check (the CLI never passes `on`, confirmed still `[ok]`/exit 0 post-change). New `detectorSkipped` event fires for both skip reasons in `loadDetectors()` (`config-disabled`, `no-patterns`) — previously silent.
- `packages/ml` needed zero changes — it throws typed `AgentArmorModelError` everywhere already, no `console.warn` to redirect.
- 9 new tests (189 total, up from 180), all passing on first run — the plan's Task 6 contingency (verify `scanSession`/`loadPatterns` signatures before trusting the test assumptions) needed no correction, both matched exactly.
- Full verification: typecheck/lint/test clean, build clean, `eval:gate` unaffected, docs regenerated under Node 20 (per #67's CONTRIBUTING.md note) with the 4 new types (`WarnEvent`, `ErrorEvent`, `DetectorSkippedEvent`, `DiagnosticsConfig`) confirmed present and cross-referenced in the generated reference.
- Next: open the PR, merge once green (same admin-bypass pattern as #72/#73/#74). Then #75 (audit-evidence records) is unblocked and ready to plan — carries forward the marywang-aiops three-layer design and the once-per-chunk/turn granularity decision from this session, nothing to re-derive.
