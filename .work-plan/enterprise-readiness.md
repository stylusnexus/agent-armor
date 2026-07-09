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
  branches: [feat/75-audit-records]
depends_on: []
last_touched: 2026-07-08T19:20
last_handoff: 2026-07-08T19:20
next_up:
  - 38
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
| #75 | feat: audit-evidence records (AuditRecord + evidence-package aggregation) | — | ✅ Shipped |


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

### Session — 2026-07-08 23:08 (merged, #24 shipped)

- PR #76 opened, all 7 checks green on the first run — neither of the two known traps from #72/#74 (packages/ml lockfile drift, Node-version docs-asset non-determinism) recurred this time. Merged via `gh pr merge --squash --admin` (branch protection required review approval; user explicitly confirmed the bypass) — commit `d65871c`. #24 auto-closed cleanly.
- Verified live post-merge: `agentarmor.dev/api/interfaces/DiagnosticsConfig.html` resolves 200 (after Cloudflare's normal trailing-redirect).
- Local/remote feature branch deleted, main synced.
- #75 (audit-evidence records) is now unblocked and next up in this track.

### Session — 2026-07-08 19:20 (#75 implemented, not yet merged)

- Implemented #75 per `docs/superpowers/plans/2026-07-08-audit-records.md` on branch `feat/75-audit-records`, carrying forward the marywang-aiops design and prior granularity decision without re-deriving.
- Two genuinely open design questions resolved with user input before writing the plan (AskUserQuestion): `decision` (allow/sanitize/block/exception) is derived from `riskLevel` via a fixed, documented mapping — explicitly labeled as Agent Armor's own classification, not proof of what the caller's application actually did, since the SDK returns a `ScanResult` and the caller decides what to do with it after the call returns, in code the SDK never sees. `exception` records are supplied via a new optional 2nd parameter on every scan method (`scanSync(content, { exception: { reason, actor } })`) with both fields required at the type level — not a separate stateful `recordException()` call.
- New `on.audit` callback (5th key alongside #24's warn/error/detectorSkipped) fires once per scan decision: once per call for `scanSync`/`scan`/`scanOutput(Sync)`, once per chunk for `scanRAGChunks(Sync)` (shared `batchId`, sequential `index`), once per turn for `scanSession`/`scanSessionAsync` (same pattern). No raw content by default — threats carry `evidenceHash` (sha256), raw `evidence` only with `includeEvidence: true`.
- New `src/audit-evidence.ts`: `buildEvidencePackage`/`verifyEvidencePackage` — sha256 digest over the record set, order-sensitive, so any edit/add/remove/reorder after the fact fails verification. Reuses `node:crypto`'s `createHash`, already a codebase precedent from `packages/ml/src/model-manager.ts`.
- Real finding mid-planning: `examples/audit-logging.ts` already existed and hand-rolled almost exactly this feature (`AuditEntry`, `simpleHash`, `enforcePolicy`) — updated it to use the real `on.audit` + built-in `decision` instead of creating a duplicate example. Added `examples/audit-evidence-package.ts` for the aggregate/verify side. Both run for real (`npx tsx`) and produce correct output, including a live tamper-detection demo (untampered records verify true, a single flipped decision verifies false).
- Real bug caught before commit: both examples import the package by its own name (`@stylusnexus/agentarmor`, resolved via `package.json`'s self-reference to `dist/`) — the first run threw `Cannot read properties of undefined (reading 'decision')` because `dist/` was stale from before today's changes. Not a code bug; `npm run build` first fixed it. Worth remembering for any future example-verification step on this repo.
- `MLDetector.version` (new, exposes `MODEL_VERSION` for `AuditRecord.mlModelVersion`) required zero core-package changes beyond a narrow duck-typed read (`'version' in this.mlDetector`) — didn't widen the shared `Detector` interface, since pattern/custom detectors have no meaningful version concept.
- 14 new tests (203 total, up from 189), all passing on first run — including the `scanSession`/`scanSessionAsync` per-turn firing tests, which needed no correction against the plan's assumed loop structure (verified identical before wiring).
- Full verification: typecheck/lint/test clean, both builds clean, CLI backward-compat confirmed live (`node dist/cli.js scan` still `[ok]`/exit 0 — the new optional `ScanOptions` 2nd parameter doesn't break the CLI's single-argument calls), `eval:gate` unaffected, docs regenerated under Node 20 with all 5 new symbols (`AuditRecord`, `EvidencePackage`, `ScanOptions`, `AuditThreatSummary`, `buildEvidencePackage`, `verifyEvidencePackage`) confirmed present.
- Next: open the PR, merge once green. User asked to thank `marywang-aiops` in a comment once #75 is implemented — do this on the PR/issue after merge, crediting the 2026-06-18 design comment on #24 that this directly implements (the three-layer split and the six test cases both carried straight through). Then #38 (SOC2/ISO crosswalk) is the last open issue in this track, still correctly deferred until its own dependencies are ready.
