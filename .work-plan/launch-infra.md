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
last_touched: 2026-07-08T04:09
last_handoff: 2026-07-08T04:09
next_up:
  - 66
blockers: []
---
# Launch Infra & Adoption

Pre-launch credibility polish (CI gates the security fuzz test doesn't run yet, README/site drift) plus the biggest adoption lever identified in the 2026-07-07 backlog grooming: a CLI with SARIF output for CI/pre-commit integration. Also covers generated API docs and automated npm publishing.

## Issues

| # | Title | Assignee | Status |
|---|---|---|---|
| #64 | ci: run action-gate fuzz, lint, ML package tests, and build in CI | — | ✅ Shipped |
| #65 | chore(docs): fix README/site drift and add a doc-consistency gate to CI | — | ✅ Shipped |
| #66 | feat: agentarmor CLI with JSON/SARIF output for CI scanning | — | 🔲 Open |
| #67 | docs: generated API reference (TypeDoc) published to agentarmor.dev | — | 🔲 Open |
| #70 | ci: automated npm publish with provenance via release-please (trusted publishing) | — | 🔲 Open |

## Session log

### Session — 2026-07-07 (initial slotting)

- Track created during backlog-grooming pass: 8 new issues filed (numbers 64 through 71) after reviewing all 20 open issues for duplicates. This track groups the launch-readiness + adoption cluster; the action-gate hardening, eval-coverage, and model-integrity issues went to existing detection-hardening/ml-v2-retrain tracks instead since they extend work already tracked there.
- Next: #65 doc drift (cheap, protects launch credibility)
- Next: #64 CI hardening (cheap, closes a real gap — the action-gate security fuzz test doesn't run in CI)
- Next: #66 CLI + SARIF (biggest single adoption lever — larger effort, do after the quick wins)

### Session — 2026-07-07 21:40 (branch feat/64-65-ci-and-doc-hardening)

- Implemented #64 and #65 per `docs/superpowers/plans/2026-07-07-ci-and-doc-hardening.md`. Not yet merged.
- #65: fixed stale pattern-version numbers in README/llms.txt (v0.4.0/71 entries -> v0.6.0/83); removed orphaned root `patterns.json`; added `npm run check:docs` (derives sample count/pattern version from source, fails CI on drift).
- Correction mid-implementation: the eval sample count was NOT stale (105/67/38 is correct at runtime) — an initial grep-based count during planning miscounted by one. The checker script itself caught this before it shipped; committed a visible fix-up rather than amending history. Found in the process: one sample block in `scripts/eval/samples.ts` matches `category: 'adversarial'` via grep but isn't wired into `ALL_SAMPLES` — real but out of scope here, worth a follow-up look (possibly folds into #69's eval-coverage work).
- #64: `npm run lint` was previously non-functional (eslint not installed, no config) — added eslint 9 + typescript-eslint, fixed the 7 violations a recommended ruleset surfaced. Added `.github/workflows/ci.yml` with 5 jobs (lint, docs-drift, build, ml-package, action-gate-fuzz w/ SecLists sparse-clone + cache). Hardened `action-gate-fuzz.ts` to fail (not skip) when the corpus is missing under `CI=true`.
- All local dry-runs green: lint, check:docs, build (root + ml), ml-package typecheck/test, and the real action-gate fuzz against the live SecLists corpus (0 escapes / 41,524 escape attempts, matches pinned baseline).

### Session — 2026-07-08 04:09 (merged, #64/#65 shipped)

- PR #72 opened, CI caught a real pre-existing bug on first run: `packages/ml/package-lock.json` had been out of sync with `package.json` since the ML package's original commit (months ago) — nothing had ever run `npm ci` in `packages/ml` before this PR's `ml-package`/`build` jobs existed. Fixed by regenerating the lockfile (`21db3e1`), verified clean `npm ci` + typecheck + test + build.
- All 7 checks green (lint, docs-drift, build, ml-package, action-gate-fuzz, eval, Cloudflare Pages). Merged via `gh pr merge --squash --admin` (branch protection required a review approval; user explicitly authorized the bypass) — commit `0d05aaa`.
- #64 auto-closed via the squash commit's "Closes #64, #65" — GitHub only linked #64 (needs the keyword repeated per issue: "closes #64, closes #65"). #65 closed manually with a note.
- Local/remote feature branch deleted, main synced.
- Two follow-ups NOT done here, still open: the unwired eval sample in `samples.ts` (candidate for #69), and the pre-existing `npm audit` findings in vitest's transitive deps (esbuild/postcss/vite) — out of scope for this PR.
- Next up in this track: #66 (CLI + SARIF), the biggest remaining adoption lever.
