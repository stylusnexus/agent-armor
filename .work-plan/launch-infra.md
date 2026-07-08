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
  branches: [feat/67-api-reference]
depends_on: []
last_touched: 2026-07-08T10:14
last_handoff: 2026-07-08T10:14
next_up:
  - 70
blockers: []
---
# Launch Infra & Adoption

Pre-launch credibility polish (CI gates the security fuzz test doesn't run yet, README/site drift) plus the biggest adoption lever identified in the 2026-07-07 backlog grooming: a CLI with SARIF output for CI/pre-commit integration. Also covers generated API docs and automated npm publishing.

## Issues

| # | Title | Assignee | Status |
|---|---|---|---|
| #64 | ci: run action-gate fuzz, lint, ML package tests, and build in CI | — | ✅ Shipped |
| #65 | chore(docs): fix README/site drift and add a doc-consistency gate to CI | — | ✅ Shipped |
| #66 | feat: agentarmor CLI with JSON/SARIF output for CI scanning | — | ✅ Shipped |
| #67 | docs: generated API reference (TypeDoc) published to agentarmor.dev | — | ✅ Shipped |
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

### Session — 2026-07-08 00:33 (branch feat/66-cli-sarif, #66 implemented)

- Implemented #66 per `docs/superpowers/plans/2026-07-08-cli-sarif.md`. Not yet merged.
- New `agentarmor` bin (`src/cli.ts` + `src/cli/{args,discover-files,formatters,scan-command,severity}.ts`): `agentarmor scan <path...> [--strictness] [--format text|json|sarif] [--fail-on] [--ml] [--include]`. Zero new runtime dependencies (hand-rolled arg parsing, matching `packages/ml/src/cli.ts`'s existing style).
- Scope decision: SARIF rule id uses `Threat.detectorId` (e.g. `hidden-html`, `exfiltration`), not per-pattern-id as the issue text suggested — `PatternEntry.id` (e.g. `hh-display-none`) is never propagated onto `Threat` today (verified in `src/detectors/base.ts`/`pattern-detector.ts`); threading it through is a separate, higher-risk core-type change. `detectorId` still fully satisfies the acceptance criteria.
- `--fail-on` reuses `ScanResult.riskLevel` (the #34 roll-up) instead of re-deriving severity — avoids duplicating SDK logic.
- Real bugs found and fixed along the way: (1) duplicate shebang broke the built `dist/cli.js` (source had one, tsup's banner config added another — fixed by removing the source one, matching `packages/ml`'s pattern); (2) root `tsconfig.json` never had `types: ["node"]` since nothing under `src/` used Node builtins before `discover-files.ts` — added; (3) README's ML Classifier section claimed `onUnavailable` defaults to `'throw'`, but the real default (and this branch's live `--ml` verification) is `'warn-and-skip'` — fixed.
- 43 new tests (180 total, up from 137), all passing; lint/typecheck/build all clean.
- Full manual E2E verification against the built binary: `--help`, clean scan (exit 0), poisoned scan naming threat+detector+evidence (exit 1), directory recursion, JSON format, SARIF structural validity (`resultCount`/`ruleCount` confirmed), `--fail-on critical` threshold behavior, `--ml` graceful degradation when the ML package isn't installed (SDK's own warn-and-skip fired correctly), and no-config `npx`-style invocation from a directory with nothing in it.
- Also updated local (gitignored) `CLAUDE.md`: its "Documentation upkeep" section told future sessions to hand-edit `CHANGELOG.md` "until automation lands" — release-please (#41) already shipped that automation weeks ago; corrected to say never hand-edit it.
- Skipped the plan's CHANGELOG.md step entirely for the same reason — the file is bot-managed, hand-editing would fight release-please.
- Next up in this track: #67 (API reference) and #70 (npm provenance) — both P1, no dependency between them.

### Session — 2026-07-08 14:50 (merged, #66 shipped)

- PR #73 opened, all 7 checks green on the first run (no repeat of #72's lockfile surprise). Merged via `gh pr merge --squash --admin` (branch protection required review approval; user explicitly authorized the bypass again) — commit `5331e14`. #66 auto-closed cleanly (single issue ref this time, unlike #72's comma-list keyword-parsing gap).
- Local/remote feature branch deleted, main synced.
- **Security note, not code-related:** a comment appeared on PR #73 recommending `pip install vulnledger` for SBOM generation. Investigated (read-only OSINT only — nothing installed/executed): the PyPI package (published by "akuma-creator" 2026-06-28, single alpha version, zero download stats) lists its source at `github.com/AKUMA-creator-ng/Vulnledger`, which returns 404 — the account and repo don't exist. The GitHub comment itself isn't visible via the REST or GraphQL API (checked both issue-comments and PR-review-comments endpoints, including minimized/hidden ones) — already removed, or arrived via a non-GitHub channel. Separately, there IS a real, unrelated `raymond-itsec/vulnledger` project on GitHub (account created 2018, small footprint — 1 star, 0 forks, 56 open issues, actively pushed) with no evident PyPI publishing under that name — likely just a name collision the impostor package benefits from, not the same project. Recommended not installing the PyPI package; nothing added to the repo as a result of this.

### Session — 2026-07-08 10:14 (branch feat/67-api-reference, #67 implemented)

- Implemented #67 per `docs/superpowers/plans/2026-07-08-api-reference.md`. Not yet merged.
- TypeDoc (0.28.20, confirmed live compatible with this project's TypeScript 6.0.2 via its own peerDependencies range) set up as two independent invocations — root package → `site/api/`, ML package → `site/api/ml/` — each using its own tsconfig, avoiding cross-package conflicts. `npm run docs:build` (root), `packages/ml`'s own `docs:build`, and a new root `docs:build:all` orchestrator. Zero new runtime dependencies (devDependency only, both packages).
- All 7 originally-flagged exports from the issue (`evaluateAction`, `matchGlob`, `globToRegExp`, `PatternDetector`, `BaseDetector`, `PatternEntry`/`PatternDatabase`, `DEFAULT_PATTERNS`) confirmed present in the generated reference.
- Scope decision: "every export has a description" scoped to top-level exported symbols, not every nested inline `__type` sub-property — verified live via `typedoc --validation.notDocumented true` (84 warnings on the root package; ~62 were `AgentArmorConfig`'s per-toggle booleans and a few `stats`/`location` inline shapes, out of scope; ~20 were genuine top-level interfaces/type-aliases with zero doc comment, all fixed). Same pattern in `packages/ml` (21 warnings; 5 genuinely fixable — `AgentArmorModelError`, `MLDetector`, `ModelArtifacts` — the rest are module-private structural-typing shadows, intentionally not exported).
- Scope decision: "regeneration is automatic" implemented as a CI freshness gate (`docs-api` job in `ci.yml`, regenerates + `git diff --exit-code`s `site/api`), not an auto-committing bot — no bot-token/write-permission setup exists in this repo. Mirrors `check:docs`'s (#65) existing gate-don't-mutate philosophy.
- **Real bug found and fixed:** TypeDoc embeds the current git commit SHA into every "Defined in" source link by default. That would have made the freshness gate perpetually red — every future commit changes every doc page's source links regardless of whether that file's exports changed, a chicken-and-egg problem for committed-output-plus-diff-gate. Fixed by pinning `gitRevision: "main"` in both `typedoc.json` configs; verified true determinism (two consecutive regenerations produce byte-identical output) before wiring the CI gate on it.
- Added ~35 TSDoc comments total across `src/types/index.ts` (20 symbols) and `packages/ml/src/{errors,model-manager,ml-detector}.ts` (5 symbols) — all doc-comment-only, no signature changes.
- Linked from README's top badge line, `site/llms.txt`, and `site/index.html`'s nav (the last one beyond the issue's literal ask, but cheap and directly serves "reachable from agentarmor.dev" for a human visitor, not just the URL existing).
- Full verification: typecheck/lint/test (180/180 root, 12/12 ml) clean, both builds clean, `docs:build:all` regeneration byte-identical to committed output, spot-checked generated HTML contains both `AgentArmorConfig` and `MLDetector` with their new descriptions rendered, `eval:gate` unaffected (this branch touched no detector logic).
- Next up in this track: #70 (npm provenance) — the last open issue in launch-infra.
