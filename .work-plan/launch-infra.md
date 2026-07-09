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
last_touched: 2026-07-09T01:02
last_handoff: 2026-07-09T01:02
next_up: []
blockers:
  - "npmjs.com Trusted Publisher registration for both packages (manual, only Eve can do this)"
  - "GitHub npm-publish Environment required-reviewer rule (manual, repo settings)"
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
| #70 | ci: automated npm publish with provenance via release-please (trusted publishing) | — | ✅ Automation shipped — first live publish not yet proven |

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

### Session — 2026-07-08 22:15 (merged, #67 shipped)

- Pushed one more fix before merging: PR #74's `docs-api` job failed on first CI run — the only diff was in TypeDoc's compressed search/navigation assets (`assets/{hierarchy,navigation,search}.js`), not any actual doc content. Root cause: I'd generated the committed `site/api/` locally under Node v26.4.0, but `ci.yml` runs Node 20 — the compressed blob bytes differ across Node/zlib versions even though the decompressed content is identical. Installed Node 20.20.2 via `nvm`, regenerated, confirmed only those asset files changed, pushed (`471a693`) — `docs-api` went green on re-run. Added a `CONTRIBUTING.md` note (`## API Reference Docs`) so the next contributor doesn't hit the same trap.
- This repo has no `dev` branch (confirmed via CONTRIBUTING.md and `git branch -a`) — feature branches PR directly into `main`, and Cloudflare Pages auto-deploys on merge with no separate promotion step. "Deploy" for this repo is just "merge to main."
- All 7 checks green, merged via `gh pr merge --squash --admin` (branch protection required review approval; user explicitly authorized the bypass a third time) — commit `39b349c`. #67 auto-closed cleanly.
- Verified live post-merge: `https://agentarmor.dev/api/` and `https://agentarmor.dev/api/ml/` both return 200.
- Local/remote feature branch deleted, main synced.
- Next up in this track: #70 (npm provenance) is the only remaining open issue in launch-infra. Separately, issue #24 (enterprise-readiness track) is queued next per user request — the `marywang-aiops` comment on it (event record / evidence package / control claim layering, already captured verbatim in the issue thread) is the design to carry forward when that work starts.

### Session — 2026-07-08 19:53 (branch feat/70-npm-provenance, #70 implemented)

- Implemented #70 per `docs/superpowers/plans/2026-07-09-npm-provenance.md`. Not yet merged.
- **Real scope finding**: `release-please-config.json` only tracked the root package — `packages/ml` wasn't tracked at all, contradicting the issue text's implication both were already covered. Added `packages/ml` as a second monorepo component (own tag scheme `agentarmor-ml-v<version>` via `include-component-in-tag: true` + `component`, verified against release-please's own docs — no collision with root's unprefixed `vX.Y.Z` tags) — necessary for "the ML package publishes independently only when its own version changes."
- **Live-verified npm Trusted Publishing requirements** (not assumed from training data, fetched from npm's current docs): npm CLI ≥11.5.1, Node ≥22.14 in the publish job, `id-token: write` permission, no `NPM_TOKEN` secret, provenance automatic (no `--provenance` flag needed). `npm publish --dry-run` locally confirmed scoped packages still need explicit `--access public` (default access is restricted, provenance being automatic doesn't change that).
- **Design decision made with explicit user input**: the issue's literal acceptance criterion says "no manual step" between merging a release-please PR and npm publish. User chose to add a manual-approval gate (a GitHub Environment `npm-publish` with a required-reviewer protection rule) instead, matching this workspace's standing rule that irreversible actions get a human check — a deliberate, recorded divergence from the issue's literal wording, not an oversight.
- Two new jobs (`publish-core`, `publish-ml`) added to the existing `.github/workflows/release-please.yml` (not a new file) using `needs:`-based per-package release outputs (`'.--release_created'`, `'packages/ml--release_created'`) — verified exact output naming live via release-please-action's own docs. Each re-runs build/typecheck/test(+eval for core) before `npm publish --access public`.
- **This is the first issue this session that can't be fully verified end-to-end** — triggering a real release-please release has real, hard-to-reverse consequences (a real tag, GitHub release, and publish attempt), so nothing safely testable was skipped, but the actual OIDC publish path is genuinely unproven until a real release happens. Validated everything that IS safely checkable: JSON/YAML syntax, and the exact command sequences both publish jobs will run (`typecheck && test:run && eval:gate && build` for core, `typecheck && test && build` for ml) — both pass locally right now.
- **Two manual one-time steps block this from doing anything even after merge**, and only Eve can do them: (1) npmjs.com → Trusted Publisher → GitHub Actions, for both `@stylusnexus/agentarmor` and `@stylusnexus/agentarmor-ml`, workflow filename exactly `release-please.yml`; (2) GitHub → Settings → Environments → `npm-publish` → add a required-reviewer rule. Recorded as `blockers` in this track's frontmatter, not silently left implicit.
- Updated `CONTRIBUTING.md`'s Releases section (committed) and local `CLAUDE.md`'s Publishing section (gitignored, not committed) to describe the new flow — the manual `npm run build && npm publish --access public` fallback is explicitly kept, not deleted, since "retire manual instructions once verified" hasn't been earned yet.
- Next: open the PR with the two manual steps flagged prominently at the top of the description — burying them would be a real usability failure of the PR itself.

### Session — 2026-07-09 01:02 (merged, #70 shipped)

- PR #78 opened, all 7 expected checks green on the first run — `publish-core`/`publish-ml` correctly did not fire (gated on release-please's own `release_created` output, absent on a normal PR), confirming that design assumption held. Merged via `gh pr merge --squash --admin` (user confirmed the bypass) — commit `a59e0ce`. #70 auto-closed cleanly.
- All 5 issues in this track are now GitHub-closed, but the track stays **active, not closed** — the two manual blockers (npmjs.com Trusted Publisher registration for both packages, `npm-publish` Environment required-reviewer rule) are real open work only Eve can do, and the automated publish path is unproven until a real release goes through it. Local/remote feature branch deleted, main synced.
- Next: Eve completes the two manual steps, then the next real release-please PR merge is the actual end-to-end test — watch that first run.
