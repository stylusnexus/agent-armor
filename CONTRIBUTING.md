# Contributing to Agent Armor

Thanks for your interest in making AI agents safer. Here's how to get started.

## Prerequisites

- Node.js >= 18
- npm
- Python 3.11+ (only if working on the ML pipeline)

## Setup

```bash
git clone https://github.com/stylusnexus/agent-armor.git
cd agent-armor
npm install
npm run build
npm run test:run
```

## Development Workflow

- Create a feature branch from `main` (`git checkout -b feat/my-feature`)
- Make your changes
- Open a PR against `main`
- Use conventional commit messages (see below)

## Adding New Patterns

- Edit `src/patterns/default-patterns.ts`
- Run the eval suite to verify no regressions: `npx tsx scripts/eval/run-eval.ts`
- Include both adversarial and benign test cases when relevant

## Adding Eval Samples

- Edit `scripts/eval/samples.ts`
- Include both adversarial and benign cases
- Each sample needs a clear label and expected detection result

## Adding Detectors

- Implement the `Detector` interface defined in `src/types/index.ts`
- Register your detector in `AgentArmor`
- Add unit tests and eval samples covering your detector

## Code Style

- TypeScript strict mode
- Prettier for formatting
- No unnecessary dependencies
- Keep imports explicit

## Testing

- **Unit tests:** `npm run test:run`
- **Eval suite:** `npx tsx scripts/eval/run-eval.ts`

Run both before submitting a PR.

## API Reference Docs

If your change adds, removes, or edits a public export in `src/index.ts` or `packages/ml/src/index.ts`, regenerate the API reference and commit the result:

```bash
npm run docs:build:all
```

**Use Node 20 to regenerate**, matching CI (`ci.yml`'s `docs-api` job runs on Node 20). TypeDoc's compressed search/navigation assets (`site/api/**/assets/{hierarchy,navigation,search}.js`) can come out byte-different on other Node versions even when the documented content is identical — that mismatch will fail the `docs-api` freshness gate even though nothing is actually stale. If you use `nvm`, `nvm use 20` before running the command above.

`docs-api` in CI regenerates the docs and fails the build if `site/api/` doesn't match what's committed — the error message names the exact command to run.

## ML Pipeline (Optional)

For contributors working on the ML-based detectors:

```bash
pip install -r requirements-ml.txt
```

- Training data generation scripts live in `ml/`
- See `ml/` for model training and export workflows

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` -- new feature
- `fix:` -- bug fix
- `docs:` -- documentation only
- `chore:` -- maintenance, deps, CI
- `feat!:` -- breaking change

These titles feed the changelog automation below, so write them as the user-facing summary of the change.

## Releases

Releases are automated end-to-end via [release-please](https://github.com/googleapis/release-please):

1. Every PR merged to `main` with a Conventional Commit title (`feat:`, `fix:`, etc.) gets picked up by release-please.
2. release-please maintains a standing "release PR" per package (root `@stylusnexus/agentarmor` and `packages/ml`'s `@stylusnexus/agentarmor-ml`, versioned and tagged independently) that accumulates changelog entries and the next version bump.
3. Merging a release PR tags the release and creates a GitHub release, which triggers that package's publish job.
4. The publish job re-runs build/typecheck/test (and the eval gate, for the core package) as a defense-in-depth check, then waits for a manual approval in the `npm-publish` GitHub Environment before running `npm publish --access public`.
5. Publishing uses npm Trusted Publishing (OIDC) — no `NPM_TOKEN` secret exists in this repo. Provenance is generated automatically.

**One-time setup** (already done if you're reading this after #70 shipped — documented here for anyone re-provisioning the repo):

- On npmjs.com, for each package (`@stylusnexus/agentarmor`, `@stylusnexus/agentarmor-ml`): Settings → Trusted Publisher → GitHub Actions → Organization `stylusnexus`, Repository `agent-armor`, Workflow filename `release-please.yml`, Allowed actions: npm publish.
- On GitHub: Settings → Environments → `npm-publish` → add a required-reviewer protection rule.

**CHANGELOG.md is bot-managed** — never hand-edit it (see the file's own header comment). Write good Conventional Commit titles instead.

If the automated publish is ever unavailable (e.g. before the one-time setup above is complete), fall back to a manual publish: `npm run build && npm publish --access public` from a clean `main` checkout, run once per package that needs it.

Pre-1.0 bump policy: a breaking change (`feat!:` / `BREAKING CHANGE:`) bumps the **minor** version; `feat:`/`fix:` bump the **patch** version.
