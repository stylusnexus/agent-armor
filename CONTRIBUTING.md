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

- Create a feature branch from `dev` (`git checkout -b feat/my-feature origin/dev`)
- Make your changes
- Open a PR against `dev` and squash-merge it once CI passes
- To ship, open a PR from `dev` to `main` and merge it with a **merge commit** (not squash), so release-please sees each feature's commit
- After the release PR merges and publishes, merge `main` back into `dev`
- Use conventional commit messages (see below)

## Adding New Patterns

- Edit `src/patterns/default-patterns.ts`
- Run the eval suite to verify no regressions: `npx tsx scripts/eval/run-eval.ts`
- Include both adversarial and benign test cases when relevant
- Keep scan time linear. `npm run test:run` runs every pattern against 200,000 characters of repeated trigger fragments and fails any that takes over a second. Avoid unbounded `[^x]*` runs on both sides of a keyword, lazy `[\s\S]*?` with no guaranteed closer, and `\s*` after a character that can repeat. If a pattern can't be written to pass, add a hand-written matcher in `src/patterns/matchers/` bound to the pattern's exact regex (see `types.ts`); `matchers-equivalence.test.ts` fuzzes it against the regex. Editing a regex that has a matcher drops the matcher, so the new regex must pass the speed test on its own

## Adding Eval Samples

- Edit `scripts/eval/samples.ts`
- Include both adversarial and benign cases
- Each sample needs a clear label and expected detection result

## Adding Detectors

- Implement the `Detector` interface defined in `src/types/index.ts`
- Register your detector in `AgentArmor`
- Add a test file for the detector, `src/__tests__/<detector-id>.test.ts`, and eval samples. Run the detector alone with `soloDetector(id)` from `src/__tests__/helpers/solo-detector.ts` (add your detector to the helper's `SOLO_FLAGS`). Cover payloads flagged as the detector's own type, benign near-misses that stay clean, sanitize output, and the detector turned off with `withoutDetector(id)`. See `hidden-html.test.ts` for the shape.

## Code Style

- TypeScript strict mode
- Prettier for formatting: the rules are in `.prettierrc.json` (single quotes, 100 columns). Run `npm run format -- <files>` on files you change, and `npm run format:check` before you push. CI runs the check. To make local `git blame` skip the one-off reformat, run `git config blame.ignoreRevsFile .git-blame-ignore-revs`.
- No unnecessary dependencies
- Keep imports explicit

## Testing

- **Unit tests:** `npm run test:run`
- **Eval suite:** `npx tsx scripts/eval/run-eval.ts`

Run both before submitting a PR.

### Checking the reference-image scan against a real renderer

The reference-image scan (`![alt][r]` plus a definition whose URL carries a data keyword) has two fuzz tests that render generated documents with `markdown-it` (HTML off and on) and fail if an image the renderer draws is not flagged:

- `src/__tests__/markdown-reference-oracle.test.ts` mixes random fragments of block and inline syntax. Extend the lists near the top (`STARTS`, `ATOMS`, `IMAGES`, `DEFINITIONS`).
- `src/__tests__/markdown-reference-family-fuzz.test.ts` builds each document from one named construct family and wraps it in nested quotes and list items. Add a family to `families()`.

Both take `ORACLE_CASES` / `FUZZ_CASES` for a bigger batch (for example `FUZZ_CASES=100000`), and the family fuzz takes `FUZZ_SEED`. A new generator is only worth trusting once it finds misses in an older version of the scan, so check that before relying on a clean run. If one finds a miss, open an issue with the smallest failing document.

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

Every ML command needs `KMP_DUPLICATE_LIB_OK=TRUE` on Apple Silicon. The data pipeline, in order:

```bash
python3 -m ml.data.seed_from_eval          # eval samples -> seed.jsonl (validation only)
python3 -m ml.data.generate_synthetic      # templated attacks, including the recent shapes
python3 -m ml.data.generate_hard_negatives # honest text that uses attack vocabulary
python3 -m ml.data.generate_fresh_attacks  # fresh attacks (training) and the held-out set
python3 -m ml.data.generate_zh_attacks     # Chinese attacks (training); honest Chinese is in benign_triggers_zh.jsonl
python3 -m ml.data.validate                # dedupe and split into train, val, test
```

- **Honest samples** live in `ml/data/benign_corpus.py` and `ml/data/generate_hard_negatives.py`. Add honest text that shares an attack's wording (setup guides, runbooks, bans, advisories). A classifier trained on few honest samples flags almost everything.
- **Honest text with trigger words** (`ml/data/benign_triggers*.jsonl`, #275): honest sentences that contain words a classifier over-reacts to, written from scratch, in English, Chinese and a formal imperative register. Add drafts with `python3 -m ml.data.build_benign_triggers --drafts DIR --out benign_triggers_NAME.jsonl --notinject FILE.parquet`, which drops drafts close to the held-out attacks, the eval suite, NotInject or the training data. NotInject (MIT) is for evaluation only: never copy its prompts or phrasing into training data, and do not paste its examples into prompts for people or agents who write training text.
- **Attack samples** live in `ml/data/fresh_attacks.py` and `ml/data/generate_synthetic.py`. Write them in your own words; copy nothing from a source with a restrictive license. Name the source in the description when a sample paraphrases a public write-up.
- **The held-out set** (`HOLDOUT_*` in `ml/data/fresh_attacks.py`) is never written to the training files. Do not move samples from it into training: it is the only measurement of generalization. Add new held-out samples, not training ones, when you want a stricter test. The Chinese held-out attacks are in `ml/data/holdout/holdout_zh_attacks.jsonl`.
- **Scoring a model:** `python3 -m ml.train.evaluate_holdout [--model-dir DIR]` reports detection and false flags on sets the model was not trained on, plus a ranking number (AUC) that does not depend on the threshold. Compare models with that, not with the test-set F1: the test set is re-shuffled whenever the data changes, so an older model may have trained on rows that are now in it.
- **Label order is fixed** (`LABELS` in `packages/ml/src/constants.ts`). Reordering or adding a label changes what every output means and fails `npm run check:model`. A trap type outside the 13 labels (credential exposure, steganographic payload, dependency substitution) is skipped when seeding, not labelled benign.
- Retraining and publishing the model is a maintainer step: see the `retrain` skill in `.agents/skills/agent-armor-tools/`.

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

1. Every PR promoted from `dev` to `main` with a Conventional Commit title (`feat:`, `fix:`, etc.) gets picked up by release-please.
2. release-please maintains a standing "release PR" per package (root `@stylusnexus/agentarmor` and `packages/ml`'s `@stylusnexus/agentarmor-ml`, versioned and tagged independently) that accumulates changelog entries and the next version bump.
3. Merging a release PR tags the release and creates a GitHub release, which triggers that package's publish job.
4. The publish job re-runs build/typecheck/test (and the eval gate, for the core package) as a defense-in-depth check, then waits for a manual approval in the `npm-publish` GitHub Environment before running `npm publish --access public`.
5. Publishing uses npm Trusted Publishing (OIDC) — no `NPM_TOKEN` secret exists in this repo. Provenance is generated automatically.

**One-time setup** (already done if you're reading this after #70 shipped — documented here for anyone re-provisioning the repo):

- On npmjs.com, for each package (`@stylusnexus/agentarmor`, `@stylusnexus/agentarmor-ml`): Settings → Trusted Publisher → GitHub Actions → Organization `stylusnexus`, Repository `agent-armor`, Workflow filename `release-please.yml`, Allowed actions: npm publish.
- On GitHub: Settings → Environments → `npm-publish` → add a required-reviewer protection rule.

**CHANGELOG.md is bot-managed** — never hand-edit it (see the file's own header comment). Write good Conventional Commit titles instead.

### Model integrity (ML package)

`packages/ml` pins the model's SHA-256 in `MODEL_CHECKSUM` (`src/constants.ts`) and enforces it on download. That constant is maintained by hand during the model-update lifecycle, so a check confirms it still matches the artifacts hosted on HuggingFace:

```bash
cd packages/ml
npm run check:model        # fast — reads HuggingFace LFS metadata, ~1s
npm run check:model:deep   # downloads and hashes the real bytes, ~5s
```

It verifies the model digest, that every required file is present and non-empty, that `tokenizer.json` isn't truncated, and that the hosted `label_map.json` matches `LABELS` **index for index** — the model emits one sigmoid output per index, so a reordered label space would mislabel everything while still looking healthy.

It runs weekly (`.github/workflows/model-integrity.yml`), on any PR touching `packages/ml/src/constants.ts` or `packages/ml/scripts/`, and as a blocking step in the `publish-ml` job. **If you update the model, run it before opening the PR** — otherwise the publish job will stop the release.

No secrets required; the HuggingFace repo is public and access is read-only.

If the automated publish is ever unavailable (e.g. before the one-time setup above is complete), fall back to a manual publish: `npm run build && npm publish --access public` from a clean `main` checkout, run once per package that needs it.

Pre-1.0 bump policy: a breaking change (`feat!:` / `BREAKING CHANGE:`) bumps the **minor** version; `feat:`/`fix:` bump the **patch** version.
