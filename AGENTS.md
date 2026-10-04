# AGENTS.md

Instructions for AI coding agents working in this repo. Humans: see [CONTRIBUTING.md](CONTRIBUTING.md).

## What this is

Agent Armor (`@stylusnexus/agentarmor`) is an open-source TypeScript library that detects AI Agent Traps in text an agent reads (the Google DeepMind taxonomy, Franklin et al., 2026). A scan runs detectors over the content and returns threats, a risk level and sanitized text. Node >= 18, MIT.

## Commands

```bash
npm run typecheck      # tsc --noEmit
npm run lint           # eslint src/
npm run test:run       # vitest, all tests
npm run build          # tsup (CJS + ESM + types)
npm run eval:gate      # detection and false-positive floors (scripts/eval/thresholds.json)
npm run check:docs     # README counts match the eval output
npx tsx scripts/eval/run-eval.ts   # full eval report
```

The ML companion package is in `packages/ml/` with its own `npm run build|test|typecheck`.

## Layout

- `src/agent-armor.ts`: the `AgentArmor` class and scan pipeline.
- `src/detectors/`: detectors. `pattern-detector.ts` runs the pattern database.
- `src/patterns/default-patterns.ts`: the shipped detection rules (regex strings, versioned, remotely updatable).
- `src/patterns/matchers/`: hand-written exact matchers for regexes that backtrack badly (see below).
- `scripts/eval/`: eval samples (adversarial and benign) and the committed gate floors.
- `site/`: the website; `site/api/` is generated TypeDoc output.

## Rules that are easy to break

- **Detection must not change by accident.** Run `npm run eval:gate` for any change to patterns, detectors or thresholds. Never lower a floor in `thresholds.json` or add a benign exemption to make a change pass.
- **Keep scan time linear.** `src/__tests__/pattern-time-budget.test.ts` runs every pattern against 200,000 characters of adversarial input and fails any that takes over a second. Do not "fix" a slow regex with length caps or stop-at-next-token rewrites: padding or a nested token then evades detection. Write an exact matcher instead, following `.agents/skills/write-matcher/SKILL.md`.
- **Editing a regex that has a matcher drops the matcher** (the binding is the exact regex source, flags and extract group). The new regex must pass the speed test on its own, or get a new matcher with `src/__tests__/matchers-equivalence.test.ts` passing.
- **Scans fail closed.** Input over `maxInputLength` (default 1,000,000 characters) is not scanned and returns a not-clean result.
- **Pattern changes need review.** This is security code: have a human review every pattern or matcher change, and an independent adversarial check where you can.
- **Add benign and adversarial eval samples** for any new detection, in `scripts/eval/samples.ts`.

## Git and releases

- Branch from `dev`; open PRs against `dev`; squash-merge once CI passes. `dev` goes to `main` with a merge commit.
- Conventional commits: `type(scope): imperative summary`, lowercase, 50 characters or fewer, no period. Reference issues as `Fixes #123` on its own line.
- Do not edit `CHANGELOG.md`: release-please generates it from commit messages.
- Do not publish to npm by hand: merging the release PR publishes through CI.
- `site/api/` is checked in CI (`docs-api`). If it goes stale, apply the diff from the failed job's log rather than regenerating on macOS (output differs from CI).

## Docs

When a feature or option changes, update `README.md` and the relevant docs in the same PR. Keep eval counts in the README in sync (`npm run check:docs`).

## Skills

Task recipes live in `.agents/skills/`:

- `write-matcher`: write an exact linear-time matcher for a slow detection regex.
