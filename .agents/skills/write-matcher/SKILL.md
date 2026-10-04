---
name: write-matcher
description: Write an exact linear-time matcher for a slow Agent Armor detection regex. Use when `pattern-time-budget.test.ts` fails on a pattern, when someone edits a regex that has a matcher in src/patterns/matchers/, or when a new pattern needs unbounded lazy or greedy runs.
---

# Write a matcher

Some shipped regexes backtrack badly (#175). Each one has a hand-written matcher in `src/patterns/matchers/` that returns exactly what the regex returns, in linear time. This skill is the recipe for adding or updating one.

Do NOT shorten the regex with length caps or stop-at-next-token rewrites. That was tried and rejected: padding past a cap, or typing the start token inside the payload, evaded detection. The rule is: detection must not change.

## When to use

- `npx vitest run src/__tests__/pattern-time-budget.test.ts` names a pattern that is over budget.
- You edited a regex that already has a matcher. The matcher no longer binds, so the plain regex runs and must pass the speed test by itself, or get a new matcher.
- A new pattern has an unbounded `[^x]*` on both sides of a keyword, a lazy `[\s\S]*?` with no guaranteed closer, or `\s*` after a character that can repeat.

If the pattern can be rewritten to be fast with identical behavior (not by capping), do that instead and skip the rest.

## Steps

1. **Reproduce.** Run the pattern on 20k–200k characters of repeated trigger fragments (its own literal words, its character classes with and without the closing token). Note the shape that stalls.
2. **Derive the exact semantics.** Walk the engine's choices: leftmost start wins; greedy quantifiers try the longest first and back off; lazy ones the shortest; alternation goes in order; `i` without `u` folds ASCII only; `.` excludes `\n \r    `; `\s` includes `﻿` and ` `. Write the result as comments above the matcher: which choice wins and why. Look for the usual reductions: a run that can only end at one place, a start that fails because of what comes after it (so every start before the same closer fails too), a right-to-left choice (greedy `[^>]*` then a keyword tries the last keyword first).
3. **Write the matcher** in `src/patterns/matchers/` (group with a sibling file or add one). Type is `PatternMatcher` in `types.ts`: `regex`, `flags`, `extractGroup`, `match(content)`, `fuzzAtoms`.
   - Copy `regex` exactly from the shipped pattern. Use a plain string for sources containing `\uXXXX` escapes (`String.raw` cooks them in some toolchains).
   - Never rescan the same stretch for many starts. Use `scan-helpers.ts` (`memoizedFinder`, `regexFinder`, `literalFinder`, `runEndFinder`, `PositionIndex`). One finder per alternating run, or they thrash.
   - Each loop must move forward on every pass, match or not.
4. **Register** it in `src/patterns/matchers/index.ts`. The lookup key is regex + flags + extractGroup.
5. **Prove equivalence.** `npx vitest run src/__tests__/matchers-equivalence.test.ts -t <pattern-id>`, then raise it: `FUZZ_CASES=200000 FUZZ_SEED=<n>` on at least 3 seeds, 0 differences. Give `fuzzAtoms` the regex's literals, near-misses, quotes/brackets, line breaks, whitespace, and filler at the `{m,n}` edges. The shared fuzz uses inputs up to about 1,100 characters; if your regex has a bound above that, add an edge test with a body of exactly that length (a missed offset at the 500-character edge once slipped past 200-character inputs).
6. **Prove speed.** `npx vitest run src/__tests__/pattern-time-budget.test.ts`, plus a 1,000,000-character full-scan check on the stalling shape: `AgentArmor.regexOnly({ maxInputLength: Infinity }).scanSync(...)` should take well under half a second.
7. **Gates.** `npx tsc --noEmit`, `npm run test:run`, `npm run eval:gate`, `npm run check:docs`; eval output must be identical to before (`npx tsx scripts/eval/run-eval.ts`).
8. **Independent review.** Have someone or something other than the author attack the change: a second agent or a reviewer. They should fuzz old vs new regex on large inputs, compare full `scanSync` results on payloads with padding and nested start tokens, and sweep 1,000,000-character speed over all patterns. A human approves every pattern change: this is security code.

## Pitfalls

- `exec` loops on a global regex reset `lastIndex` to 0 when a sticky check fails; read the result, never reuse a stale `lastIndex`.
- A start inside the same run as a failed start usually fails the same way: jump to the end of the run instead of retrying each position.
- Lookup tables over the whole input are fine (linear), but build them lazily, once per `match()` call.
- Editing the regex source later drops the matcher silently. The speed test is what catches it.

## Done when

Fuzz shows 0 differences on 3+ seeds, the speed test passes, eval output is identical, the independent review has no findings, and a human has approved the PR.
