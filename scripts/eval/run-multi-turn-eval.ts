/**
 * Agent Armor Multi-Turn Evaluation (#35)
 *
 * Scores attacks distributed across conversation turns against two views of the
 * real product (AgentArmor.scanSession), at each strictness level —
 *
 *   - fast view:     scanSession's per-turn results (each turn on its own)
 *   - stateful view: scanSession's cross-turn threats (Phase 1 window — catches
 *                    payloads split across a turn boundary)
 *
 * and classifies each adversarial conversation as caught per-turn, caught only
 * cumulatively (cross-turn window), or a blind-spot (invisible to both). The
 * blind-spot count is the surface Phase 2 (signal accumulation) must close.
 *
 * The run FAILS when detection regresses below each sample's committed
 * `expectedToday` prediction: a benign false positive, or an adversarial sample
 * that slid to a worse class than recorded. Standing blind-spots that match
 * their prediction are the remaining target, not a failure. Improvements never
 * fail but are surfaced so the prediction can be tightened to lock the gain in.
 *
 * Usage: npx tsx scripts/eval/run-multi-turn-eval.ts
 */

import { AgentArmor } from '../../src/agent-armor';
import {
  MULTI_TURN_SAMPLES,
  type ExpectedToday,
  type MultiTurnSample,
} from './multi-turn-samples';
import type { Strictness } from '../../src/types';

type AdversarialClass = 'per-turn' | 'cumulative' | 'blind-spot';
type BenignClass = 'clean' | 'false-positive';

interface SampleOutcome {
  sample: MultiTurnSample;
  actual: ExpectedToday;
  /** Which view(s) produced detection — for reporting. */
  perTurnHit: boolean;
  cumulativeHit: boolean;
  /** Did the actual classification match the committed prediction? */
  matchesPrediction: boolean;
  /** Actual is strictly WORSE than the committed prediction (detection lost). */
  regressed: boolean;
  /** Actual is strictly BETTER than the committed prediction (detection gained). */
  improved: boolean;
}

/**
 * Detection "badness" ordering, worst-highest. A higher actual rank than the
 * committed prediction means detection was lost (a regression); a lower rank
 * means detection was gained (lock it in by updating the prediction).
 */
const SEVERITY: Record<ExpectedToday, number> = {
  clean: 0,
  'per-turn': 1,
  cumulative: 2,
  'blind-spot': 3,
};

/** Detection counts as a "hit" for an adversarial sample only on an expected
 * trap type; for a benign sample, ANY threat is a (false) hit. */
function threatsHit(
  threats: { type: string }[],
  sample: MultiTurnSample
): boolean {
  if (sample.category === 'benign') return threats.length > 0;
  return threats.some((t) =>
    (sample.expected as string[]).includes(t.type)
  );
}

function classify(strictness: Strictness): SampleOutcome[] {
  // Accumulation is opt-in; the harness enables it so Phase 2 is exercised.
  const armor = new AgentArmor({
    strictness,
    session: { accumulation: true },
  });
  return MULTI_TURN_SAMPLES.map((sample) => {
    // Both views come from the real product: scanSession's per-turn results
    // (fast view) and its cross-turn window threats (stateful view, Phase 1).
    const session = armor.scanSession(sample.turns);
    const perTurnHit = session.turns.some((turn) =>
      threatsHit(turn.threats, sample)
    );
    const cumulativeHit = threatsHit(session.crossTurnThreats, sample);

    if (sample.category === 'benign') {
      // Benign conversations must stay clean in both views. Any hit is a false
      // positive, treated as a regression (hard failure) below.
      const fp = perTurnHit || cumulativeHit;
      return {
        sample,
        actual: 'clean',
        perTurnHit,
        cumulativeHit,
        matchesPrediction: !fp,
        regressed: fp,
        improved: false,
      };
    }

    let actual: AdversarialClass;
    if (perTurnHit) actual = 'per-turn';
    else if (cumulativeHit) actual = 'cumulative';
    else actual = 'blind-spot';

    const delta = SEVERITY[actual] - SEVERITY[sample.expectedToday];
    return {
      sample,
      actual,
      perTurnHit,
      cumulativeHit,
      matchesPrediction: actual === sample.expectedToday,
      regressed: delta > 0, // detection lost relative to committed prediction
      improved: delta < 0, // detection gained — update the prediction to lock it
    };
  });
}

function printReport(strictness: Strictness, outcomes: SampleOutcome[]): {
  regressions: SampleOutcome[];
  improvements: SampleOutcome[];
} {
  console.log('\n' + '='.repeat(74));
  console.log(`  MULTI-TURN EVAL — strictness: ${strictness}`);
  console.log('='.repeat(74));

  const adversarial = outcomes.filter((o) => o.sample.category === 'adversarial');
  const benign = outcomes.filter((o) => o.sample.category === 'benign');

  const counts: Record<AdversarialClass, number> = {
    'per-turn': 0,
    cumulative: 0,
    'blind-spot': 0,
  };
  for (const o of adversarial) counts[o.actual as AdversarialClass]++;

  console.log('\n  ── Adversarial conversations ──');
  for (const o of adversarial) {
    let drift = '';
    if (o.regressed) drift = `  REGRESSED (predicted ${o.sample.expectedToday})`;
    else if (o.improved) drift = `  improved (predicted ${o.sample.expectedToday})`;
    console.log(
      `  ${o.sample.id.padEnd(14)} ${o.actual.padEnd(11)} ${o.sample.description}${drift}`
    );
  }

  console.log('\n  ── Benign conversations ──');
  for (const o of benign) {
    const view = o.perTurnHit
      ? 'per-turn FP'
      : o.cumulativeHit
        ? 'cumulative FP'
        : 'clean';
    console.log(`  ${o.sample.id.padEnd(14)} ${view.padEnd(13)} ${o.sample.description}`);
  }

  const regressions = outcomes.filter((o) => o.regressed);
  const improvements = outcomes.filter((o) => o.improved);
  const total = adversarial.length;
  const fastBlindSpot = counts.cumulative + counts['blind-spot'];
  console.log('\n  ── Gap summary ──');
  console.log(`  Caught per-turn (fast view sees it):  ${counts['per-turn']}/${total}`);
  console.log(`  Caught only cumulatively:             ${counts.cumulative}/${total}`);
  console.log(`  Blind-spot (#35 target):              ${counts['blind-spot']}/${total}`);
  console.log(
    `  Fast-test blind spot (cumulative+blind): ${fastBlindSpot}/${total} ` +
      `— invisible to per-turn scanning`
  );

  return { regressions, improvements };
}

// ─── Run ──────────────────────────────────────────────────────────────────────

// A run fails if detection got WORSE than the committed prediction in any
// conversation — a benign false positive, or an adversarial sample that slid to
// a worse class (e.g. a phrase that used to be caught per-turn now slips to
// blind-spot). Standing blind-spots that match their committed prediction are
// the #35 surface, not a failure. Improvements never fail, but are surfaced so
// the prediction can be tightened to lock the gain in.
const allRegressions: SampleOutcome[] = [];
const allImprovements: SampleOutcome[] = [];
for (const strictness of ['balanced', 'strict'] as const) {
  const outcomes = classify(strictness);
  const { regressions, improvements } = printReport(strictness, outcomes);
  allRegressions.push(...regressions);
  allImprovements.push(...improvements);
}

console.log('\n' + '='.repeat(74));
if (allImprovements.length > 0) {
  console.log('  NOTE: detection improved beyond the committed prediction for:');
  for (const o of allImprovements) {
    console.log(
      `    ${o.sample.id}: now ${o.actual} (predicted ${o.sample.expectedToday}) — update expectedToday to lock it in`
    );
  }
  console.log('');
}
if (allRegressions.length > 0) {
  console.log('  VERDICT: FAIL — detection regressed below the committed prediction:');
  for (const o of allRegressions) {
    const what =
      o.sample.category === 'benign'
        ? 'benign conversation flagged (false positive)'
        : `slipped to ${o.actual} (predicted ${o.sample.expectedToday})`;
    console.log(`    ${o.sample.id}: ${what} — ${o.sample.description}`);
  }
  console.log('\n  If a slide is intentional, update expectedToday in');
  console.log('  multi-turn-samples.ts in this same PR so the change is reviewed.');
  console.log('='.repeat(74) + '\n');
  process.exit(1);
}
console.log('  VERDICT: no regressions. Standing adversarial blind-spots above are the');
console.log('  surface for #35 (session-aware detection) — informational, not a gate.');
console.log('='.repeat(74) + '\n');
