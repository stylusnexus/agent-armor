/**
 * Agent Armor Evaluation Suite
 *
 * Tests all detectors against curated adversarial + benign samples.
 * Outputs per-category detection rate, false positive rate, and
 * confidence calibration.
 *
 * Usage: npx tsx scripts/eval/run-eval.ts
 */

import { readFileSync } from 'node:fs';
import { AgentArmor } from '../../src/agent-armor';
import {
  ALL_SAMPLES,
  ADVERSARIAL_SAMPLES,
  BENIGN_SAMPLES,
  type EvalSample,
} from './samples';
import type { Strictness, TrapType } from '../../src/types';

interface DetectionResult {
  sample: EvalSample;
  detected: TrapType[];
  truePositives: TrapType[];
  falseNegatives: TrapType[];
  falsePositives: TrapType[];
  correct: boolean;
  highestConfidence: number;
  highestSeverity: string | null;
}

function evaluate(
  strictness: Strictness
): { results: DetectionResult[]; summary: Summary } {
  const armor = new AgentArmor({ strictness });
  const results: DetectionResult[] = [];

  for (const sample of ALL_SAMPLES) {
    const scanResult = armor.scanSync(sample.content);
    const detected = [
      ...new Set(scanResult.threats.map((t) => t.type)),
    ] as TrapType[];

    const truePositives = sample.expected.filter((e) =>
      detected.includes(e)
    );
    const falseNegatives = sample.expected.filter(
      (e) => !detected.includes(e)
    );
    const falsePositives = detected.filter(
      (d) => !sample.expected.includes(d)
    );

    const correct =
      falseNegatives.length === 0 && falsePositives.length === 0;

    results.push({
      sample,
      detected,
      truePositives,
      falseNegatives,
      falsePositives,
      correct,
      highestConfidence: scanResult.threats[0]?.confidence ?? 0,
      highestSeverity: scanResult.stats.highestSeverity,
    });
  }

  return { results, summary: computeSummary(results) };
}

interface CategoryStats {
  total: number;
  detected: number;
  missed: number;
  rate: number;
}

interface Summary {
  strictness: Strictness;
  totalSamples: number;
  adversarialSamples: number;
  benignSamples: number;
  overallDetectionRate: number;
  overallFalsePositiveRate: number;
  byCategory: Record<string, CategoryStats>;
  byDifficulty: Record<string, CategoryStats>;
  falsePositiveDetails: Array<{
    id: string;
    description: string;
    falseTypes: TrapType[];
  }>;
  falseNegativeDetails: Array<{
    id: string;
    description: string;
    missedTypes: TrapType[];
  }>;
  avgConfidenceTruePositive: number;
  avgConfidenceFalsePositive: number;
}

function computeSummary(results: DetectionResult[]): Summary {
  const adversarial = results.filter(
    (r) => r.sample.category === 'adversarial'
  );
  const benign = results.filter((r) => r.sample.category === 'benign');

  // Detection rate: what fraction of adversarial samples had at least 1 TP.
  // KNOWN LIMITATION: a multi-label sample counts as detected the moment ANY
  // one expected trap type fires, so a single detector regressing to zero on a
  // multi-label sample would not move this aggregate. This is the existing
  // definition of the published headline rate; the gate inherits it rather than
  // silently redefining it. Per-trap-type rates are in `byCategory` below; a
  // future per-label floor could gate those directly.
  const detected = adversarial.filter((r) => r.truePositives.length > 0);
  const overallDetectionRate = detected.length / adversarial.length;

  // False positive rate: what fraction of benign samples had any detection
  const falsePositiveBenign = benign.filter(
    (r) => r.detected.length > 0
  );
  const overallFalsePositiveRate =
    falsePositiveBenign.length / benign.length;

  // By trap type category
  const byCategory: Record<string, CategoryStats> = {};
  const trapTypes = [
    ...new Set(adversarial.flatMap((r) => r.sample.expected)),
  ];
  for (const trapType of trapTypes) {
    const relevant = adversarial.filter((r) =>
      r.sample.expected.includes(trapType)
    );
    const found = relevant.filter((r) =>
      r.truePositives.includes(trapType)
    );
    byCategory[trapType] = {
      total: relevant.length,
      detected: found.length,
      missed: relevant.length - found.length,
      rate: found.length / relevant.length,
    };
  }

  // By difficulty
  const byDifficulty: Record<string, CategoryStats> = {};
  for (const diff of ['easy', 'moderate', 'hard'] as const) {
    const relevant = adversarial.filter(
      (r) => r.sample.difficulty === diff
    );
    const found = relevant.filter((r) => r.truePositives.length > 0);
    byDifficulty[diff] = {
      total: relevant.length,
      detected: found.length,
      missed: relevant.length - found.length,
      rate: relevant.length > 0 ? found.length / relevant.length : 0,
    };
  }

  // False positive details
  const falsePositiveDetails = benign
    .filter((r) => r.detected.length > 0)
    .map((r) => ({
      id: r.sample.id,
      description: r.sample.description,
      falseTypes: r.falsePositives,
    }));

  // False negative details
  const falseNegativeDetails = adversarial
    .filter((r) => r.falseNegatives.length > 0)
    .map((r) => ({
      id: r.sample.id,
      description: r.sample.description,
      missedTypes: r.falseNegatives,
    }));

  // Confidence calibration
  const tpConfidences = adversarial
    .filter((r) => r.truePositives.length > 0)
    .map((r) => r.highestConfidence);
  const fpConfidences = benign
    .filter((r) => r.detected.length > 0)
    .map((r) => r.highestConfidence);

  const avg = (arr: number[]) =>
    arr.length > 0 ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;

  return {
    strictness: 'balanced',
    totalSamples: results.length,
    adversarialSamples: adversarial.length,
    benignSamples: benign.length,
    overallDetectionRate,
    overallFalsePositiveRate,
    byCategory,
    byDifficulty,
    falsePositiveDetails,
    falseNegativeDetails,
    avgConfidenceTruePositive: avg(tpConfidences),
    avgConfidenceFalsePositive: avg(fpConfidences),
  };
}

function printReport(summary: Summary): void {
  const pct = (n: number) => `${(n * 100).toFixed(1)}%`;

  console.log('\n' + '='.repeat(70));
  console.log('  AGENT ARMOR EVALUATION REPORT');
  console.log('  Strictness: ' + summary.strictness);
  console.log('='.repeat(70));

  console.log(`\n  Samples: ${summary.totalSamples} total (${summary.adversarialSamples} adversarial, ${summary.benignSamples} benign)`);
  console.log(`\n  DETECTION RATE:      ${pct(summary.overallDetectionRate)} (${Math.round(summary.overallDetectionRate * summary.adversarialSamples)}/${summary.adversarialSamples} adversarial samples caught)`);
  console.log(`  FALSE POSITIVE RATE: ${pct(summary.overallFalsePositiveRate)} (${Math.round(summary.overallFalsePositiveRate * summary.benignSamples)}/${summary.benignSamples} benign samples flagged)`);

  console.log('\n  ── By Trap Type ──');
  for (const [type, stats] of Object.entries(summary.byCategory)) {
    console.log(`  ${type.padEnd(25)} ${pct(stats.rate).padStart(6)}  (${stats.detected}/${stats.total})`);
  }

  console.log('\n  ── By Difficulty ──');
  for (const [diff, stats] of Object.entries(summary.byDifficulty)) {
    console.log(`  ${diff.padEnd(25)} ${pct(stats.rate).padStart(6)}  (${stats.detected}/${stats.total})`);
  }

  console.log('\n  ── Confidence Calibration ──');
  console.log(`  Avg confidence (true positives):  ${summary.avgConfidenceTruePositive.toFixed(3)}`);
  console.log(`  Avg confidence (false positives): ${summary.avgConfidenceFalsePositive.toFixed(3)}`);

  if (summary.falseNegativeDetails.length > 0) {
    console.log('\n  ── Missed Detections (False Negatives) ──');
    for (const fn of summary.falseNegativeDetails) {
      console.log(`  ${fn.id}: ${fn.description}`);
      console.log(`         Missed: ${fn.missedTypes.join(', ')}`);
    }
  }

  if (summary.falsePositiveDetails.length > 0) {
    console.log('\n  ── False Positives ──');
    for (const fp of summary.falsePositiveDetails) {
      console.log(`  ${fp.id}: ${fp.description}`);
      console.log(`         Flagged as: ${fp.falseTypes.join(', ')}`);
    }
  }

  console.log('\n' + '='.repeat(70));

  // Overall verdict
  const dr = summary.overallDetectionRate;
  const fpr = summary.overallFalsePositiveRate;
  if (dr >= 0.9 && fpr <= 0.1) {
    console.log('  VERDICT: READY for npm publish');
  } else if (dr >= 0.75 && fpr <= 0.2) {
    console.log('  VERDICT: ACCEPTABLE — review false negatives/positives before publish');
  } else {
    console.log('  VERDICT: NEEDS WORK — detection rate or false positive rate outside acceptable range');
  }
  console.log('='.repeat(70) + '\n');
}

// ─── Threshold gate ──────────────────────────────────────────────────────────

interface ThresholdEntry {
  minDetectionRate: number;
  maxFalsePositiveRate: number;
}

type Thresholds = Record<Strictness, ThresholdEntry>;

interface GateFailure {
  strictness: Strictness;
  metric: 'detection' | 'falsePositive';
  actual: number;
  bound: number;
}

const STRICTNESS_LEVELS: Strictness[] = ['permissive', 'balanced', 'strict'];

function isRate(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1;
}

/**
 * Load and validate thresholds.json. Throws (fails the gate loudly) on any
 * missing strictness key or out-of-range / non-numeric bound, so a malformed
 * config cannot silently pass the gate by skipping a comparison.
 */
function loadThresholds(): Thresholds {
  const raw = readFileSync(
    new URL('./thresholds.json', import.meta.url),
    'utf-8'
  );
  const parsed = JSON.parse(raw) as Record<string, unknown>;
  const out = {} as Thresholds;
  for (const level of STRICTNESS_LEVELS) {
    const entry = parsed[level] as Partial<ThresholdEntry> | undefined;
    if (!entry || typeof entry !== 'object') {
      throw new Error(`thresholds.json: missing "${level}" entry`);
    }
    if (!isRate(entry.minDetectionRate)) {
      throw new Error(
        `thresholds.json: "${level}.minDetectionRate" must be a number in [0,1]`
      );
    }
    if (!isRate(entry.maxFalsePositiveRate)) {
      throw new Error(
        `thresholds.json: "${level}.maxFalsePositiveRate" must be a number in [0,1]`
      );
    }
    out[level] = {
      minDetectionRate: entry.minDetectionRate,
      maxFalsePositiveRate: entry.maxFalsePositiveRate,
    };
  }
  return out;
}

/**
 * Compare summaries against the committed floors in thresholds.json.
 * Returns the list of violations (empty = pass). Float comparisons use a
 * small epsilon so deterministic 1.0 / 0.0 results are not tripped by
 * representation error.
 */
function checkGate(
  summaries: Summary[],
  thresholds: Thresholds
): GateFailure[] {
  const EPS = 1e-9;
  const failures: GateFailure[] = [];
  for (const summary of summaries) {
    const bound = thresholds[summary.strictness];
    if (!bound) {
      throw new Error(`no threshold entry for strictness "${summary.strictness}"`);
    }
    // Guard against an eroded dataset: empty cohorts produce 0/0 = NaN, and
    // every `NaN < x` / `NaN > x` comparison is false, so a metric of NaN would
    // otherwise pass the gate with zero coverage. Treat it as a hard failure.
    if (summary.adversarialSamples === 0 || summary.benignSamples === 0) {
      throw new Error(
        `empty eval cohort for "${summary.strictness}" ` +
          `(${summary.adversarialSamples} adversarial, ${summary.benignSamples} benign)`
      );
    }
    if (
      !Number.isFinite(summary.overallDetectionRate) ||
      !Number.isFinite(summary.overallFalsePositiveRate)
    ) {
      throw new Error(`non-finite metric for strictness "${summary.strictness}"`);
    }
    if (summary.overallDetectionRate < bound.minDetectionRate - EPS) {
      failures.push({
        strictness: summary.strictness,
        metric: 'detection',
        actual: summary.overallDetectionRate,
        bound: bound.minDetectionRate,
      });
    }
    if (summary.overallFalsePositiveRate > bound.maxFalsePositiveRate + EPS) {
      failures.push({
        strictness: summary.strictness,
        metric: 'falsePositive',
        actual: summary.overallFalsePositiveRate,
        bound: bound.maxFalsePositiveRate,
      });
    }
  }
  return failures;
}

function printGateResult(failures: GateFailure[]): void {
  const pct = (n: number) => `${(n * 100).toFixed(1)}%`;
  console.log('\n' + '='.repeat(70));
  console.log('  EVAL GATE');
  console.log('='.repeat(70));
  if (failures.length === 0) {
    console.log('  PASS — all strictness levels meet committed floors.');
    console.log('='.repeat(70) + '\n');
    return;
  }
  console.log('  FAIL — regression against scripts/eval/thresholds.json:\n');
  for (const f of failures) {
    if (f.metric === 'detection') {
      console.log(
        `  [${f.strictness}] detection rate ${pct(f.actual)} below floor ${pct(f.bound)}`
      );
    } else {
      console.log(
        `  [${f.strictness}] false-positive rate ${pct(f.actual)} above ceiling ${pct(f.bound)}`
      );
    }
  }
  console.log(
    '\n  If this drop is intentional, edit scripts/eval/thresholds.json in'
  );
  console.log('  this same PR so the trade-off is reviewed alongside the change.');
  console.log('='.repeat(70) + '\n');
}

// ─── Run all three strictness levels ─────────────────────────────────────────

const gate = process.argv.includes('--gate');

const summaries: Summary[] = [];
for (const strictness of ['permissive', 'balanced', 'strict'] as const) {
  const { summary } = evaluate(strictness);
  summary.strictness = strictness;
  summaries.push(summary);
  printReport(summary);
}

if (gate) {
  const failures = checkGate(summaries, loadThresholds());
  printGateResult(failures);
  if (failures.length > 0) process.exit(1);
}
