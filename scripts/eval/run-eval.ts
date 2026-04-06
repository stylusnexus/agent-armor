/**
 * Agent Armor Evaluation Suite
 *
 * Tests all detectors against curated adversarial + benign samples.
 * Outputs per-category detection rate, false positive rate, and
 * confidence calibration.
 *
 * Usage: npx tsx scripts/eval/run-eval.ts
 */

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

  // Detection rate: what fraction of adversarial samples had at least 1 TP
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

// ─── Run all three strictness levels ─────────────────────────────────────────

for (const strictness of ['permissive', 'balanced', 'strict'] as const) {
  const { summary } = evaluate(strictness);
  summary.strictness = strictness;
  printReport(summary);
}
