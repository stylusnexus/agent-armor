/**
 * Doc-drift consistency check — derives ground-truth numbers from source
 * (eval sample counts, pattern database version + entry count) and fails
 * if README.md / site/llms.txt have gone stale.
 *
 * This exists because those numbers drifted silently for months (105 vs
 * the real 106 samples, "v0.4.0 / 71 entries" vs the real v0.6.0 / 83) —
 * nothing caught it until a manual audit. Run: npx tsx scripts/check-doc-drift.ts
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_PATTERNS } from '../src/patterns/default-patterns';
import { ALL_SAMPLES, ADVERSARIAL_SAMPLES, BENIGN_SAMPLES } from './eval/samples';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

function patternEntryCount(): number {
  return Object.values(DEFAULT_PATTERNS.detectors).reduce((sum, arr) => sum + arr.length, 0);
}

interface Check {
  file: string;
  label: string;
  pattern: RegExp;
  expected: string;
}

function buildChecks(): Check[] {
  const sampleTotal = ALL_SAMPLES.length;
  const adversarialCount = ADVERSARIAL_SAMPLES.length;
  const benignCount = BENIGN_SAMPLES.length;
  const patternVersion = DEFAULT_PATTERNS.version;
  const patternCount = patternEntryCount();

  return [
    {
      file: 'README.md',
      label: 'eval sample count',
      pattern: /\d+ curated samples \(\d+ adversarial, \d+ benign\)/,
      expected: `${sampleTotal} curated samples (${adversarialCount} adversarial, ${benignCount} benign)`,
    },
    {
      file: 'README.md',
      label: 'patternVersion code example',
      pattern: /armor\.patternVersion\); \/\/ '[\d.]+'/,
      expected: `armor.patternVersion); // '${patternVersion}'`,
    },
    {
      file: 'README.md',
      label: 'pattern database version + entry count',
      pattern: /Pattern database v[\d.]+ with \d+ pattern entries/,
      expected: `Pattern database v${patternVersion} with ${patternCount} pattern entries`,
    },
    {
      file: 'site/llms.txt',
      label: 'eval results header sample count',
      pattern: /Eval results \(v[\d.]+ patterns, \d+ samples\)/,
      expected: `Eval results (v${patternVersion} patterns, ${sampleTotal} samples)`,
    },
  ];
}

function main(): void {
  const checks = buildChecks();
  let failed = false;

  for (const check of checks) {
    const filePath = path.join(ROOT, check.file);
    const text = readFileSync(filePath, 'utf8');
    const match = text.match(check.pattern);

    if (!match) {
      console.error(`FAIL [${check.file}] ${check.label}: no text matched ${check.pattern}`);
      failed = true;
      continue;
    }
    if (match[0] !== check.expected) {
      console.error(`FAIL [${check.file}] ${check.label}:`);
      console.error(`  found:    ${match[0]}`);
      console.error(`  expected: ${check.expected}`);
      failed = true;
    }
  }

  if (failed) {
    console.error(
      '\nDoc drift detected. Update the stale doc(s) to match source, or if source' +
        ' itself changed intentionally, this check picks up the new numbers automatically.'
    );
    process.exit(1);
  }

  const sampleTotal = ALL_SAMPLES.length;
  console.log(
    `Docs in sync: ${sampleTotal} samples (${ADVERSARIAL_SAMPLES.length} adversarial /` +
      ` ${BENIGN_SAMPLES.length} benign), pattern v${DEFAULT_PATTERNS.version}` +
      ` (${patternEntryCount()} entries).`
  );
  process.exit(0);
}

main();
