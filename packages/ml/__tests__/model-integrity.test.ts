import { describe, it, expect } from 'vitest';
import {
  checkLabelMap,
  checkModelChecksum,
  checkRequiredFiles,
  checkTokenizer,
  mergeReports,
  MIN_TOKENIZER_BYTES,
  type HfTreeEntry,
} from '../scripts/model-integrity';
import { LABELS, MODEL_CHECKSUM, MODEL_FILENAME } from '../src/constants';

const GOOD_DIGEST = 'a'.repeat(64);

/** A tree response with everything healthy, overridable per test. */
function tree(overrides: Partial<Record<string, HfTreeEntry | null>> = {}): Map<string, HfTreeEntry> {
  const base: Record<string, HfTreeEntry> = {
    [MODEL_FILENAME]: {
      path: MODEL_FILENAME,
      size: 172_313_551,
      lfs: { oid: MODEL_CHECKSUM, size: 172_313_551 },
    },
    'tokenizer.json': { path: 'tokenizer.json', size: 8_656_889 },
    'label_map.json': { path: 'label_map.json', size: 402 },
  };
  const merged = { ...base, ...overrides };
  const map = new Map<string, HfTreeEntry>();
  for (const [k, v] of Object.entries(merged)) {
    if (v) map.set(k, v);
  }
  return map;
}

/** The label map exactly as hosted today. */
const healthyLabelMap = Object.fromEntries(LABELS.map((label, i) => [String(i), label]));

describe('checkRequiredFiles', () => {
  it('passes when every required file is present and non-empty', () => {
    expect(checkRequiredFiles(tree()).failures).toEqual([]);
  });

  it('fails and names the file when one is missing — the partial-upload case', () => {
    const { failures } = checkRequiredFiles(tree({ 'label_map.json': null }));
    expect(failures).toHaveLength(1);
    expect(failures[0]).toContain('label_map.json');
    expect(failures[0]).toContain('missing');
  });

  it('fails on a zero-byte file rather than treating presence as sufficient', () => {
    const { failures } = checkRequiredFiles(
      tree({ 'tokenizer.json': { path: 'tokenizer.json', size: 0 } })
    );
    expect(failures[0]).toContain('zero bytes');
  });
});

describe('checkModelChecksum', () => {
  it('passes when the hosted digest matches the shipped constant', () => {
    const r = checkModelChecksum(tree(), MODEL_CHECKSUM, MODEL_CHECKSUM, { deep: false });
    expect(r.failures).toEqual([]);
    expect(r.notes[0]).toContain('checksum matches');
  });

  it('fails and reports BOTH hashes so the disagreement is actionable', () => {
    const { failures } = checkModelChecksum(tree(), MODEL_CHECKSUM, GOOD_DIGEST, { deep: false });
    expect(failures).toHaveLength(1);
    expect(failures[0]).toContain(MODEL_FILENAME);
    expect(failures[0]).toContain(GOOD_DIGEST);
    expect(failures[0]).toContain(MODEL_CHECKSUM);
  });

  it('labels a deep-mode mismatch as coming from downloaded bytes', () => {
    const { failures } = checkModelChecksum(tree(), MODEL_CHECKSUM, GOOD_DIGEST, { deep: true });
    expect(failures[0]).toContain('downloaded bytes');
  });

  it('fails when the model file is absent entirely', () => {
    const { failures } = checkModelChecksum(
      tree({ [MODEL_FILENAME]: null }),
      MODEL_CHECKSUM,
      undefined,
      { deep: false }
    );
    expect(failures[0]).toContain('not found');
  });

  it('fails on a placeholder constant instead of silently passing', () => {
    // model-manager's verifyChecksum() deliberately SKIPS verification for a
    // placeholder. That is right at runtime and wrong here: shipping a
    // placeholder is exactly what this check exists to catch before publish.
    const { failures } = checkModelChecksum(tree(), 'PLACEHOLDER_SHA256', MODEL_CHECKSUM, {
      deep: false,
    });
    expect(failures).toHaveLength(1);
    expect(failures[0]).toContain('placeholder');
    expect(failures[0]).toContain(MODEL_CHECKSUM);
  });

  it('fails when the file is not in LFS, so no oid is available to compare', () => {
    const { failures } = checkModelChecksum(
      tree({ [MODEL_FILENAME]: { path: MODEL_FILENAME, size: 172_313_551 } }),
      MODEL_CHECKSUM,
      undefined,
      { deep: false }
    );
    expect(failures[0]).toContain('--deep');
  });
});

describe('checkLabelMap', () => {
  it('passes on the label map as currently hosted', () => {
    const r = checkLabelMap(healthyLabelMap);
    expect(r.failures).toEqual([]);
    expect(r.notes[0]).toContain(`all ${LABELS.length} labels`);
  });

  it('fails when the label space grows — a retrain, not a checksum bump', () => {
    const { failures } = checkLabelMap({ ...healthyLabelMap, '14': 'tool-call-tampering' });
    expect(failures[0]).toContain(`has ${LABELS.length + 1} labels`);
    expect(failures[0]).toContain('MODEL_VERSION');
  });

  it('fails when the label space shrinks', () => {
    const shrunk = { ...healthyLabelMap };
    delete shrunk['13'];
    expect(checkLabelMap(shrunk).failures[0]).toContain(`has ${LABELS.length - 1} labels`);
  });

  it('catches a same-size REORDER, which set comparison would miss', () => {
    const swapped = { ...healthyLabelMap, '10': LABELS[11], '11': LABELS[10] };
    const { failures } = checkLabelMap(swapped);

    expect(failures).toHaveLength(1);
    expect(failures[0]).toContain('index 10');
    expect(failures[0]).toContain('index 11');
    expect(failures[0]).toContain('mislabels silently');
  });

  it('reports every mismatched index, not just the first', () => {
    const scrambled = Object.fromEntries(
      LABELS.map((_, i) => [String(i), LABELS[(i + 1) % LABELS.length]])
    );
    const { failures } = checkLabelMap(scrambled);
    expect(failures[0]).toContain(`at ${LABELS.length} index(es)`);
  });
});

describe('checkTokenizer', () => {
  it('passes at the real hosted size', () => {
    expect(checkTokenizer(tree()).failures).toEqual([]);
  });

  it('fails on a truncated upload that a presence-only check would allow', () => {
    const { failures } = checkTokenizer(
      tree({ 'tokenizer.json': { path: 'tokenizer.json', size: MIN_TOKENIZER_BYTES - 1 } })
    );
    expect(failures[0]).toContain('truncated');
  });

  it('stays silent when absent — checkRequiredFiles owns that failure', () => {
    const r = checkTokenizer(tree({ 'tokenizer.json': null }));
    expect(r.failures).toEqual([]);
    expect(r.notes).toEqual([]);
  });
});

describe('mergeReports', () => {
  it('accumulates every failure rather than short-circuiting on the first', () => {
    const merged = mergeReports(
      checkRequiredFiles(tree({ 'label_map.json': null })),
      checkModelChecksum(tree(), MODEL_CHECKSUM, GOOD_DIGEST, { deep: false }),
      checkTokenizer(tree({ 'tokenizer.json': { path: 'tokenizer.json', size: 10 } }))
    );
    expect(merged.failures).toHaveLength(3);
  });

  it('reports a fully healthy repo with no failures', () => {
    const merged = mergeReports(
      checkRequiredFiles(tree()),
      checkModelChecksum(tree(), MODEL_CHECKSUM, MODEL_CHECKSUM, { deep: false }),
      checkLabelMap(healthyLabelMap),
      checkTokenizer(tree())
    );
    expect(merged.failures).toEqual([]);
    expect(merged.notes).toHaveLength(3);
  });
});
