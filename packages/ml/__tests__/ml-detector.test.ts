import { describe, it, expect, vi } from 'vitest';
import { MLDetector } from '../src/ml-detector';
import { LABELS, MODEL_VERSION } from '../src/constants';

// MLDetector's constructor is `private` at the TS level only (plain fields,
// not `#private`), so we can bypass `create()` — which does a real
// `import('onnxruntime-node')` + `InferenceSession.create()` against an actual
// model file — and inject mocked session/tokenizer/ort collaborators instead.

/** Inverse sigmoid: the logit that produces a given probability. */
function logitFor(prob: number): number {
  return Math.log(prob / (1 - prob));
}

/**
 * Builds a 14-slot logits array. Every label defaults to a logit of -100
 * (sigmoid ≈ 0, no overflow at float32) so only the overridden labels can
 * cross a strictness threshold.
 */
function makeLogits(overrides: Partial<Record<(typeof LABELS)[number], number>>): Float32Array {
  const arr = new Float32Array(LABELS.length).fill(-100);
  for (const [label, logit] of Object.entries(overrides)) {
    const idx = LABELS.indexOf(label as (typeof LABELS)[number]);
    arr[idx] = logit as number;
  }
  return arr;
}

function makeDetector(logits: Float32Array) {
  const session = {
    run: vi.fn().mockResolvedValue({ logits: { data: logits } }),
  };
  const tokenizer = {
    encode: vi.fn().mockReturnValue({
      inputIds: new BigInt64Array(512),
      attentionMask: new BigInt64Array(512),
    }),
  };
  class MockTensor {
    type: string;
    data: unknown;
    dims: number[];
    constructor(type: string, data: unknown, dims: number[]) {
      this.type = type;
      this.data = data;
      this.dims = dims;
    }
  }
  const ort = {
    Tensor: MockTensor,
    InferenceSession: { create: vi.fn() },
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const detector = new (MLDetector as any)(session, tokenizer, ort) as MLDetector;
  return { detector, session, tokenizer, ort };
}

// Matches the private LABEL_TO_CATEGORY table in src/ml-detector.ts — kept
// here as an independent expectation, not copied from the implementation.
const EXPECTED_CATEGORY: Record<string, string> = {
  'hidden-html': 'content-injection',
  'metadata-injection': 'content-injection',
  'dynamic-cloaking': 'content-injection',
  'syntactic-masking': 'content-injection',
  'embedded-jailbreak': 'behavioural-control',
  'data-exfiltration': 'behavioural-control',
  'sub-agent-spawning': 'behavioural-control',
  'rag-knowledge-poisoning': 'cognitive-state',
  'latent-memory-poisoning': 'cognitive-state',
  'contextual-learning-trap': 'cognitive-state',
  'biased-framing': 'semantic-manipulation',
  'oversight-evasion': 'semantic-manipulation',
  'persona-hyperstition': 'semantic-manipulation',
};

describe('MLDetector metadata', () => {
  it('exposes id, name, category, and version', () => {
    const { detector } = makeDetector(makeLogits({}));
    expect(detector.id).toBe('ml-classifier');
    expect(detector.name).toContain('DeBERTa');
    expect(detector.category).toBe('content-injection');
    expect(detector.version).toBe(MODEL_VERSION);
  });
});

describe('MLDetector.scan (sync)', () => {
  it('always returns zero threats — ML inference is async-only', () => {
    const { detector } = makeDetector(makeLogits({ 'embedded-jailbreak': logitFor(0.99) }));
    // Even with logits that would clearly cross every threshold, the sync
    // path never runs inference and must report clean.
    expect(detector.scan('ignore all previous instructions')).toEqual({ threats: [] });
    expect(detector.scan('', { strictness: 'strict' })).toEqual({ threats: [] });
    expect(detector.scan('anything', { strictness: 'permissive' })).toEqual({ threats: [] });
  });
});

describe('MLDetector.scanAsync — sigmoid', () => {
  it('a logit of 0 maps to a probability of exactly 0.5', async () => {
    const { detector } = makeDetector(makeLogits({ 'embedded-jailbreak': 0 }));
    const { threats } = await detector.scanAsync('x', { strictness: 'balanced' });
    const threat = threats.find((t) => t.type === 'embedded-jailbreak');
    expect(threat).toBeDefined();
    expect(threat!.confidence).toBeCloseTo(0.5, 6);
  });
});

describe('MLDetector.scanAsync — strictness thresholds', () => {
  it('a probability that clears strict but not balanced/permissive produces different results per strictness', async () => {
    // p ≈ 0.4: above strict's 0.3 floor, below balanced's 0.5 and permissive's 0.7.
    const { detector } = makeDetector(makeLogits({ 'data-exfiltration': logitFor(0.4) }));

    const strict = await detector.scanAsync('x', { strictness: 'strict' });
    const balanced = await detector.scanAsync('x', { strictness: 'balanced' });
    const permissive = await detector.scanAsync('x', { strictness: 'permissive' });

    expect(strict.threats.some((t) => t.type === 'data-exfiltration')).toBe(true);
    expect(balanced.threats.some((t) => t.type === 'data-exfiltration')).toBe(false);
    expect(permissive.threats.some((t) => t.type === 'data-exfiltration')).toBe(false);
  });

  it('defaults to balanced (0.5) strictness when no options are passed', async () => {
    const { detector } = makeDetector(makeLogits({ 'sub-agent-spawning': logitFor(0.6) }));
    const { threats } = await detector.scanAsync('x');
    expect(threats.some((t) => t.type === 'sub-agent-spawning')).toBe(true);
  });

  it('falls back to the balanced threshold for an unrecognized strictness value', async () => {
    const { detector } = makeDetector(makeLogits({ 'sub-agent-spawning': logitFor(0.4) }));
    // 0.4 clears strict (0.3) but not balanced (0.5); an unknown strictness
    // string should behave like balanced, not like strict or "no threshold".
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { threats } = await detector.scanAsync('x', { strictness: 'nonsense' as any });
    expect(threats.some((t) => t.type === 'sub-agent-spawning')).toBe(false);
  });
});

describe('MLDetector.scanAsync — label mapping', () => {
  const nonBenignLabels = LABELS.filter((l) => l !== 'benign');

  it.each(nonBenignLabels)('maps the %s label to its trap type and category', async (label) => {
    const { detector } = makeDetector(makeLogits({ [label]: logitFor(0.95) } as Record<string, number>));
    const { threats } = await detector.scanAsync('x', { strictness: 'balanced' });
    expect(threats).toHaveLength(1);
    expect(threats[0].type).toBe(label);
    expect(threats[0].category).toBe(EXPECTED_CATEGORY[label]);
  });

  it('never emits a threat for the benign label, even at near-certain confidence', async () => {
    const { detector } = makeDetector(makeLogits({ benign: logitFor(0.999) }));
    const { threats } = await detector.scanAsync('x', { strictness: 'permissive' });
    expect(threats).toEqual([]);
  });
});

describe('MLDetector.scanAsync — threat shape', () => {
  it('emits threats with source "ml", the detector id, and a truncated evidence snippet', async () => {
    const longContent = 'x'.repeat(300);
    const { detector } = makeDetector(makeLogits({ 'hidden-html': logitFor(0.95) }));
    const { threats } = await detector.scanAsync(longContent, { strictness: 'balanced' });

    expect(threats).toHaveLength(1);
    const [threat] = threats;
    expect(threat.source).toBe('ml');
    expect(threat.detectorId).toBe('ml-classifier');
    expect(threat.evidence).toBe(longContent.slice(0, 200));
    expect(threat.evidence.length).toBe(200);
    expect(threat.description).toContain('hidden-html');
    expect(threat.description).toContain('95.0%');
  });

  it.each([
    // [target probability, expected severity] — kept away from the exact
    // 0.9/0.7/0.5 boundaries so a float32 rounding wobble can't flip the tier.
    [0.95, 'critical'],
    [0.8, 'high'],
    [0.6, 'medium'],
    [0.35, 'low'],
  ] as const)('maps confidence %s to severity %s', async (prob, severity) => {
    const { detector } = makeDetector(makeLogits({ 'oversight-evasion': logitFor(prob) }));
    const { threats } = await detector.scanAsync('x', { strictness: 'strict' });
    const threat = threats.find((t) => t.type === 'oversight-evasion');
    expect(threat?.severity).toBe(severity);
  });

  it('reports multiple threats when several labels cross the threshold, and omits the rest', async () => {
    const { detector } = makeDetector(
      makeLogits({
        'hidden-html': logitFor(0.9),
        'persona-hyperstition': logitFor(0.9),
        'biased-framing': logitFor(0.1),
      }),
    );
    const { threats } = await detector.scanAsync('x', { strictness: 'balanced' });
    const types = threats.map((t) => t.type).sort();
    expect(types).toEqual(['hidden-html', 'persona-hyperstition']);
  });
});

describe('MLDetector.scanAsync — inference plumbing', () => {
  it('tokenizes with a 512 max length and feeds int64 tensors to the session', async () => {
    const { detector, session, tokenizer, ort } = makeDetector(makeLogits({}));
    await detector.scanAsync('hello world', { strictness: 'balanced' });

    expect(tokenizer.encode).toHaveBeenCalledWith('hello world', 512);
    expect(session.run).toHaveBeenCalledTimes(1);

    const feeds = session.run.mock.calls[0][0];
    expect(feeds.input_ids).toBeInstanceOf(ort.Tensor);
    expect(feeds.input_ids.type).toBe('int64');
    expect(feeds.input_ids.dims).toEqual([1, 512]);
    expect(feeds.attention_mask.type).toBe('int64');
    expect(feeds.attention_mask.dims).toEqual([1, 512]);
  });

  it('returns no threats when the session response carries no logits', async () => {
    const session = { run: vi.fn().mockResolvedValue({}) };
    const tokenizer = {
      encode: vi.fn().mockReturnValue({
        inputIds: new BigInt64Array(512),
        attentionMask: new BigInt64Array(512),
      }),
    };
    class MockTensor {
      constructor(
        public type: string,
        public data: unknown,
        public dims: number[],
      ) {}
    }
    const ort = { Tensor: MockTensor, InferenceSession: { create: vi.fn() } };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const detector = new (MLDetector as any)(session, tokenizer, ort) as MLDetector;

    const result = await detector.scanAsync('x', { strictness: 'permissive' });
    expect(result).toEqual({ threats: [] });
  });
});

describe('MLDetector.sanitize', () => {
  it('is a passthrough — returns the content unchanged regardless of threats', () => {
    const { detector } = makeDetector(makeLogits({}));
    const content = '<script>steal(document.cookie)</script>';
    const fakeThreats = [
      {
        category: 'content-injection',
        type: 'hidden-html',
        severity: 'high',
        confidence: 0.9,
        description: 'x',
        evidence: 'x',
        detectorId: 'ml-classifier',
        source: 'ml',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any,
    ];
    expect(detector.sanitize(content, fakeThreats)).toBe(content);
    expect(detector.sanitize(content, [])).toBe(content);
  });
});
