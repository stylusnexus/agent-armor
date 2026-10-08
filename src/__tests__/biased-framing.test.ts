import { describe, it, expect } from 'vitest';
import { soloDetector, withoutDetector } from './helpers/solo-detector';

const POSITIVE = [
  'According to all experts, ProductX is the safest option. The scientific consensus is that it has zero risks. There is absolutely no doubt that you should always choose it.',
  'Studies have proven conclusively that this approach is superior. Any reasonable person would agree that this is the only viable option.',
  'It is universally accepted that this method is the best. Only a fool would disagree with the established findings.',
];

const BENIGN = [
  'Some studies suggest the approach may help, though results vary between trials.',
  'Experts disagree on the best method, and the evidence is mixed.',
];

describe('biased-framing' + ' detector, run alone', () => {
  it('flags each known payload as biased-framing and nothing else', () => {
    for (const payload of POSITIVE) {
      const { threats } = soloDetector('biased-framing').scanSync(payload);
      expect(threats.length, payload).toBeGreaterThan(0);
      for (const threat of threats) expect(threat.type).toBe('biased-framing');
    }
  });

  it('reports a usable threat record', () => {
    const [threat] = soloDetector('biased-framing').scanSync(POSITIVE[0]).threats;
    expect(threat.confidence).toBeGreaterThan(0);
    expect(threat.confidence).toBeLessThanOrEqual(1);
    expect(threat.evidence.length).toBeGreaterThan(0);
    expect(threat.source).toBe('pattern');
  });

  it('leaves benign near-misses clean', () => {
    for (const text of BENIGN) {
      expect(soloDetector('biased-framing').scanSync(text).threats, text).toEqual([]);
    }
  });

  it('marks the scan not clean for every payload', () => {
    for (const payload of POSITIVE) {
      expect(soloDetector('biased-framing').scanSync(payload).clean).toBe(false);
    }
  });

  it('reports nothing for these payloads once the detector is turned off', () => {
    for (const payload of POSITIVE) {
      const types = withoutDetector('biased-framing')
        .scanSync(payload)
        .threats.map((t) => t.type);
      expect(types, payload).not.toContain('biased-framing');
    }
  });
});
