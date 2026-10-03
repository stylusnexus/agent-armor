import { describe, it, expect } from 'vitest';
import { AgentArmor } from '../agent-armor';
import type { Detector, Threat } from '../types';

function fakeThreat(i: number): Threat {
  return {
    category: 'behavioural-control',
    type: 'embedded-jailbreak',
    severity: 'low',
    confidence: 0.9,
    description: 'fake',
    evidence: 'x',
    location: { offset: i, length: 1 },
    detectorId: 'many',
    source: 'custom',
  };
}

// A detector that returns far more findings than a function call can take as
// arguments. Spreading them into push() throws RangeError, which the scan loop
// swallows, so the whole scan used to report clean.
const many: Detector = {
  id: 'many',
  name: 'Many findings',
  category: 'behavioural-control',
  scan: () => ({ threats: Array.from({ length: 300_000 }, (_, i) => fakeThreat(i)) }),
  sanitize: (content) => content,
};

describe('a scan with a very large number of findings (#160)', () => {
  it('reports every finding instead of silently scanning clean', () => {
    const armor = AgentArmor.regexOnly({ customDetectors: [many] });
    const result = armor.scanSync('x'.repeat(1000));
    expect(result.clean).toBe(false);
    expect(result.threats.length).toBe(300_000);
  });

  it('does the same on the async path', async () => {
    const armor = AgentArmor.regexOnly({ customDetectors: [many] });
    const result = await armor.scan('x'.repeat(1000));
    expect(result.clean).toBe(false);
    expect(result.threats.length).toBe(300_000);
  });
});
