import { describe, it, expect } from 'vitest';
import { AgentArmor } from '../agent-armor';

describe('maxInputLength (#175)', () => {
  it('refuses oversized input with a clear, non-clean result', () => {
    const armor = AgentArmor.regexOnly({ maxInputLength: 100 });
    const result = armor.scanSync('x'.repeat(101));
    expect(result.clean).toBe(false);
    expect(result.riskLevel).toBe('high');
    expect(result.sanitized).toBe('');
    expect(result.threats).toHaveLength(1);
    expect(result.threats[0].detectorId).toBe('input-limit');
    expect(result.threats[0].type).toBe('congestion-trap');
    expect(result.threats[0].description).toContain('maxInputLength');
  });

  it('scans input exactly at the limit', () => {
    const armor = AgentArmor.regexOnly({ maxInputLength: 100 });
    const result = armor.scanSync('x'.repeat(100));
    expect(result.clean).toBe(true);
    expect(result.sanitized).toBe('x'.repeat(100));
  });

  it('does the same on the async path', async () => {
    const armor = AgentArmor.regexOnly({ maxInputLength: 100 });
    const result = await armor.scan('x'.repeat(101));
    expect(result.clean).toBe(false);
    expect(result.threats[0].detectorId).toBe('input-limit');
  });

  it('defaults to one million characters', () => {
    const armor = AgentArmor.regexOnly();
    expect(armor.scanSync('x'.repeat(1_000_000)).clean).toBe(true);
    expect(armor.scanSync('x'.repeat(1_000_001)).threats[0]?.detectorId).toBe('input-limit');
  });

  it('can be turned off with Infinity', () => {
    const armor = AgentArmor.regexOnly({ maxInputLength: Infinity });
    expect(armor.scanSync('x'.repeat(1_000_001)).clean).toBe(true);
  });
});
