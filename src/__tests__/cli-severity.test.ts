import { describe, it, expect } from 'vitest';
import { RISK_LEVEL_ORDER, meetsOrExceeds, severityToSarifLevel } from '../cli/severity';

describe('RISK_LEVEL_ORDER', () => {
  it('orders none < low < medium < high < critical', () => {
    expect(RISK_LEVEL_ORDER.none).toBeLessThan(RISK_LEVEL_ORDER.low);
    expect(RISK_LEVEL_ORDER.low).toBeLessThan(RISK_LEVEL_ORDER.medium);
    expect(RISK_LEVEL_ORDER.medium).toBeLessThan(RISK_LEVEL_ORDER.high);
    expect(RISK_LEVEL_ORDER.high).toBeLessThan(RISK_LEVEL_ORDER.critical);
  });
});

describe('meetsOrExceeds', () => {
  it('returns true when level equals threshold', () => {
    expect(meetsOrExceeds('high', 'high')).toBe(true);
  });
  it('returns true when level exceeds threshold', () => {
    expect(meetsOrExceeds('critical', 'low')).toBe(true);
  });
  it('returns false when level is below threshold', () => {
    expect(meetsOrExceeds('low', 'high')).toBe(false);
  });
  it('returns false for a clean scan against any non-none threshold', () => {
    expect(meetsOrExceeds('none', 'low')).toBe(false);
  });
});

describe('severityToSarifLevel', () => {
  it('maps critical and high to error', () => {
    expect(severityToSarifLevel('critical')).toBe('error');
    expect(severityToSarifLevel('high')).toBe('error');
  });
  it('maps medium to warning', () => {
    expect(severityToSarifLevel('medium')).toBe('warning');
  });
  it('maps low to note', () => {
    expect(severityToSarifLevel('low')).toBe('note');
  });
});
