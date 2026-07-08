import type { RiskLevel, Severity } from '../types';

/** Ordinal scale for `--fail-on` comparisons against `ScanResult.riskLevel`. */
export const RISK_LEVEL_ORDER: Record<RiskLevel, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** True when `level` is at or above `threshold` on the risk-level scale. */
export function meetsOrExceeds(level: RiskLevel, threshold: RiskLevel): boolean {
  return RISK_LEVEL_ORDER[level] >= RISK_LEVEL_ORDER[threshold];
}

/** Maps a per-threat Severity to a SARIF 2.1.0 result `level`. */
export function severityToSarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}
