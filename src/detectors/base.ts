import type {
  Confidence,
  Detector,
  DetectorOptions,
  DetectorResult,
  Severity,
  Strictness,
  Threat,
  TrapCategory,
  TrapType,
} from '../types';

/**
 * Confidence thresholds per strictness level.
 * Strict mode reports more potential threats (lower threshold).
 * Permissive mode only reports high-confidence findings.
 */
const CONFIDENCE_THRESHOLDS: Record<Strictness, number> = {
  strict: 0.3,
  balanced: 0.5,
  permissive: 0.7,
};

export interface PatternMatch {
  pattern: string;
  match: string;
  index: number;
  length: number;
  confidence: Confidence;
  severity: Severity;
  description: string;
}

export abstract class BaseDetector implements Detector {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly category: TrapCategory;
  protected abstract readonly trapType: TrapType;

  abstract findPatterns(content: string): PatternMatch[];
  abstract sanitize(content: string, threats: Threat[]): string;

  scan(content: string, options?: DetectorOptions): DetectorResult {
    const strictness = options?.strictness ?? 'balanced';
    const threshold = CONFIDENCE_THRESHOLDS[strictness];

    const matches = this.findPatterns(content);

    const threats: Threat[] = matches
      .filter((m) => m.confidence >= threshold)
      .map((m) => ({
        category: this.category,
        type: this.trapType,
        severity: m.severity,
        confidence: m.confidence,
        description: m.description,
        evidence: truncate(m.match, 200),
        location: { offset: m.index, length: m.length },
        detectorId: this.id,
      }));

    return { threats };
  }
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + '...';
}
