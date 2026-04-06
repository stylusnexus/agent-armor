import type { Severity, TrapCategory, TrapType } from '../types';

/**
 * A single detection pattern in the database.
 * Patterns are regex strings (not RegExp objects) so they can be
 * serialized to/from JSON for remote updates.
 */
export interface PatternEntry {
  /** Unique ID for this pattern */
  id: string;
  /** Regex source string (without flags) */
  regex: string;
  /** Regex flags (e.g. "gi") */
  flags: string;
  /** Which trap category this pattern detects */
  category: TrapCategory;
  /** Specific trap type */
  type: TrapType;
  /** Base severity if matched */
  severity: Severity;
  /** Base confidence score (0-1) before instruction-signal boosting */
  confidence: number;
  /** Human-readable label for this pattern */
  label: string;
  /** Which capture group to extract text from (0 = full match) */
  extractGroup?: number;
  /** Minimum extracted text length to trigger (avoids false positives) */
  minLength?: number;
  /** Whether to boost confidence when instruction signals are found */
  boostOnInstructions?: boolean;
}

/**
 * The full pattern database, versioned for update tracking.
 */
export interface PatternDatabase {
  /** Semver version of this pattern set */
  version: string;
  /** ISO date when these patterns were last updated */
  updatedAt: string;
  /** All patterns grouped by detector ID */
  detectors: Record<string, PatternEntry[]>;
}

/**
 * Compile a PatternEntry's regex string into a RegExp object.
 */
export function compilePattern(entry: PatternEntry): RegExp {
  return new RegExp(entry.regex, entry.flags);
}
