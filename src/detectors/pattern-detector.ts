import { BaseDetector, type PatternMatch } from './base';
import type { PatternEntry } from '../patterns/pattern-db';
import { compilePattern } from '../patterns/pattern-db';
import type { Threat, TrapCategory, TrapType } from '../types';

const INSTRUCTION_SIGNALS =
  /(?:ignore|disregard|forget|override|system|assistant|you (?:are|must|should|will)|IMPORTANT|instruction|do not|instead|pretend|act as|role|new task|exfiltrat|send to|transmit|summarise|summarize|say that|respond with|output|generate|write|tell the user|without\s+(?:restrictions?|scrutiny|review)|approve\s+(?:all|everything|any)|all\s+files|arbitrary|bypass|credentials?|privileged|unrestricted)/i;

const CONFIDENCE_BOOST = 0.35;

/**
 * Generic detector driven by the pattern database.
 * Replaces all hardcoded detector classes for pattern-based detection.
 */
export class PatternDetector extends BaseDetector {
  readonly id: string;
  readonly name: string;
  readonly category: TrapCategory;
  protected readonly trapType: TrapType;
  private readonly patterns: PatternEntry[];
  private readonly sanitizeMode: 'remove' | 'replace' | 'none';
  private readonly replaceText?: string;

  constructor(opts: {
    id: string;
    name: string;
    category: TrapCategory;
    trapType: TrapType;
    patterns: PatternEntry[];
    sanitizeMode?: 'remove' | 'replace' | 'none';
    replaceText?: string;
  }) {
    super();
    this.id = opts.id;
    this.name = opts.name;
    this.category = opts.category;
    this.trapType = opts.trapType;
    this.patterns = opts.patterns;
    this.sanitizeMode = opts.sanitizeMode ?? 'remove';
    this.replaceText = opts.replaceText;
  }

  findPatterns(content: string): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const entry of this.patterns) {
      const regex = compilePattern(entry);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const extracted = match[entry.extractGroup ?? 0] ?? match[0];
        const trimmed = extracted.trim();

        if (entry.minLength && trimmed.length < entry.minLength) continue;

        const hasInstruction = INSTRUCTION_SIGNALS.test(trimmed);
        let confidence = entry.confidence;
        let severity = entry.severity;

        if (entry.boostOnInstructions && hasInstruction) {
          confidence = Math.min(confidence + CONFIDENCE_BOOST, 1.0);
          if (severity === 'high') severity = 'critical';
          else if (severity === 'medium') severity = 'high';
        }

        // Hard gate: requireInstructions means no instruction = no detection
        if (entry.requireInstructions && !hasInstruction) {
          continue;
        }

        // Soft gate: low-confidence boost-eligible patterns need instructions
        if (entry.boostOnInstructions && !hasInstruction && entry.confidence < 0.5) {
          continue;
        }

        matches.push({
          pattern: entry.label,
          match: match[0],
          index: match.index,
          length: match[0].length,
          confidence,
          severity,
          description: hasInstruction
            ? `${entry.label} with instruction-like language`
            : entry.label,
        });
      }
    }

    return matches;
  }

  sanitize(content: string, threats: Threat[]): string {
    if (this.sanitizeMode === 'none') return content;

    let result = content;
    const sorted = [...threats]
      .filter((t) => t.location)
      .sort((a, b) => (b.location?.offset ?? 0) - (a.location?.offset ?? 0));

    for (const threat of sorted) {
      if (!threat.location) continue;
      const { offset, length } = threat.location;

      if (this.sanitizeMode === 'replace' && this.replaceText) {
        result =
          result.slice(0, offset) +
          this.replaceText +
          result.slice(offset + length);
      } else {
        result = result.slice(0, offset) + result.slice(offset + length);
      }
    }

    return result;
  }
}
