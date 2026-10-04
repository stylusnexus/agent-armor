import { BaseDetector, type PatternMatch } from './base';
import type { PatternEntry } from '../patterns/pattern-db';
import { compilePattern } from '../patterns/pattern-db';
import { findMatcher, type MatcherHit, type PatternMatcher } from '../patterns/matchers';
import type { Threat, TrapCategory, TrapType } from '../types';

const INSTRUCTION_SIGNALS =
  /(?:ignore|disregard|forget|override|system|assistant|you (?:are|must|should|will)|IMPORTANT|instruction|do not|instead|pretend|act as|role|new task|send to|transmit|summarise|summarize|say that|respond with|output|generate|write|tell the user|without\s+(?:restrictions?|scrutiny|review)|approve\s+(?:all|everything|any)|all\s+files|arbitrary|bypass|credentials?|privileged|unrestricted)/i;

const CONFIDENCE_BOOST = 0.35;

/** Characters of the match kept in redacted evidence — enough to identify the
 *  credential format (`AKIA`, `ghp_`, `sk-p`), never enough to use it. */
const EVIDENCE_PREFIX_CHARS = 4;

/**
 * Reduce a matched secret to a non-usable fingerprint: a short format-identifying
 * prefix plus the original length. Provider key prefixes are format identifiers,
 * not secret material — GitHub, AWS and Stripe all publish theirs — so keeping
 * four characters aids triage ("which key leaked?") without carrying the value.
 */
export function redactSecret(match: string): string {
  const trimmed = match.trim();
  if (trimmed.length <= EVIDENCE_PREFIX_CHARS) return '[REDACTED]';
  const prefix = trimmed.slice(0, EVIDENCE_PREFIX_CHARS);
  return `${prefix}[REDACTED ${trimmed.length} chars]`;
}

/** Matches of `regex` the way a `g`-flag `exec` loop reports them. */
function* execAll(regex: RegExp, content: string, group: number): Generator<MatcherHit> {
  regex.lastIndex = 0; // reset stateful /g cursor before reuse
  let match: RegExpExecArray | null;
  while ((match = regex.exec(content)) !== null) {
    yield { index: match.index, text: match[0], extracted: match[group] };
  }
}

/**
 * Generic detector driven by the pattern database.
 * Replaces all hardcoded detector classes for pattern-based detection.
 */
export class PatternDetector extends BaseDetector {
  readonly id: string;
  readonly name: string;
  readonly category: TrapCategory;
  protected readonly trapType: TrapType;
  /** Patterns with their regexes compiled once at construction, not per scan. */
  private readonly compiled: Array<{ entry: PatternEntry; regex: RegExp; matcher?: PatternMatcher }>;
  private readonly sanitizeMode: 'remove' | 'replace' | 'none';
  private readonly replaceText?: string;
  private readonly maskEvidence: boolean;

  constructor(opts: {
    id: string;
    name: string;
    category: TrapCategory;
    trapType: TrapType;
    patterns: PatternEntry[];
    sanitizeMode?: 'remove' | 'replace' | 'none';
    replaceText?: string;
    /** Redact matched text in `Threat.evidence`. Set for detectors whose
     *  matches are secrets, so a scan can't leak what it just found. */
    maskEvidence?: boolean;
  }) {
    super();
    this.id = opts.id;
    this.name = opts.name;
    this.category = opts.category;
    this.trapType = opts.trapType;
    this.compiled = opts.patterns.map((entry) => ({
      entry,
      regex: compilePattern(entry),
      matcher: findMatcher(entry.regex, entry.flags, entry.extractGroup ?? 0),
    }));
    this.sanitizeMode = opts.sanitizeMode ?? 'remove';
    this.replaceText = opts.replaceText;
    this.maskEvidence = opts.maskEvidence ?? false;
  }

  protected override redactEvidence(match: string): string {
    return this.maskEvidence ? redactSecret(match) : match;
  }

  findPatterns(content: string): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const { entry, regex, matcher } of this.compiled) {
      for (const hit of matcher ? matcher.match(content) : execAll(regex, content, entry.extractGroup ?? 0)) {
        const extracted = hit.extracted ?? hit.text;
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
          match: hit.text,
          index: hit.index,
          length: hit.text.length,
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

    const sorted = [...threats]
      .filter((t) => t.location)
      .sort((a, b) => (b.location?.offset ?? 0) - (a.location?.offset ?? 0));

    const replacement =
      this.sanitizeMode === 'replace' && this.replaceText
        ? this.replaceText
        : '';

    // Apply the edits from the last offset to the first without rebuilding the
    // string per edit (that was quadratic in the number of findings, #160).
    // State: result = content.slice(0, boundary) + the chunks, which are kept
    // in reverse so the front is the last element. An edit that reaches past
    // `boundary` eats into the front of the chunks, as slicing the already-edited
    // string did. Output matches the old method whenever every edit fits the
    // text; an offset past the end (stale offsets from an earlier detector)
    // now appends instead of landing inside inserted text.
    const chunks: string[] = [];
    let boundary = content.length;

    for (const threat of sorted) {
      if (!threat.location) continue;
      const { offset, length } = threat.location;
      const end = offset + length;

      if (end <= boundary) {
        if (end < boundary) chunks.push(content.slice(end, boundary));
      } else {
        let drop = end - boundary;
        while (drop > 0 && chunks.length > 0) {
          const front = chunks[chunks.length - 1];
          if (front.length <= drop) {
            drop -= front.length;
            chunks.pop();
          } else {
            chunks[chunks.length - 1] = front.slice(drop);
            drop = 0;
          }
        }
      }
      if (replacement) chunks.push(replacement);
      boundary = offset;
    }

    return content.slice(0, boundary) + chunks.reverse().join('');
  }
}
