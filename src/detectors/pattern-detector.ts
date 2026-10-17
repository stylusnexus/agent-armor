import { BaseDetector, type PatternMatch } from './base';
import type { PatternEntry } from '../patterns/pattern-db';
import { compilePattern } from '../patterns/pattern-db';
import { findMatcher, type MatcherHit, type PatternMatcher } from '../patterns/matchers';
import type { TextEdit, Threat, TrapCategory, TrapType } from '../types';
import { replaceRanges } from '../sanitize';
import { redactCredentialsIn, redactSecret } from './credentials';
import { findCommandValues, foldForScan, type CommandValue } from './tool-call-json';

export { redactSecret };

const INSTRUCTION_SIGNALS =
  /(?:ignore|disregard|forget|override|system|assistant|you (?:are|must|should|will)|IMPORTANT|instruction|do not|instead|pretend|act as|role|new task|send to|transmit|summarise|summarize|say that|respond with|output|generate|write|tell the user|without\s+(?:restrictions?|scrutiny|review)|approve\s+(?:all|everything|any)|all\s+files|arbitrary|bypass|credentials?|privileged|unrestricted)/i;

const CONFIDENCE_BOOST = 0.35;

/**
 * Matches of `regex` the way a `g`-flag `exec` loop reports them. A zero-width
 * match is skipped and the cursor moved on, so a pattern that can match empty
 * text (a bare lookahead, say) cannot stall the loop.
 */
function* execAll(regex: RegExp, content: string, group: number): Generator<MatcherHit> {
  regex.lastIndex = 0; // reset stateful /g cursor before reuse
  let match: RegExpExecArray | null;
  while ((match = regex.exec(content)) !== null) {
    if (match[0].length === 0) {
      const code = regex.unicode ? content.codePointAt(regex.lastIndex) : undefined;
      regex.lastIndex += code !== undefined && code > 0xffff ? 2 : 1;
      continue;
    }
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
  private readonly compiled: Array<{
    entry: PatternEntry;
    regex: RegExp;
    matcher?: PatternMatcher;
  }>;
  private readonly sanitizeMode: 'remove' | 'replace' | 'none';
  private readonly replaceText?: string;
  private readonly maskEvidence: boolean;
  private readonly redactCredentials: boolean;
  private readonly foldInside: boolean;

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
    /** Cut credentials inside the matched text down to a prefix, keeping the rest. */
    redactCredentials?: boolean;
    /**
     * Scan the text as given and fold Unicode here instead: the tool-call
     * reader must see the original characters. Patterns on the whole text run
     * on a folded copy and map back; patterns on tool-call commands run on
     * folded commands.
     */
    foldInside?: boolean;
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
    this.redactCredentials = opts.redactCredentials ?? false;
    this.foldInside = opts.foldInside ?? false;
  }

  protected override redactEvidence(match: string): string {
    if (this.maskEvidence) return redactSecret(match);
    return this.redactCredentials ? redactCredentialsIn(match) : match;
  }

  findPatterns(content: string): PatternMatch[] {
    const matches: PatternMatch[] = [];

    let commands: CommandValue[] | undefined;
    let folded: ReturnType<typeof foldForScan> | undefined;
    for (const { entry, regex, matcher } of this.compiled) {
      const hits: Array<MatcherHit & { span?: { start: number; end: number } }> = [];
      if (entry.scope === 'tool-call-command') {
        commands ??= findCommandValues(content);
        for (const command of commands) {
          const text = this.foldInside ? foldForScan(command.text).text : command.text;
          for (const hit of execAll(regex, text, entry.extractGroup ?? 0)) {
            hits.push({ ...hit, span: command });
          }
        }
      } else {
        const view = this.foldInside ? (folded ??= foldForScan(content)) : undefined;
        const text = view ? view.text : content;
        for (const hit of matcher
          ? matcher.match(text)
          : execAll(regex, text, entry.extractGroup ?? 0)) {
          if (!view) {
            hits.push(hit);
            continue;
          }
          const at = view.back(hit.index, hit.text.length);
          hits.push({
            ...hit,
            index: at.offset,
            text: content.slice(at.offset, at.offset + at.length),
          });
        }
      }
      for (const hit of hits) {
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
          // A finding in a tool call's command sits on the whole command value.
          index: hit.span ? hit.span.start : hit.index,
          length: hit.span ? hit.span.end - hit.span.start : hit.text.length,
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

  sanitizeEdits(_content: string, threats: Threat[]): TextEdit[] {
    if (this.sanitizeMode === 'none') return [];
    const replacement = this.sanitizeMode === 'replace' && this.replaceText ? this.replaceText : '';
    return threats
      .filter((t) => t.location)
      .map((t) => ({
        offset: t.location!.offset,
        length: t.location!.length,
        replacement,
        severity: t.severity,
      }));
  }

  sanitize(content: string, threats: Threat[]): string {
    if (this.sanitizeMode === 'none') return content;
    const replacement = this.sanitizeMode === 'replace' && this.replaceText ? this.replaceText : '';
    return replaceRanges(
      content,
      threats.flatMap((t) => (t.location ? [t.location] : [])),
      replacement,
    );
  }
}
