import { BaseDetector, type PatternMatch } from '../base';
import type { Threat, TrapCategory, TrapType } from '../../types';

/**
 * Detects payloads hidden in formatting language syntax (Markdown, LaTeX).
 *
 * Reference: Keuper (2025) — white-on-white or tiny-font LaTeX text in
 * scientific manuscripts survives PDF-to-Markdown conversion.
 */
export class SyntacticMaskingDetector extends BaseDetector {
  readonly id = 'syntactic-masking';
  readonly name = 'Syntactic Masking Detector';
  readonly category: TrapCategory = 'content-injection';
  protected readonly trapType: TrapType = 'syntactic-masking';

  private static readonly INSTRUCTION_SIGNALS =
    /(?:ignore|disregard|forget|override|system|assistant|you (?:are|must|should|will)|IMPORTANT|instruction|do not|instead|pretend|act as|role|new task|exfiltrat|send to|transmit)/i;

  private static readonly PATTERNS: Array<{
    regex: RegExp;
    severity: 'medium' | 'high';
    baseConfidence: number;
    label: string;
    extractGroup: number;
  }> = [
    {
      regex: /\[([^\]]{20,})\]\([^)]+\)/g,
      severity: 'high',
      baseConfidence: 0.3,
      label: 'Markdown link with long anchor text',
      extractGroup: 1,
    },
    {
      regex: /!\[([^\]]{30,})\]\([^)]+\)/g,
      severity: 'medium',
      baseConfidence: 0.3,
      label: 'Markdown image with long alt text',
      extractGroup: 1,
    },
    {
      regex: /\\(?:tiny|scriptsize|footnotesize)\s*\{([^}]+)\}/g,
      severity: 'high',
      baseConfidence: 0.6,
      label: 'LaTeX small-font text',
      extractGroup: 1,
    },
    {
      regex: /\\(?:textcolor|color)\s*\{(?:white|background)\}\s*\{([^}]+)\}/g,
      severity: 'high',
      baseConfidence: 0.8,
      label: 'LaTeX invisible text color',
      extractGroup: 1,
    },
    {
      regex:
        /<(?:div|span|p)\s+[^>]*style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)[^"']*["'][^>]*>([\s\S]*?)<\/(?:div|span|p)>/gi,
      severity: 'high',
      baseConfidence: 0.85,
      label: 'Hidden HTML embedded in Markdown',
      extractGroup: 1,
    },
    {
      regex: /[\u200B\u200C\u200D\uFEFF]{2,}/g,
      severity: 'medium',
      baseConfidence: 0.6,
      label: 'Cluster of zero-width characters',
      extractGroup: 0,
    },
    {
      regex: /[\u202A-\u202E\u2066-\u2069]+[^]*?[\u202C\u2069]/g,
      severity: 'high',
      baseConfidence: 0.75,
      label: 'Unicode bidirectional override',
      extractGroup: 0,
    },
  ];

  findPatterns(content: string): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const pattern of SyntacticMaskingDetector.PATTERNS) {
      let match: RegExpExecArray | null;
      pattern.regex.lastIndex = 0;

      while ((match = pattern.regex.exec(content)) !== null) {
        const extracted = match[pattern.extractGroup] ?? match[0];
        const trimmed = extracted.trim();
        if (trimmed.length < 5) continue;

        const hasInstruction =
          SyntacticMaskingDetector.INSTRUCTION_SIGNALS.test(trimmed);

        const confidence = hasInstruction
          ? Math.min(pattern.baseConfidence + 0.35, 1.0)
          : pattern.baseConfidence;

        if (!hasInstruction && pattern.baseConfidence < 0.5) continue;

        matches.push({
          pattern: pattern.label,
          match: match[0],
          index: match.index,
          length: match[0].length,
          confidence,
          severity: hasInstruction ? 'high' : pattern.severity,
          description: hasInstruction
            ? `${pattern.label} contains instruction-like language`
            : pattern.label,
        });
      }
    }

    return matches;
  }

  sanitize(content: string, threats: Threat[]): string {
    let result = content;
    const sorted = [...threats]
      .filter((t) => t.location)
      .sort((a, b) => (b.location?.offset ?? 0) - (a.location?.offset ?? 0));

    for (const threat of sorted) {
      if (!threat.location) continue;
      const { offset, length } = threat.location;
      result = result.slice(0, offset) + result.slice(offset + length);
    }

    return result;
  }
}
