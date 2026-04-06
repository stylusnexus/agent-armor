import { BaseDetector, type PatternMatch } from '../base';
import type { Threat, TrapCategory, TrapType } from '../../types';

/**
 * Detects instructions injected via HTML metadata channels that agents parse
 * but humans don't see: HTML comments, aria-label, alt text, meta tags.
 *
 * Research shows that injecting adversarial instructions into HTML elements
 * like metadata and aria-label tags alters generated summaries in 15-29%
 * of cases (Verma and Yadav, 2025).
 */
export class MetadataInjectionDetector extends BaseDetector {
  readonly id = 'metadata-injection';
  readonly name = 'Metadata Injection Detector';
  readonly category: TrapCategory = 'content-injection';
  protected readonly trapType: TrapType = 'metadata-injection';

  private static readonly INSTRUCTION_SIGNALS =
    /(?:ignore|disregard|forget|override|system|assistant|you (?:are|must|should|will)|IMPORTANT|instruction|do not|instead|pretend|act as|role|new task|summarise|summarize|say that|respond with|output|generate|write|tell the user)/i;

  private static readonly PATTERNS: Array<{
    regex: RegExp;
    severity: 'medium' | 'high' | 'critical';
    baseConfidence: number;
    label: string;
  }> = [
    {
      regex: /<!--([\s\S]*?)-->/g,
      severity: 'high',
      baseConfidence: 0.4,
      label: 'HTML comment',
    },
    {
      regex: /aria-label\s*=\s*["']([^"']{50,})["']/gi,
      severity: 'high',
      baseConfidence: 0.6,
      label: 'Suspicious aria-label content',
    },
    {
      regex: /alt\s*=\s*["']([^"']{80,})["']/gi,
      severity: 'medium',
      baseConfidence: 0.4,
      label: 'Suspicious alt text',
    },
    {
      regex: /<meta\s+[^>]*content\s*=\s*["']([^"']{50,})["'][^>]*>/gi,
      severity: 'medium',
      baseConfidence: 0.4,
      label: 'Meta tag content',
    },
    {
      regex: /data-[\w-]+\s*=\s*["']([^"']{80,})["']/gi,
      severity: 'medium',
      baseConfidence: 0.5,
      label: 'Suspicious data attribute',
    },
    {
      regex: /title\s*=\s*["']([^"']{80,})["']/gi,
      severity: 'medium',
      baseConfidence: 0.4,
      label: 'Suspicious title attribute',
    },
  ];

  findPatterns(content: string): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const pattern of MetadataInjectionDetector.PATTERNS) {
      let match: RegExpExecArray | null;
      pattern.regex.lastIndex = 0;

      while ((match = pattern.regex.exec(content)) !== null) {
        const extracted = match[1] ?? '';
        const trimmed = extracted.trim();
        if (trimmed.length < 10) continue;

        const hasInstruction =
          MetadataInjectionDetector.INSTRUCTION_SIGNALS.test(trimmed);

        const confidence = hasInstruction
          ? Math.min(pattern.baseConfidence + 0.4, 1.0)
          : pattern.baseConfidence;

        const severity: 'medium' | 'high' | 'critical' = hasInstruction
          ? pattern.severity === 'high'
            ? 'critical'
            : 'high'
          : pattern.severity;

        matches.push({
          pattern: pattern.label,
          match: match[0],
          index: match.index,
          length: match[0].length,
          confidence,
          severity,
          description: hasInstruction
            ? `${pattern.label} contains instruction-like language`
            : `${pattern.label} with unusually long content`,
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
      const original = result.slice(offset, offset + length);

      if (original.startsWith('<!--')) {
        result = result.slice(0, offset) + result.slice(offset + length);
      } else {
        result =
          result.slice(0, offset) +
          original.replace(/=\s*["'][^"']*["']/, '=""') +
          result.slice(offset + length);
      }
    }

    return result;
  }
}
