import { BaseDetector, type PatternMatch } from '../base';
import type { Threat, TrapCategory, TrapType } from '../../types';

/**
 * Detects instructions hidden via CSS/HTML that are invisible to humans
 * but parsed by LLMs. This is the most common content injection vector.
 *
 * Covers:
 * - CSS display:none / visibility:hidden elements with text content
 * - Off-screen positioned elements (position:absolute with extreme offsets)
 * - Zero-size elements (width:0, height:0, font-size:0)
 * - Background-matching text color
 * - Opacity:0 elements
 */
export class HiddenHTMLDetector extends BaseDetector {
  readonly id = 'hidden-html';
  readonly name = 'Hidden HTML Detector';
  readonly category: TrapCategory = 'content-injection';
  protected readonly trapType: TrapType = 'hidden-html';

  private static readonly HIDING_PATTERNS: Array<{
    regex: RegExp;
    severity: 'medium' | 'high' | 'critical';
    confidence: number;
    label: string;
  }> = [
    {
      regex:
        /<[^>]+style\s*=\s*["'][^"']*display\s*:\s*none[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
      severity: 'high',
      confidence: 0.85,
      label: 'CSS display:none hiding content',
    },
    {
      regex:
        /<[^>]+style\s*=\s*["'][^"']*visibility\s*:\s*hidden[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
      severity: 'high',
      confidence: 0.85,
      label: 'CSS visibility:hidden hiding content',
    },
    {
      regex:
        /<[^>]+style\s*=\s*["'][^"']*(?:left|top|right|bottom)\s*:\s*-\d{3,}px[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
      severity: 'high',
      confidence: 0.8,
      label: 'Off-screen positioning hiding content',
    },
    {
      regex:
        /<[^>]+style\s*=\s*["'][^"']*(?:font-size\s*:\s*0|width\s*:\s*0|height\s*:\s*0)[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
      severity: 'medium',
      confidence: 0.7,
      label: 'Zero-size element hiding content',
    },
    {
      regex:
        /<[^>]+style\s*=\s*["'][^"']*opacity\s*:\s*0[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
      severity: 'medium',
      confidence: 0.7,
      label: 'Opacity:0 hiding content',
    },
    {
      regex:
        /<[^>]+style\s*=\s*["'][^"']*overflow\s*:\s*hidden[^"']*(?:max-height|max-width)\s*:\s*[01]px[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
      severity: 'medium',
      confidence: 0.65,
      label: 'Overflow-hidden micro container',
    },
    {
      regex:
        /<[^>]+style\s*=\s*["'][^"']*color\s*:\s*(white|#fff(?:fff)?|rgba?\(\s*255)[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
      severity: 'medium',
      confidence: 0.5,
      label: 'Possible background-matching text color',
    },
  ];

  private static readonly INSTRUCTION_SIGNALS =
    /(?:ignore|disregard|forget|override|system|assistant|you (?:are|must|should|will)|IMPORTANT|instruction|do not|instead|pretend|act as|role|new task)/i;

  findPatterns(content: string): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const pattern of HiddenHTMLDetector.HIDING_PATTERNS) {
      let match: RegExpExecArray | null;
      pattern.regex.lastIndex = 0;

      while ((match = pattern.regex.exec(content)) !== null) {
        const hiddenText = match[1] ?? match[2] ?? '';
        const trimmed = hiddenText.trim();

        if (trimmed.length < 5) continue;

        const hasInstruction =
          HiddenHTMLDetector.INSTRUCTION_SIGNALS.test(trimmed);
        const adjustedConfidence = hasInstruction
          ? Math.min(pattern.confidence + 0.15, 1.0)
          : pattern.confidence;
        const adjustedSeverity: 'medium' | 'high' | 'critical' =
          hasInstruction && pattern.severity === 'high'
            ? 'critical'
            : pattern.severity;

        matches.push({
          pattern: pattern.label,
          match: match[0],
          index: match.index,
          length: match[0].length,
          confidence: adjustedConfidence,
          severity: adjustedSeverity,
          description: hasInstruction
            ? `${pattern.label} with instruction-like language`
            : `${pattern.label}`,
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
