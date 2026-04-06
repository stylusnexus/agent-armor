import { BaseDetector, type PatternMatch } from '../base';
import type { Threat, TrapCategory, TrapType } from '../../types';

/**
 * Detects data exfiltration trap patterns.
 *
 * Reference: Shapira et al. (2025) — 80%+ exfiltration success rate.
 * Reddy & Gujral (2025) — single email exfiltrated M365 Copilot context.
 */
export class ExfiltrationDetector extends BaseDetector {
  readonly id = 'exfiltration';
  readonly name = 'Data Exfiltration Detector';
  readonly category: TrapCategory = 'behavioural-control';
  protected readonly trapType: TrapType = 'data-exfiltration';

  private static readonly PATTERNS: Array<{
    regex: RegExp;
    severity: 'high' | 'critical';
    confidence: number;
    label: string;
  }> = [
    {
      regex:
        /(?:send|transmit|post|forward|upload|exfiltrate|leak|share|deliver)\s+(?:the\s+)?(?:data|content|information|context|conversation|messages?|history|credentials?|password|token|key|secret|api[\s_-]?key|session)/gi,
      severity: 'critical',
      confidence: 0.85,
      label: 'Direct data exfiltration instruction',
    },
    {
      regex:
        /(?:webhook|callback|endpoint|receiver|collector|listener)[\s\S]{0,50}(?:https?:\/\/)/gi,
      severity: 'high',
      confidence: 0.7,
      label: 'Webhook/callback exfiltration pattern',
    },
    {
      regex:
        /(?:read|access|retrieve|get|fetch|find|locate|extract)\s+[\s\S]{0,80}(?:then|and|after\s+that)\s+(?:send|post|transmit|forward|share|deliver|upload)/gi,
      severity: 'critical',
      confidence: 0.9,
      label: 'Read-then-transmit pattern',
    },
    {
      regex:
        /(?:encode|convert|transform)\s+(?:the\s+)?(?:data|content|response|context|conversation)\s+(?:to|into|as|using)\s+(?:base64|hex|url[\s-]?encoded|json)/gi,
      severity: 'high',
      confidence: 0.8,
      label: 'Data encoding for exfiltration',
    },
    {
      regex:
        /(?:read|access|open|cat|list|find)\s+(?:the\s+)?(?:file|files|directory|folder|path)\s+(?:at|in|from)\s+[\s\S]{0,50}(?:\.env|\.ssh|credentials?|password|secret|config|token)/gi,
      severity: 'critical',
      confidence: 0.9,
      label: 'Sensitive file access instruction',
    },
    {
      regex:
        /(?:send|email|mail|forward)\s+(?:the\s+)?(?:data|content|results?|output|context|summary)\s+to\s+[\w.+-]+@[\w.-]+/gi,
      severity: 'high',
      confidence: 0.8,
      label: 'Email exfiltration attempt',
    },
  ];

  findPatterns(content: string): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const pattern of ExfiltrationDetector.PATTERNS) {
      let match: RegExpExecArray | null;
      pattern.regex.lastIndex = 0;

      while ((match = pattern.regex.exec(content)) !== null) {
        matches.push({
          pattern: pattern.label,
          match: match[0],
          index: match.index,
          length: match[0].length,
          confidence: pattern.confidence,
          severity: pattern.severity,
          description: pattern.label,
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
      result =
        result.slice(0, offset) +
        '[BLOCKED: exfiltration instruction removed by AgentArmor]' +
        result.slice(offset + length);
    }

    return result;
  }
}
