import { BaseDetector, type PatternMatch } from '../base';
import type { Threat, TrapCategory, TrapType } from '../../types';

/**
 * Detects embedded jailbreak sequences in external content.
 *
 * Reference: Evtimov et al. (2025) — WASP benchmark shows prompt
 * injections can partially commandeer agents in up to 86% of scenarios.
 */
export class JailbreakPatternDetector extends BaseDetector {
  readonly id = 'jailbreak-patterns';
  readonly name = 'Jailbreak Pattern Detector';
  readonly category: TrapCategory = 'behavioural-control';
  protected readonly trapType: TrapType = 'embedded-jailbreak';

  private static readonly PATTERNS: Array<{
    regex: RegExp;
    severity: 'medium' | 'high' | 'critical';
    confidence: number;
    label: string;
  }> = [
    {
      regex:
        /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier|your)\s+(?:instructions?|rules?|guidelines?|constraints?|directives?)/gi,
      severity: 'critical',
      confidence: 0.95,
      label: 'Instruction override attempt',
    },
    {
      regex: /(?:^|\n)\s*(?:SYSTEM|System)\s*:\s*.{10,}/gm,
      severity: 'critical',
      confidence: 0.9,
      label: 'System prompt injection',
    },
    {
      regex:
        /(?:you are now|from now on you|act as|pretend (?:to be|you are)|roleplay as|imagine you are)\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|DAN|evil|unethical)/gi,
      severity: 'critical',
      confidence: 0.95,
      label: 'Role assignment jailbreak',
    },
    {
      regex:
        /(?:for\s+(?:educational|research|academic|security)\s+purposes?\s+only|this\s+is\s+(?:a|an)\s+(?:hypothetical|thought\s+experiment|simulation|red[\s-]?team))/gi,
      severity: 'high',
      confidence: 0.7,
      label: 'Educational/hypothetical framing bypass',
    },
    {
      regex: /\bD\.?A\.?N\.?\b.*(?:mode|enabled|activated|jailbreak)/gi,
      severity: 'critical',
      confidence: 0.95,
      label: 'DAN jailbreak keyword',
    },
    {
      regex:
        /(?:in\s+(?:this|a)\s+(?:fictional|alternate|hypothetical)\s+(?:world|universe|scenario|reality))\s*[,.]?\s*(?:you|there\s+are\s+no|all\s+restrictions)/gi,
      severity: 'high',
      confidence: 0.8,
      label: 'Fictional context bypass',
    },
    {
      regex:
        /(?:developer|admin|debug|maintenance|root|sudo|superuser|override)\s+mode\s+(?:enabled|activated|on|initiated)/gi,
      severity: 'critical',
      confidence: 0.9,
      label: 'False privilege escalation claim',
    },
    {
      regex:
        /(?:new\s+conversation|reset\s+context|clear\s+(?:all\s+)?(?:previous|prior)\s+(?:context|messages|history))/gi,
      severity: 'high',
      confidence: 0.85,
      label: 'Context reset attempt',
    },
    {
      regex: /(?:base64|atob|decode|unescape|fromCharCode)\s*\([^)]*\)/gi,
      severity: 'medium',
      confidence: 0.5,
      label: 'Possible encoded instruction',
    },
  ];

  findPatterns(content: string): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const pattern of JailbreakPatternDetector.PATTERNS) {
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
        '[BLOCKED: potential jailbreak sequence removed by AgentArmor]' +
        result.slice(offset + length);
    }

    return result;
  }
}
