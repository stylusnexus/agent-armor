import { BaseDetector, type PatternMatch } from '../base';
import type { Threat, TrapCategory, TrapType } from '../../types';

/**
 * Detects sub-agent spawning traps.
 *
 * Reference: Triedman et al. (2025) — adversarial content hijacks
 * multi-agent control flow with 58-90% success rate.
 */
export class SubAgentSpawningDetector extends BaseDetector {
  readonly id = 'sub-agent-spawning';
  readonly name = 'Sub-Agent Spawning Detector';
  readonly category: TrapCategory = 'behavioural-control';
  protected readonly trapType: TrapType = 'sub-agent-spawning';

  private static readonly PATTERNS: Array<{
    regex: RegExp;
    severity: 'high' | 'critical';
    confidence: number;
    label: string;
  }> = [
    {
      regex:
        /(?:create|spawn|instantiate|launch|start|initialize|invoke|call|run)\s+(?:a\s+)?(?:new\s+)?(?:agent|sub[\s-]?agent|assistant|worker|helper|bot|process|thread|task)/gi,
      severity: 'high',
      confidence: 0.7,
      label: 'Agent spawning instruction',
    },
    {
      regex:
        /(?:with|using)\s+(?:the\s+)?(?:system\s+)?(?:prompt|instructions?|role)\s*[=:]\s*["'`]/gi,
      severity: 'critical',
      confidence: 0.85,
      label: 'System prompt for spawned agent',
    },
    {
      regex:
        /(?:grant|give|enable|allow|provide|add)\s+(?:the\s+)?(?:agent|assistant|it|them)\s+(?:access|permission|ability|capability)\s+to\s+(?:read|write|delete|run|browse|fetch|call)/gi,
      severity: 'critical',
      confidence: 0.85,
      label: 'Tool privilege escalation request',
    },
    {
      regex:
        /(?:delegate|forward|route|pass|hand[\s-]?off)\s+(?:this\s+)?(?:task|request|work|job)\s+to\s+/gi,
      severity: 'high',
      confidence: 0.6,
      label: 'Task delegation to external service',
    },
    {
      regex:
        /(?:spin\s+up|create)\s+(?:a\s+)?(?:critic|reviewer|validator|checker)\s+[\s\S]{0,100}(?:approve|accept|pass|allow|authorize)/gi,
      severity: 'critical',
      confidence: 0.9,
      label: 'Poisoned critic agent spawning',
    },
    {
      regex:
        /(?:add|insert|inject)\s+(?:a\s+)?(?:step|stage|phase|node)\s+(?:to|into|in)\s+(?:the\s+)?(?:pipeline|workflow|chain|graph)/gi,
      severity: 'high',
      confidence: 0.75,
      label: 'Pipeline/workflow injection',
    },
  ];

  findPatterns(content: string): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const pattern of SubAgentSpawningDetector.PATTERNS) {
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
        '[BLOCKED: agent spawning instruction removed by AgentArmor]' +
        result.slice(offset + length);
    }

    return result;
  }
}
