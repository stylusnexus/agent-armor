import { BaseDetector, type PatternMatch } from '../base';
import type { Threat, TrapCategory, TrapType } from '../../types';

/**
 * Detects JavaScript patterns that conditionally serve different content
 * to AI agents vs human users.
 *
 * Reference: Zychlinski (2025) — fingerprinting scripts that detect
 * LLM-powered web agents and serve semantically different pages.
 */
export class DynamicCloakingDetector extends BaseDetector {
  readonly id = 'dynamic-cloaking';
  readonly name = 'Dynamic Cloaking Detector';
  readonly category: TrapCategory = 'content-injection';
  protected readonly trapType: TrapType = 'dynamic-cloaking';

  private static readonly PATTERNS: Array<{
    regex: RegExp;
    severity: 'medium' | 'high';
    confidence: number;
    label: string;
  }> = [
    {
      regex:
        /(?:navigator\.userAgent|user[\s_-]?agent)[\s\S]{0,100}(?:bot|crawl|spider|scrape|headless|phantom|puppeteer|playwright|selenium|webdriver)/gi,
      severity: 'high',
      confidence: 0.75,
      label: 'User-agent bot detection',
    },
    {
      regex:
        /(?:navigator\.webdriver|window\.webdriver|__selenium|__webdriver|callPhantom|_phantom|phantom\.callback)/gi,
      severity: 'high',
      confidence: 0.8,
      label: 'Automation framework detection',
    },
    {
      regex:
        /if\s*\([^)]*(?:isBot|is_bot|isRobot|isCrawler|isAgent|isAutomated)[^)]*\)\s*\{[\s\S]{0,500}\}/gi,
      severity: 'high',
      confidence: 0.85,
      label: 'Conditional content based on bot detection',
    },
    {
      regex:
        /(?:innerHTML|textContent|innerText)\s*=[\s\S]{0,200}(?:bot|agent|crawl|automated)/gi,
      severity: 'medium',
      confidence: 0.6,
      label: 'Dynamic content modification with bot references',
    },
    {
      regex:
        /(?:window\.chrome\s*&&\s*!window\.chrome\.runtime|navigator\.languages\.length\s*===\s*0|!navigator\.plugins\.length)/gi,
      severity: 'medium',
      confidence: 0.7,
      label: 'Headless browser fingerprinting',
    },
    {
      regex:
        /(?:performance\.now|Date\.now)[\s\S]{0,100}(?:threshold|too[\s_]?fast|bot[\s_]?detect|suspicious)/gi,
      severity: 'medium',
      confidence: 0.5,
      label: 'Timing-based bot detection',
    },
  ];

  findPatterns(content: string): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const pattern of DynamicCloakingDetector.PATTERNS) {
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

  sanitize(content: string, _threats: Threat[]): string {
    // For cloaking, we flag but don't auto-strip. Removing JS could break
    // legitimate pages. The caller decides how to handle flagged content.
    return content;
  }
}
