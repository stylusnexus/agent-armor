import { BaseDetector, type PatternMatch } from '../base';
import { applyEdits, mergeEdits } from '../../sanitize';
import type { TextEdit, Threat, TrapCategory, TrapType } from '../../types';

const KEYWORDS =
  '(?:data|token|secret|key|context|conversation|history|session|password|credential|api[_-]?key|env)';

/**
 * `[label]: destination`, destination optionally on the next line or in
 * `<...>`. The destination is read in a lookahead so a match only consumes
 * `[label]:`: a line that happens to look like a definition cannot swallow the
 * real definition on the next line.
 */
const DEFINITION = /^ {0,3}\[([^\]\n\r\u2028\u2029]{1,200})\]:(?=[ \t]*(?:\r?\n[ \t]*)?(<[^>\n\r\u2028\u2029]{1,2000}>|[^\s<]\S{0,2000}))/gm;

/** A destination that sends data out: an http(s) URL whose query holds a data keyword. */
const EXFIL_DESTINATION = new RegExp(
  '^<?https?:\\/\\/[^\\s>?]{0,200}\\?[^\\s>]{0,200}?' + KEYWORDS + '\\b',
  'i',
);

/** `![alt][label]`, `![alt][]` (collapsed) and `![alt]` (shortcut, not an inline `![alt](url)`). */
const IMAGE_REFERENCE = /!\[([^\]\n\r\u2028\u2029]{0,200})\](?:\[([^\]\n\r\u2028\u2029]{0,200})\]|(?!\())/g;

const MARKER = '[BLOCKED: exfiltration instruction removed by AgentArmor]';

/** Markdown matches reference labels case-insensitively with whitespace runs collapsed. */
function normalizeLabel(label: string): string {
  return label.trim().replace(/\s+/g, ' ').toLowerCase();
}

/**
 * Detects a reference-style markdown image whose definition sends data out
 * (#219): `![alt][ref]` plus `[ref]: https://host/path?data=...`, where the
 * image loads the URL and so leaks whatever the query carries (the EchoLeak
 * shape). It finds the definition before or after the image, at any distance,
 * and for full, collapsed (`![alt][]`) and shortcut (`![alt]`) references,
 * which a fixed-window regex cannot do without a cap that padding evades.
 *
 * One pass collects the flagged definitions by label, one pass finds the
 * images and looks the label up, so time stays linear. Inline images
 * (`![](url)`) are handled by the `ex-markdown-image` pattern.
 */
export class MarkdownReferenceExfiltrationDetector extends BaseDetector {
  readonly id = 'markdown-reference-exfiltration';
  readonly name = 'Markdown Reference Exfiltration Detector';
  readonly category: TrapCategory = 'behavioural-control';
  protected readonly trapType: TrapType = 'data-exfiltration';

  findPatterns(content: string): PatternMatch[] {
    const flagged = new Set<string>();
    const seen = new Set<string>();
    DEFINITION.lastIndex = 0;
    let def: RegExpExecArray | null;
    while ((def = DEFINITION.exec(content)) !== null) {
      const label = normalizeLabel(def[1]);
      if (seen.has(label)) continue; // the first definition of a label wins
      seen.add(label);
      if (EXFIL_DESTINATION.test(def[2])) flagged.add(label);
    }
    if (flagged.size === 0) return [];

    const matches: PatternMatch[] = [];
    IMAGE_REFERENCE.lastIndex = 0;
    let image: RegExpExecArray | null;
    while ((image = IMAGE_REFERENCE.exec(content)) !== null) {
      const label = normalizeLabel(image[2] === undefined || image[2].trim() === '' ? image[1] : image[2]);
      if (label === '' || !flagged.has(label)) continue;
      matches.push({
        pattern: 'Reference-style markdown image data exfiltration',
        match: image[0],
        index: image.index,
        length: image[0].length,
        confidence: 0.85,
        severity: 'critical',
        description: 'Reference-style markdown image data exfiltration',
      });
    }
    return matches;
  }

  sanitizeEdits(_content: string, threats: Threat[]): TextEdit[] {
    return threats
      .filter((t) => t.location)
      .map((t) => ({
        offset: t.location!.offset,
        length: t.location!.length,
        replacement: MARKER,
        severity: t.severity,
      }));
  }

  sanitize(content: string, threats: Threat[]): string {
    return applyEdits(content, mergeEdits(this.sanitizeEdits(content, threats), content.length));
  }
}
