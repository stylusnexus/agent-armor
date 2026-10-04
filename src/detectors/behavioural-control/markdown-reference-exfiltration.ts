import { BaseDetector, type PatternMatch } from '../base';
import { applyEdits, mergeEdits } from '../../sanitize';
import { regexFinder } from '../../patterns/matchers/scan-helpers';
import type { TextEdit, Threat, TrapCategory, TrapType } from '../../types';

const KEYWORDS =
  '(?:data|token|secret|key|context|conversation|history|session|password|credential|api[_-]?key|env)';

/** The longest reference label CommonMark accepts. */
const MAX_LABEL = 999;

/**
 * `[label]: destination`, with any mix of spaces, tabs and `>` before the `[`
 * (so a definition inside a block quote or a list item counts), and the
 * destination on the same line, on the next line, or in `<...>`. The
 * destination is read in a lookahead so a match only consumes `[label]:`: a
 * line that happens to look like a definition cannot swallow the real
 * definition on the next line.
 */
const DEFINITION =
  /^[ \t>]*\[([^\]\n\r\u2028\u2029]{1,999})\]:(?=[ \t]*(?:\r?\n[ \t>]*)?(<[^>\n\r\u2028\u2029]+>|[^\s<]\S*))/gm;

/** A destination that sends data out: an http(s) or scheme-relative URL whose query holds a data keyword. */
const EXFIL_DESTINATION = new RegExp('^<?(?:https?:)?\\/\\/[^\\s>?]*\\?[^\\s>]*?' + KEYWORDS + '\\b', 'i');

/** Flagged images this close together (only whitespace between) are reported as one finding. */
const MERGE_GAP = 100;

const MARKER = '[BLOCKED: exfiltration instruction removed by AgentArmor]';

/** Markdown matches reference labels case-insensitively with whitespace runs collapsed. */
function normalizeLabel(label: string): string {
  return label.trim().replace(/\s+/g, ' ').toLowerCase();
}

/**
 * Detects a reference-style markdown image whose definition sends data out
 * (#219): `![alt][ref]` plus `[ref]: https://host/path?data=...`, where the
 * image loads the URL and so leaks whatever the query carries (the EchoLeak
 * shape). It finds the definition before or after the image, at any distance
 * and with any URL length, and for full, collapsed (`![alt][]`) and shortcut
 * (`![alt]`) references, which a fixed-window regex cannot do without a cap
 * that padding evades.
 *
 * A label is flagged if ANY definition of it sends data out: a decoy
 * definition placed first (in a code fence, a comment, a paragraph) must not
 * hide the real one, and the scan cannot tell which definition a renderer
 * will use.
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
    // label -> the first definition of it that sends data out
    const flagged = new Map<string, { index: number; length: number }>();
    DEFINITION.lastIndex = 0;
    let def: RegExpExecArray | null;
    while ((def = DEFINITION.exec(content)) !== null) {
      const label = normalizeLabel(def[1]);
      if (flagged.has(label)) continue;
      if (EXFIL_DESTINATION.test(def[2])) {
        // Only whitespace separates `[label]:` from its destination, so the first hit is the destination.
        const destAt = content.indexOf(def[2], def.index + def[0].length);
        flagged.set(label, { index: def.index, length: destAt + def[2].length - def.index });
      }
    }
    if (flagged.size === 0) return [];

    // Next `]` or line break at or after a position, remembered so a run of
    // `![` openers does not rescan to the same far `]`.
    const nextStop = regexFinder(content, /[\]\n\r\u2028\u2029]/g);
    const matches: PatternMatch[] = [];
    // Flagged images that sit next to each other become one finding, so a run of tiny images is replaced by one marker.
    let pending: { index: number; end: number; related: { index: number; length: number } } | undefined;
    const flush = (): void => {
      if (!pending) return;
      matches.push({
        pattern: 'Reference-style markdown image data exfiltration',
        match: content.slice(pending.index, pending.end),
        index: pending.index,
        length: pending.end - pending.index,
        confidence: 0.85,
        severity: 'critical',
        description: 'Reference-style markdown image data exfiltration',
        related: pending.related,
      });
      pending = undefined;
    };
    let at = content.indexOf('![');
    while (at >= 0) {
      const altEnd = nextStop(at + 2);
      if (altEnd < 0 || content[altEnd] !== ']') {
        at = content.indexOf('![', at + 1);
        continue;
      }
      const afterAlt = altEnd + 1;
      let end = afterAlt;
      let labelText: string | undefined;
      if (content[afterAlt] === '[') {
        const labelEnd = nextStop(afterAlt + 1);
        if (labelEnd >= 0 && content[labelEnd] === ']' && labelEnd - (afterAlt + 1) <= MAX_LABEL) {
          end = labelEnd + 1;
          const explicit = content.slice(afterAlt + 1, labelEnd);
          if (explicit.trim() !== '') labelText = explicit;
        }
      } else if (content[afterAlt] === '(') {
        at = content.indexOf('![', at + 1); // an inline image, not a reference
        continue;
      }
      if (labelText === undefined && altEnd - (at + 2) <= MAX_LABEL) labelText = content.slice(at + 2, altEnd);
      const label = labelText === undefined ? '' : normalizeLabel(labelText);
      const related = label === '' ? undefined : flagged.get(label);
      if (related) {
        if (pending && at - pending.end <= MERGE_GAP && /^\s*$/.test(content.slice(pending.end, at))) {
          pending.end = end;
        } else {
          flush();
          pending = { index: at, end, related };
        }
      }
      at = content.indexOf('![', end);
    }
    flush();
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

