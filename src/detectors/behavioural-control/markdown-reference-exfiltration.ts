import { BaseDetector, type PatternMatch } from '../base';
import { applyEdits, mergeEdits } from '../../sanitize';
import type { TextEdit, Threat, TrapCategory, TrapType } from '../../types';

const KEYWORDS =
  '(?:data|token|secret|key|context|conversation|history|session|password|credential|api[_-]?key|env)';

/** The longest reference label CommonMark accepts. */
const MAX_LABEL = 999;

/**
 * `[label]: destination`, with any mix of spaces, tabs and `>` before the `[`
 * (so a definition inside a block quote or a list item counts), and the
 * destination on the same line, on the next line, or in `<...>`.
 *
 * The label follows CommonMark: no unescaped brackets, backslash escapes
 * (`\]`), and it may continue over line breaks (`\n`, `\r` or `\r\n`) but
 * not across a blank line. The destination is read in a lookahead so a match
 * only consumes `[label]:`: a line that happens to look like a definition
 * cannot swallow the real definition on the next line.
 */
const DEFINITION =
  /^[ \t>]*\[((?:[^[\]\\\r\n]|\\[\s\S]|(?:\r\n|\r|\n)(?![ \t]*(?:\r\n|\r|\n|(?![\s\S])))){1,999})\]:(?=[ \t]*(?:(?:\r\n|\r|\n)[ \t>]*)?(<[^>\r\n]+>|[^\s<]\S*))/gm;

/** A destination that sends data out: an http(s) or scheme-relative URL whose query holds a data keyword. */
const EXFIL_DESTINATION = new RegExp('^<?(?:https?:)?\\/\\/[^\\s>?]*\\?[^\\s>]*?' + KEYWORDS + '\\b', 'i');

/** Flagged images this close together (only whitespace between) are reported as one finding. */
const MERGE_GAP = 100;

const MARKER = '[BLOCKED: exfiltration instruction removed by AgentArmor]';

/**
 * Markdown matches reference labels after trimming, collapsing whitespace runs
 * (line breaks included) and Unicode case folding. Lowercase, uppercase,
 * lowercase approximates the fold: it turns `ß` and `SS` into the same `ss`.
 */
function normalizeLabel(label: string): string {
  return label.trim().replace(/\s+/g, ' ').toLowerCase().toUpperCase().toLowerCase();
}

/**
 * Pairs every `[` with its `]` in one pass, the way a markdown parser does:
 * backslash escapes skip a character, brackets nest, and a blank line ends the
 * paragraph, so brackets still open at that point never match.
 */
function pairBrackets(content: string): { close: Int32Array; hasInner: Uint8Array } {
  const n = content.length;
  const close = new Int32Array(n).fill(-1);
  const hasInner = new Uint8Array(n);
  const open: number[] = [];
  let i = 0;
  while (i < n) {
    const c = content.charCodeAt(i);
    if (c === 92) {
      i += 2; // a backslash escapes the next character
    } else if (c === 91) {
      if (open.length > 0) hasInner[open[open.length - 1]] = 1;
      open.push(i);
      i++;
    } else if (c === 93) {
      const o = open.pop();
      if (o !== undefined) close[o] = i;
      i++;
    } else if (c === 10 || c === 13) {
      i += c === 13 && content.charCodeAt(i + 1) === 10 ? 2 : 1;
      let k = i;
      while (k < n && (content.charCodeAt(k) === 32 || content.charCodeAt(k) === 9)) k++;
      if (k >= n || content.charCodeAt(k) === 10 || content.charCodeAt(k) === 13) open.length = 0; // blank line
    } else {
      i++;
    }
  }
  return { close, hasInner };
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

    const { close, hasInner } = pairBrackets(content);
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
      const altOpen = at + 1;
      const altEnd = close[altOpen];
      if (altEnd < 0) {
        at = content.indexOf('![', at + 1);
        continue;
      }
      const afterAlt = altEnd + 1;
      let end = afterAlt;
      let labelText: string | undefined;
      if (content[afterAlt] === '[') {
        const labelEnd = close[afterAlt];
        if (labelEnd >= 0 && !hasInner[afterAlt] && labelEnd - afterAlt - 1 <= MAX_LABEL) {
          end = labelEnd + 1;
          const explicit = content.slice(afterAlt + 1, labelEnd);
          if (explicit.trim() !== '') labelText = explicit;
          else if (!hasInner[altOpen] && altEnd - altOpen - 1 <= MAX_LABEL) labelText = content.slice(altOpen + 1, altEnd);
        }
      } else if (content[afterAlt] === '(') {
        at = content.indexOf('![', at + 1); // an inline image, not a reference
        continue;
      }
      // A shortcut reference (and a collapsed one) uses the alt text as its label, which cannot hold brackets.
      if (labelText === undefined && end === afterAlt && !hasInner[altOpen] && altEnd - altOpen - 1 <= MAX_LABEL) {
        labelText = content.slice(altOpen + 1, altEnd);
      }
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

