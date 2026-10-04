import { BaseDetector, type PatternMatch } from '../base';
import { applyEdits, mergeEdits } from '../../sanitize';
import { normalizeForScan } from '../../normalize/unicode';
import type { TextEdit, Threat, TrapCategory, TrapType } from '../../types';

const KEYWORDS =
  '(?:data|token|secret|key|context|conversation|history|session|password|credential|api[_-]?key|env)';

/** Whitespace a renderer trims around a destination: JavaScript's own trim set, minus line breaks. */
const GAP = '[ \\t\\u00a0\\u1680\\u2000-\\u200a\\u202f\\u205f\\u3000\\ufeff]';

/**
 * `[label]: destination`, preceded by any mix of spaces, tabs, `>` block quote
 * markers and list markers (`-`, `*`, `+`, `1.`, `1)`), so a definition inside
 * a quote or a list item counts, and followed by the destination on the same
 * line, on the next line, or in `<...>`.
 *
 * The label follows CommonMark: no unescaped brackets, backslash escapes
 * (`\]`), and it may continue over line breaks (`\n`, `\r` or `\r\n`) but
 * not across a blank line. There is no length cap: renderers accept any
 * length, so a cap is just padding to pass. The destination is read in a
 * lookahead so a match only consumes `[label]:`: a line that happens to look
 * like a definition cannot swallow the real definition on the next line.
 */
const DEFINITION = new RegExp(
  '^(?:[ \\t>]|[-*+](?=[ \\t])|\\d{1,9}[.)](?=[ \\t]))*\\[((?:[^[\\]\\\\\\r\\n]|\\\\[\\s\\S]|(?:\\r\\n|\\r|\\n)(?![ \\t]*(?:\\r\\n|\\r|\\n|(?![\\s\\S])))){1,})\\]:' +
    '(?=' + GAP + '*(?:(?:\\r\\n|\\r|\\n)(?:' + GAP + '|>)*)?(<(?:[^>\\\\\\r\\n]|\\\\[^\\r\\n])+>|[^\\s<]\\S*))',
  'gm',
);

/** A destination that sends data out: an http(s) or scheme-relative URL whose query holds a data keyword. */
const EXFIL_DESTINATION = new RegExp('^<?(?:https?:)?\\/\\/[^\\s>?]*\\?[^\\s>]*?' + KEYWORDS + '\\b', 'i');
/** The same inside `<...>`, where a destination may hold spaces (a renderer encodes them). */
const EXFIL_ANGLE_DESTINATION = new RegExp('^<(?:https?:)?\\/\\/[^>?]*\\?[^>]*?' + KEYWORDS + '\\b', 'i');

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", quest: '?', colon: ':', sol: '/', bsol: '\\', num: '#', equals: '=',
  period: '.', comma: ',', semi: ';', excl: '!', lowbar: '_', lpar: '(', rpar: ')', commat: '@', percnt: '%', plus: '+', Tab: '\t',
};

/**
 * What a renderer and the server behind the URL would see: HTML entities and
 * backslash escapes resolved, percent-encoded letters and digits decoded, then
 * the scan's own Unicode normalization applied (fullwidth forms, look-alike
 * letters, invisible characters), so `%64ata`, `d&#97;ta`, `\uFF44ata` and a
 * Cyrillic `\u0430` all read as `data`.
 */
function decodeDestination(dest: string): string {
  const resolved = dest
    .replace(/&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|([a-zA-Z]{2,6}));/g, (m, dec, hex, name) => {
      if (name) return NAMED_ENTITIES[name] ?? m;
      const cp = dec ? parseInt(dec, 10) : parseInt(hex, 16);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    })
    .replace(/\\([!-/:-@[-`{-~])/g, '$1')
    .replace(/%([2-7][0-9A-Fa-f])/g, (m, h) => {
      const c = String.fromCharCode(parseInt(h, 16));
      return /[A-Za-z0-9_-]/.test(c) ? c : m;
    });
  return normalizeForScan(resolved).normalized;
}

function sendsDataOut(dest: string): boolean {
  const angle = dest.startsWith('<');
  // `\>` inside `<...>` is part of the URL; keep it from ending the destination once unescaped.
  const decoded = decodeDestination(angle ? dest.replace(/\\>/g, '%3E') : dest);
  return (angle ? EXFIL_ANGLE_DESTINATION : EXFIL_DESTINATION).test(decoded);
}

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

interface BracketInfo {
  /** For each `[`: the `]` that closes it, or -1. */
  close: Int32Array;
  /** For each `[`: 1 if another unescaped `[` sits inside it. */
  hasInner: Uint8Array;
  /** For each image's `[` (the one after `!`): the first unescaped `]` after it in the same paragraph. */
  firstClose: Map<number, number>;
  /** Each unpaired `]` followed by `[label]`, after an earlier `]`, in an image's paragraph: the opener's `!` and the label's `[`. */
  labelAfterImage: Array<{ bang: number; labelOpen: number }>;
}

/**
 * One pass over the text, the way a markdown parser reads brackets:
 * backslash escapes skip a character, brackets nest, and a blank line ends the
 * paragraph, so brackets still open at that point never match. It also records
 * the first `]` after each `![` and every `][label]` that follows one, so the
 * image can be read more than one way: a stray `[` inside the alt text (in a
 * code span, an autolink, or just unpaired) must not hide it.
 */
function analyzeBrackets(content: string): BracketInfo {
  const n = content.length;
  const close = new Int32Array(n).fill(-1);
  const hasInner = new Uint8Array(n);
  const firstClose = new Map<number, number>();
  const labelAfterImage: Array<{ bang: number; labelOpen: number }> = [];
  const open: number[] = [];
  let waiting: number[] = []; // image `[`s still waiting for their first `]`
  let lastBang = -1;
  let closesSinceBang = 0;
  let i = 0;
  while (i < n) {
    const c = content.charCodeAt(i);
    if (c === 92) {
      i += 2; // a backslash escapes the next character
    } else if (c === 91) {
      if (open.length > 0) hasInner[open[open.length - 1]] = 1;
      open.push(i);
      if (i > 0 && content.charCodeAt(i - 1) === 33) {
        lastBang = i - 1;
        closesSinceBang = 0;
        waiting.push(i);
      }
      i++;
    } else if (c === 93) {
      const o = open.pop();
      if (o !== undefined) close[o] = i;
      for (const w of waiting) firstClose.set(w, i);
      waiting = [];
      if (lastBang >= 0) {
        // A `]` with nothing to close, after an earlier `]`, followed by `[label]`: the alt text ended
        // here, and the earlier `]` (in a code span, say) was not its end.
        if (o === undefined && closesSinceBang > 0 && content.charCodeAt(i + 1) === 91) {
          labelAfterImage.push({ bang: lastBang, labelOpen: i + 1 });
        }
        closesSinceBang++;
      }
      i++;
    } else if (c === 10 || c === 13) {
      i += c === 13 && content.charCodeAt(i + 1) === 10 ? 2 : 1;
      let k = i;
      while (k < n && (content.charCodeAt(k) === 32 || content.charCodeAt(k) === 9)) k++;
      if (k >= n || content.charCodeAt(k) === 10 || content.charCodeAt(k) === 13) {
        open.length = 0; // a blank line ends the paragraph
        waiting = [];
        lastBang = -1;
      }
    } else {
      i++;
    }
  }
  return { close, hasInner, firstClose, labelAfterImage };
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
      if (sendsDataOut(def[2])) {
        // Only whitespace separates `[label]:` from its destination, so the first hit is the destination.
        const destAt = content.indexOf(def[2], def.index + def[0].length);
        flagged.set(label, { index: def.index, length: destAt + def[2].length - def.index });
      }
    }
    if (flagged.size === 0) return [];

    const { close, hasInner, firstClose, labelAfterImage } = analyzeBrackets(content);
    const hits: Array<{ index: number; end: number; related: { index: number; length: number } }> = [];

    // Each `[label]` is read once, however many image openers wait on it.
    const labelCache = new Map<number, { end: number; norm: string; blank: boolean } | null>();
    const labelAt = (open: number): { end: number; norm: string; blank: boolean } | null => {
      const cached = labelCache.get(open);
      if (cached !== undefined) return cached;
      const labelEnd = close[open];
      let info: { end: number; norm: string; blank: boolean } | null = null;
      if (labelEnd >= 0 && !hasInner[open]) {
        const text = content.slice(open + 1, labelEnd);
        info = { end: labelEnd + 1, norm: normalizeLabel(text), blank: text.trim() === '' };
      }
      labelCache.set(open, info);
      return info;
    };

    /** The image whose alt text ends at `altEnd`, read as a full, collapsed or shortcut reference. */
    const readImage = (at: number, altEnd: number): void => {
      const altOpen = at + 1;
      const afterAlt = altEnd + 1;
      let end = afterAlt;
      let label = '';
      if (content[afterAlt] === '[') {
        const info = labelAt(afterAlt);
        if (info) {
          end = info.end;
          if (!info.blank) label = info.norm;
          else if (!hasInner[altOpen]) label = normalizeLabel(content.slice(altOpen + 1, altEnd));
        }
      } else if (content[afterAlt] === '(') {
        return; // an inline image, not a reference
      }
      // A shortcut reference (and a collapsed one) uses the alt text as its label, which cannot hold brackets.
      if (label === '' && end === afterAlt && !hasInner[altOpen]) label = normalizeLabel(content.slice(altOpen + 1, altEnd));
      const related = label === '' ? undefined : flagged.get(label);
      if (related) hits.push({ index: at, end, related });
    };

    let at = content.indexOf('![');
    while (at >= 0) {
      const altOpen = at + 1;
      const paired = close[altOpen];
      if (paired >= 0) readImage(at, paired);
      const first = firstClose.get(altOpen);
      if (first !== undefined && first !== paired) readImage(at, first);
      at = content.indexOf('![', at + 1);
    }
    // An unpaired `]` before `[label]` after an earlier `]` ends the alt text, whatever it held.
    for (const { bang, labelOpen } of labelAfterImage) {
      const info = labelAt(labelOpen);
      if (!info || info.norm === '') continue;
      const related = flagged.get(info.norm);
      if (related) hits.push({ index: bang, end: info.end, related });
    }
    if (hits.length === 0) return [];

    // Overlapping readings of one image are one finding; flagged images that sit next to each other
    // (only whitespace between) are one finding too, so a run of tiny images is replaced by one marker.
    hits.sort((x, y) => x.index - y.index || y.end - x.end);
    const matches: PatternMatch[] = [];
    let cur = { ...hits[0] };
    const flush = (): void => {
      matches.push({
        pattern: 'Reference-style markdown image data exfiltration',
        match: content.slice(cur.index, cur.end),
        index: cur.index,
        length: cur.end - cur.index,
        confidence: 0.85,
        severity: 'critical',
        description: 'Reference-style markdown image data exfiltration',
        related: cur.related,
      });
    };
    for (let k = 1; k < hits.length; k++) {
      const h = hits[k];
      const gap = h.index - cur.end;
      if (gap < 0 || (gap <= MERGE_GAP && /^\s*$/.test(content.slice(cur.end, h.index)))) {
        cur.end = Math.max(cur.end, h.end);
      } else {
        flush();
        cur = { ...h };
      }
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

