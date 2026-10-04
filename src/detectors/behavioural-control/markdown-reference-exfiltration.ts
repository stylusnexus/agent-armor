import { BaseDetector, type PatternMatch } from '../base';
import { applyEdits, mergeEdits } from '../../sanitize';
import { normalizeForScan } from '../../normalize/unicode';
import type { TextEdit, Threat, TrapCategory, TrapType } from '../../types';

const KEYWORDS =
  '(?:data|token|secret|key|context|conversation|history|session|password|credential|api[_-]?key|env)';

/** ASCII punctuation, the only characters a backslash escapes. */
function isAsciiPunctuation(c: number): boolean {
  return (c >= 33 && c <= 47) || (c >= 58 && c <= 64) || (c >= 91 && c <= 96) || (c >= 123 && c <= 126);
}

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
  '^(?:[ \\t>]|[-*+](?=[ \\t])|\\d{1,9}[.)](?=[ \\t]))*\\[((?:[^[\\]\\\\\\r\\n]|\\\\[!-/:-@[-`{-~]|\\\\(?![!-/:-@[-`{-~])|(?:\\r\\n|\\r|\\n)(?![ \\t]*(?:\\r\\n|\\r|\\n|(?![\\s\\S])))){1,})\\]:' +
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
function normalizeLabel(label: string, dropQuoteMarkers: boolean): string {
  let text = label.replace(/\0/g, '\ufffd'); // a renderer reads NUL as U+FFFD
  // Block quote markers on a continuation line are not part of the label, unless the line is an indented
  // paragraph continuation, where the `>` is text: a label matches under either reading.
  if (dropQuoteMarkers) text = text.replace(/(?:\r\n|\r|\n)[ \t>]*/g, ' ');
  return text.trim().replace(/\s+/g, ' ').toLowerCase().toUpperCase().toLowerCase();
}

/** Both readings of a label's text, without duplicates. */
function labelKeys(label: string): string[] {
  const plain = normalizeLabel(label, false);
  const quoted = normalizeLabel(label, true);
  return plain === quoted ? [plain] : [plain, quoted];
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

/** An autolink or email autolink: a renderer reads its contents as a URL, so brackets inside it are not brackets. */
const AUTOLINK =
  /<(?:[A-Za-z][A-Za-z0-9+.-]{1,31}:[^\s<>]*|[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*)>/y;

/** Every run of backticks, by length, so the closing run of a code span is found without rescanning. */
function backtickRuns(content: string): { closerOf(len: number, from: number, stop: number): number } {
  const byLen = new Map<number, number[]>();
  const cursor = new Map<number, number>();
  const n = content.length;
  for (let i = 0; i < n; ) {
    if (content.charCodeAt(i) !== 96) {
      i++;
      continue;
    }
    let k = 1;
    while (content.charCodeAt(i + k) === 96) k++;
    const list = byLen.get(k);
    if (list) list.push(i);
    else byLen.set(k, [i]);
    i += k;
  }
  return {
    /** The first run of exactly `len` backticks that starts at or after `from` and before `stop`, or -1. */
    closerOf(len, from, stop) {
      const list = byLen.get(len);
      if (!list) return -1;
      let at = cursor.get(len) ?? 0;
      while (at < list.length && list[at] < from) at++;
      cursor.set(len, at);
      return at < list.length && list[at] < stop ? list[at] : -1;
    },
  };
}

interface BlockEvents {
  /** Where each block boundary is: the start of a line. Nondecreasing. */
  at: number[];
  /** Where scanning resumes after it: the same offset, or past a fenced code block. */
  to: number[];
}

/**
 * The block boundaries a markdown parser finds before it reads any inline text,
 * so brackets and code spans never cross them: a blank or quote-only line, a
 * list item, a thematic break, a block quote that starts or deepens, a heading
 * (a boundary on both sides), and a fenced code block, which can sit on a
 * list item's line or inside a quote and hides everything up to its closing
 * fence. An unclosed fence hides nothing: the rest of the text stays readable.
 */
function blockEvents(content: string): BlockEvents {
  const n = content.length;
  const out: BlockEvents = { at: [], to: [] };
  const push = (at: number, to: number): void => {
    out.at.push(at);
    out.to.push(to);
  };
  const lineEnd = (from: number): number => {
    let e = from;
    while (e < n && content.charCodeAt(e) !== 10 && content.charCodeAt(e) !== 13) e++;
    return e;
  };
  const nextLine = (e: number): number => (e >= n ? n + 1 : e + (content.charCodeAt(e) === 13 && content.charCodeAt(e + 1) === 10 ? 2 : 1));
  const isSpace = (c: number): boolean => c === 32 || c === 9;

  /** A line's leading indent in columns, its quote depth, whether a list marker or quote marker opens it, and where the rest starts. */
  const parseLine = (line: number): { indent: number; depth: number; container: boolean; list: boolean; thematic: boolean; rest: number } => {
    let q = line;
    let indent = 0;
    while (q < n && isSpace(content.charCodeAt(q))) {
      indent = content.charCodeAt(q) === 9 ? indent + 4 - (indent % 4) : indent + 1;
      q++;
    }
    let depth = 0;
    let list = false;
    let thematic = false;
    for (;;) {
      while (q < n && isSpace(content.charCodeAt(q))) q++;
      const c = content.charCodeAt(q);
      if (c === 45 || c === 42 || c === 95) {
        // `---`, `***`, `___`, with spaces between: a thematic break, not a list item
        let k = q;
        let count = 0;
        while (k < n && (content.charCodeAt(k) === c || isSpace(content.charCodeAt(k)))) {
          if (content.charCodeAt(k) === c) count++;
          k++;
        }
        const ch = content.charCodeAt(k);
        if (count >= 3 && (k >= n || ch === 10 || ch === 13)) {
          thematic = true;
          break;
        }
      }
      if (c === 62) {
        depth++;
        q++;
        continue;
      }
      if (c === 45 || c === 42 || c === 43) {
        if (isSpace(content.charCodeAt(q + 1))) {
          list = true;
          q++;
          continue;
        }
      } else if (c >= 48 && c <= 57) {
        let d = q;
        while (d < n && d - q < 9 && content.charCodeAt(d) >= 48 && content.charCodeAt(d) <= 57) d++;
        const mark = content.charCodeAt(d);
        if ((mark === 46 || mark === 41) && isSpace(content.charCodeAt(d + 1))) {
          list = true;
          q = d + 1;
          continue;
        }
      }
      break;
    }
    return { indent, depth, container: depth > 0 || list, list, thematic, rest: q };
  };

  let line = 0;
  let prevDepth = 0;
  while (line <= n) {
    const info = parseLine(line);
    let q = info.rest;
    while (q < n && isSpace(content.charCodeAt(q))) q++;
    const c = content.charCodeAt(q);
    const e = lineEnd(q);
    let next = nextLine(lineEnd(line));
    const blank = q >= n || c === 10 || c === 13;
    const indentedText = !blank && info.indent >= 4 && !info.container; // indented code cannot interrupt a paragraph
    if (info.depth > prevDepth && !indentedText) push(line, line); // a block quote starts or deepens
    prevDepth = info.depth;
    if (indentedText) {
      line = next;
      continue;
    }
    if (info.thematic) {
      push(line, line);
    } else {
      if (info.list) push(line, line); // a list item starts a new block
      if (q >= n || c === 10 || c === 13) {
        push(line, line); // a blank or quote-only line
      } else if (c === 35) {
        let h = q;
        while (content.charCodeAt(h) === 35) h++;
        const after = content.charCodeAt(h);
        if (h - q <= 6 && (h >= n || after === 32 || after === 9 || after === 10 || after === 13)) {
          push(line, line);
          if (next <= n) push(next, next);
        }
      } else if (c === 96 || c === 126) {
        let f = q;
        while (content.charCodeAt(f) === c) f++;
        const fence = f - q;
        if (fence >= 3 && !(c === 96 && content.slice(f, e).includes('`'))) {
          // Code until a line that is only a fence of the same character, at least as long, or a line that
          // leaves the quote the fence opened in. An unclosed fence hides nothing.
          let close = next;
          let resume = -1;
          while (close <= n) {
            const cl = parseLine(close);
            if (cl.depth < info.depth) {
              resume = close; // the quote ended, and the fence with it
              break;
            }
            let g = cl.rest;
            while (g < n && isSpace(content.charCodeAt(g))) g++;
            let h = g;
            while (content.charCodeAt(h) === c) h++;
            if (h - g >= fence && content.slice(h, lineEnd(h)).trim() === '' && (cl.indent < 4 || info.container)) {
              resume = nextLine(lineEnd(h));
              break;
            }
            close = nextLine(lineEnd(close));
          }
          if (resume >= 0) {
            push(line, Math.min(resume, n));
            next = resume;
          } else {
            push(line, line);
          }
        }
      }
    }
    line = next;
  }
  return out;
}

/**
 * One pass over the text, the way a markdown parser reads brackets:
 * backslash escapes skip a character, brackets nest, and a blank line ends the
 * paragraph, so brackets still open at that point never match. It also records
 * the first `]` after each `![` and every `][label]` that follows one, so the
 * image can be read more than one way: a stray `[` inside the alt text (in a
 * code span, an autolink, or just unpaired) must not hide it.
 */
function analyzeBrackets(content: string, renderer: boolean): BracketInfo {
  const n = content.length;
  const close = new Int32Array(n).fill(-1);
  const hasInner = new Uint8Array(n);
  const firstClose = new Map<number, number>();
  const labelAfterImage: Array<{ bang: number; labelOpen: number }> = [];
  const open: number[] = [];
  let waiting: number[] = []; // image `[`s still waiting for their first `]`
  let lastBang = -1;
  let closesSinceBang = 0;
  // Renderer mode: code spans, autolinks and block boundaries (headings, fences, list items, quote-only
  // lines) hide or end brackets the way a markdown parser does.
  const runs = renderer ? backtickRuns(content) : undefined;
  const events: BlockEvents = renderer ? blockEvents(content) : { at: [], to: [] };
  let ev = 0;
  const reset = (): void => {
    open.length = 0;
    waiting = [];
    lastBang = -1;
  };
  let i = 0;
  while (i < n) {
    if (ev < events.at.length && events.at[ev] <= i) {
      reset();
      i = Math.max(i, events.to[ev]);
      ev++;
      continue;
    }
    const c = content.charCodeAt(i);
    if (renderer && c === 96) {
      let k = 1;
      while (content.charCodeAt(i + k) === 96) k++;
      const stop = ev < events.at.length ? events.at[ev] : n;
      const closer = runs!.closerOf(k, i + k, stop);
      i = closer >= 0 ? closer + k : i + k;
    } else if (renderer && c === 60) {
      AUTOLINK.lastIndex = i;
      const m = AUTOLINK.exec(content);
      i = m ? i + m[0].length : i + 1;
    } else if (c === 92) {
      i += isAsciiPunctuation(content.charCodeAt(i + 1)) ? 2 : 1; // a backslash escapes only ASCII punctuation, never a line break
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
        if (!renderer && o === undefined && closesSinceBang > 0 && content.charCodeAt(i + 1) === 91) {
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
        reset(); // a blank line ends the paragraph
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
      const keys = labelKeys(def[1]);
      if (keys.every((key) => flagged.has(key))) continue;
      if (sendsDataOut(def[2])) {
        // Only whitespace separates `[label]:` from its destination, so the first hit is the destination.
        const destAt = content.indexOf(def[2], def.index + def[0].length);
        for (const key of keys) if (!flagged.has(key)) flagged.set(key, { index: def.index, length: destAt + def[2].length - def.index });
      }
    }
    if (flagged.size === 0) return [];

    const raw = analyzeBrackets(content, false);
    const rendered = analyzeBrackets(content, true);
    const hits: Array<{ index: number; end: number; related: { index: number; length: number } }> = [];

    const lookup = (text: string): { index: number; length: number } | undefined => {
      for (const key of labelKeys(text)) {
        if (key === '') continue;
        const found = flagged.get(key);
        if (found) return found;
      }
      return undefined;
    };

    // A bracket reading: each `[label]` is read once, however many image openers wait on it.
    const reader = ({ close, hasInner }: BracketInfo) => {
      const labelCache = new Map<number, { end: number; text: string; blank: boolean } | null>();
      const labelAt = (open: number): { end: number; text: string; blank: boolean } | null => {
        const cached = labelCache.get(open);
        if (cached !== undefined) return cached;
        const labelEnd = close[open];
        let info: { end: number; text: string; blank: boolean } | null = null;
        if (labelEnd >= 0 && !hasInner[open]) {
          const text = content.slice(open + 1, labelEnd);
          info = { end: labelEnd + 1, text, blank: text.trim() === '' };
        }
        labelCache.set(open, info);
        return info;
      };

      /** The image whose alt text ends at `altEnd`, read as a full, collapsed or shortcut reference. */
      const readImage = (at: number, altEnd: number): void => {
        const altOpen = at + 1;
        const afterAlt = altEnd + 1;
        let end = afterAlt;
        let label: string | undefined;
        if (content[afterAlt] === '[') {
          const info = labelAt(afterAlt);
          if (info) {
            end = info.end;
            if (!info.blank) label = info.text;
            else if (!hasInner[altOpen]) label = content.slice(altOpen + 1, altEnd);
          }
        } else if (content[afterAlt] === '(') {
          return; // an inline image, not a reference
        }
        // A shortcut reference (and a collapsed one) uses the alt text as its label, which cannot hold brackets.
        if (label === undefined && end === afterAlt && !hasInner[altOpen]) label = content.slice(altOpen + 1, altEnd);
        const related = label === undefined ? undefined : lookup(label);
        if (related) hits.push({ index: at, end, related });
      };
      return { labelAt, readImage };
    };
    const rawReader = reader(raw);
    const renderedReader = reader(rendered);

    let at = content.indexOf('![');
    while (at >= 0) {
      const altOpen = at + 1;
      // Read the alt text as brackets pair in the text, as a renderer pairs them (code spans and autolinks hidden),
      // and as ending at the first `]`: one stray bracket must not hide the image.
      const paired = raw.close[altOpen];
      if (paired >= 0) rawReader.readImage(at, paired);
      const first = raw.firstClose.get(altOpen);
      if (first !== undefined && first !== paired) rawReader.readImage(at, first);
      const renderedEnd = rendered.close[altOpen];
      if (renderedEnd >= 0) renderedReader.readImage(at, renderedEnd);
      at = content.indexOf('![', at + 1);
    }
    // An unpaired `]` before `[label]` after an earlier `]` ends the alt text, whatever it held.
    for (const { bang, labelOpen } of raw.labelAfterImage) {
      const info = rawReader.labelAt(labelOpen);
      if (!info || info.blank) continue;
      const related = lookup(info.text);
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

