import { BaseDetector, type PatternMatch } from '../base';
import { applyEdits, mergeEdits } from '../../sanitize';
import { normalizeForScan } from '../../normalize/unicode';
import { blockEvents, blockTriggers, legacyBlockEvents, type BlockEvents } from './markdown-blocks';
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
function normalizeLabel(label: string, quoteMarkers: number): string {
  let text = label.replace(/\0/g, '\ufffd'); // a renderer reads NUL as U+FFFD
  // Block quote markers on a continuation line are not part of the label. How many to drop depends on the
  // quote depth and on whether the line is an indented paragraph continuation (where a `>` is text), which
  // a label's text alone does not tell, so a label matches under each reading: none, all, or exactly 1 or 2.
  if (quoteMarkers === -1) text = text.replace(/(?:\r\n|\r|\n)[ \t>]*/g, ' ');
  else if (quoteMarkers > 0) text = text.replace(new RegExp('(?:\\r\\n|\\r|\\n)(?: {0,3}> ?){' + quoteMarkers + '}', 'g'), ' ');
  return text.trim().replace(/\s+/g, ' ').toLowerCase().toUpperCase().toLowerCase();
}

/** Every reading of a label's text, without duplicates. */
function labelKeys(label: string): string[] {
  const plain = normalizeLabel(label, 0);
  // Without a line break there are no quote markers to drop: one reading.
  if (!/[\r\n]/.test(label)) return [plain];
  const keys = [plain];
  for (const markers of [-1, 1, 2]) {
    const key = normalizeLabel(label, markers);
    if (!keys.includes(key)) keys.push(key);
  }
  return keys;
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

function sameEvents(a: BlockEvents, b: BlockEvents): boolean {
  if (a.at.length !== b.at.length) return false;
  for (let i = 0; i < a.at.length; i++) if (a.at[i] !== b.at[i] || a.to[i] !== b.to[i]) return false;
  return true;
}

/** An inline HTML open or closing tag, which a renderer with HTML on reads as markup, not text. */
const HTML_TAG =
  /<(?:[A-Za-z][A-Za-z0-9-]*(?:\s+[A-Za-z_:][A-Za-z0-9_.:-]*(?:\s*=\s*(?:[^\s"'=<>`]+|'[^']*'|"[^"]*"))?)*\s*\/?>|\/[A-Za-z][A-Za-z0-9-]*\s*>)/y;

/**
 * The end of an inline link's `(destination "title")` starting at the `(` at
 * `at`, or -1 if it is not one. A renderer reads the destination and title as
 * part of the link, so a backtick or bracket in them is not code or a label.
 * Parentheses in the destination nest at most 32 deep, as in the renderers.
 */
function inlineLinkEnd(content: string, at: number, stop: number, findQuote: (quote: number, from: number) => number): number {
  const n = Math.min(content.length, stop);
  let x = at + 1;
  const skipSpace = (): void => {
    while (x < n && (content.charCodeAt(x) === 32 || content.charCodeAt(x) === 9 || content.charCodeAt(x) === 10 || content.charCodeAt(x) === 13)) x++;
  };
  skipSpace();
  if (x >= n) return -1;
  if (content.charCodeAt(x) === 60) {
    x++;
    while (x < n && content.charCodeAt(x) !== 62) {
      const c = content.charCodeAt(x);
      if (c === 10 || c === 13 || c === 60) return -1;
      x += c === 92 && isAsciiPunctuation(content.charCodeAt(x + 1)) ? 2 : 1;
    }
    if (x >= n) return -1;
    x++;
  } else {
    let depth = 0;
    while (x < n) {
      const c = content.charCodeAt(x);
      if (c === 92 && isAsciiPunctuation(content.charCodeAt(x + 1))) {
        x += 2;
        continue;
      }
      if (c === 40) {
        depth++;
        if (depth > 32) return -1;
      } else if (c === 41) {
        if (depth === 0) break;
        depth--;
      } else if (c <= 32) {
        break;
      }
      x++;
    }
  }
  const afterDestination = x;
  skipSpace();
  const open = content.charCodeAt(x);
  if (x > afterDestination && (open === 34 || open === 39 || open === 40)) {
    let close: number;
    if (open === 40) {
      close = x + 1;
      while (close < n && content.charCodeAt(close) !== 41) {
        if (content.charCodeAt(close) === 40) return -1;
        close += content.charCodeAt(close) === 92 && isAsciiPunctuation(content.charCodeAt(close + 1)) ? 2 : 1;
      }
      if (close >= n) return -1;
    } else {
      close = findQuote(open, x + 1);
      if (close === -1 || close >= n) return -1;
    }
    x = close + 1;
    skipSpace();
  }
  return content.charCodeAt(x) === 41 && x < n ? x + 1 : -1;
}

/** The next unescaped `quote` at or after `from`, cached so many searches stay linear. */
function makeQuoteFinder(content: string, quote: number): (from: number) => number {
  const needle = String.fromCharCode(quote);
  let searched = -1;
  let found = -2;
  return (from: number): number => {
    if (found !== -2 && from >= searched && (found === -1 || from <= found)) return found;
    let at = content.indexOf(needle, from);
    while (at > 0) {
      let b = at - 1;
      while (b >= 0 && content.charCodeAt(b) === 92) b--;
      if ((at - 1 - b) % 2 === 0) break;
      at = content.indexOf(needle, at + 1);
    }
    searched = from;
    found = at;
    return at;
  };
}

interface HtmlInlineFinders {
  comment: (from: number) => number;
  pi: (from: number) => number;
  cdata: (from: number) => number;
  decl: (from: number) => number;
}

/** Cached searches for the end of inline HTML comments, processing instructions, CDATA and declarations. */
function htmlInlineFinders(content: string): HtmlInlineFinders {
  const make = (needle: string): ((from: number) => number) => {
    let searched = -1;
    let found = -2;
    return (from) => {
      if (found !== -2 && from >= searched && (found === -1 || from <= found)) return found;
      searched = from;
      found = content.indexOf(needle, from);
      return found;
    };
  };
  return { comment: make('-->'), pi: make('?>'), cdata: make(']]>'), decl: make('>') };
}

/** The end of inline HTML (a tag, comment, instruction, declaration or CDATA) starting at `at`, or -1. */
function htmlInlineEnd(content: string, at: number, finders: HtmlInlineFinders): number {
  const next = content.charCodeAt(at + 1);
  if (next === 33) {
    if (content.startsWith('<!--', at)) {
      const end = finders.comment(at + 4);
      return end === -1 ? -1 : end + 3;
    }
    if (content.startsWith('<![CDATA[', at)) {
      const end = finders.cdata(at + 9);
      return end === -1 ? -1 : end + 3;
    }
    const c = content.charCodeAt(at + 2);
    if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122)) {
      const end = finders.decl(at + 3);
      return end === -1 ? -1 : end + 1;
    }
    return -1;
  }
  if (next === 63) {
    const end = finders.pi(at + 2);
    return end === -1 ? -1 : end + 2;
  }
  HTML_TAG.lastIndex = at;
  const m = HTML_TAG.exec(content);
  return m ? at + m[0].length : -1;
}

/**
 * One pass over the text, the way a markdown parser reads brackets:
 * backslash escapes skip a character, brackets nest, and a blank line ends the
 * paragraph, so brackets still open at that point never match. It also records
 * the first `]` after each `![` and every `][label]` that follows one, so the
 * image can be read more than one way: a stray `[` inside the alt text (in a
 * code span, an autolink, or just unpaired) must not hide it.
 */
function analyzeBrackets(content: string, renderer: boolean, blocks?: BlockEvents, html = false, linkDestinations = true): BracketInfo {
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
  const events: BlockEvents = renderer ? (blocks ?? blockEvents(content, { html, tables: false })) : { at: [], to: [], plain: true };
  const quoteFinders = new Map<number, (from: number) => number>();
  const findQuote = (quote: number, from: number): number => {
    let find = quoteFinders.get(quote);
    if (!find) {
      find = makeQuoteFinder(content, quote);
      quoteFinders.set(quote, find);
    }
    return find(from);
  };
  const htmlEnds = renderer && html ? htmlInlineFinders(content) : undefined;
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
      if (m) {
        i += m[0].length;
      } else if (htmlEnds) {
        const end = htmlInlineEnd(content, i, htmlEnds);
        i = end > i ? end : i + 1;
      } else {
        i++;
      }
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
      if (renderer && linkDestinations && o !== undefined && content.charCodeAt(i) === 40) {
        // `[text](destination "title")`: the destination and title are not inline text
        const stop = ev < events.at.length ? events.at[ev] : n;
        const end = inlineLinkEnd(content, i, stop, findQuote);
        if (end !== -1) i = end;
      }
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
    // Renderers differ: HTML may be on or off, and GFM tables may be on or off. Read the text under each
    // combination the text can tell apart, and flag an image any of them draws. A reading that would only
    // repeat the raw one (no code spans, `<`, link destinations or block structure) is skipped.
    const hasBacktick = content.includes('`');
    const hasLink = content.includes('](');
    // A reading is only worth running when the text holds something that tells it apart from the others.
    const hasHtmlLike = /<[A-Za-z/!?]/.test(content); // inline HTML, and HTML blocks, for renderers with HTML on
    const { table: hasTable, mdit: needsMdit } = blockTriggers(content, hasHtmlLike);
    const rendered: BracketInfo[] = [];
    const seen: Array<{ html: boolean; blocks: BlockEvents }> = [];
    for (const html of hasHtmlLike ? [false, true] : [false]) {
      for (const tables of hasTable ? [false, true] : [false]) {
        for (const mdit of needsMdit ? [false, true] : [false]) {
          const blocks = blockEvents(content, { html, tables, mdit });
          if (seen.some((v) => v.html === html && sameEvents(v.blocks, blocks))) continue;
          seen.push({ html, blocks });
          if (!blocks.plain || hasBacktick || hasHtmlLike || hasLink) rendered.push(analyzeBrackets(content, true, blocks, html));
        }
      }
    }
    // The simpler block model #224 shipped, kept as one more reading so nothing it flagged is lost.
    const legacy = legacyBlockEvents(content);
    if (!legacy.plain || hasBacktick || content.includes('<')) {
      if (hasLink || !seen.some((v) => !v.html && sameEvents(v.blocks, legacy))) rendered.push(analyzeBrackets(content, true, legacy, false, false));
    }
    const hits: Array<{ index: number; end: number; related: { index: number; length: number } }> = [];

    const lookup = (keys: string[]): { index: number; length: number } | undefined => {
      for (const key of keys) {
        if (key === '') continue;
        const found = flagged.get(key);
        if (found) return found;
      }
      return undefined;
    };

    // A bracket reading: each `[label]` is read once, however many image openers wait on it.
    const reader = ({ close, hasInner }: BracketInfo) => {
      const labelCache = new Map<number, { end: number; text: string; blank: boolean; keys: string[] } | null>();
      const labelAt = (open: number): { end: number; text: string; blank: boolean; keys: string[] } | null => {
        const cached = labelCache.get(open);
        if (cached !== undefined) return cached;
        const labelEnd = close[open];
        let info: { end: number; text: string; blank: boolean; keys: string[] } | null = null;
        if (labelEnd >= 0 && !hasInner[open]) {
          const text = content.slice(open + 1, labelEnd);
          info = { end: labelEnd + 1, text, blank: text.trim() === '', keys: labelKeys(text) };
        }
        labelCache.set(open, info);
        return info;
      };

      /** The image whose alt text ends at `altEnd`, read as a full, collapsed or shortcut reference. */
      const readImage = (at: number, altEnd: number): void => {
        const altOpen = at + 1;
        const afterAlt = altEnd + 1;
        let end = afterAlt;
        let keys: string[] | undefined;
        if (content[afterAlt] === '[') {
          const info = labelAt(afterAlt);
          if (info) {
            end = info.end;
            if (!info.blank) keys = info.keys;
            else if (!hasInner[altOpen]) keys = labelKeys(content.slice(altOpen + 1, altEnd));
          }
        } else if (content[afterAlt] === '(') {
          return; // an inline image, not a reference
        }
        // A shortcut reference (and a collapsed one) uses the alt text as its label, which cannot hold brackets.
        if (keys === undefined && end === afterAlt && !hasInner[altOpen]) keys = labelKeys(content.slice(altOpen + 1, altEnd));
        const related = keys === undefined ? undefined : lookup(keys);
        if (related) hits.push({ index: at, end, related });
      };
      return { labelAt, readImage };
    };
    const rawReader = reader(raw);
    const renderedReaders = rendered.map((info) => ({ info, read: reader(info) }));

    let at = content.indexOf('![');
    while (at >= 0) {
      const altOpen = at + 1;
      // Read the alt text as brackets pair in the text, as a renderer pairs them (code spans and autolinks hidden),
      // and as ending at the first `]`: one stray bracket must not hide the image.
      const paired = raw.close[altOpen];
      if (paired >= 0) rawReader.readImage(at, paired);
      const first = raw.firstClose.get(altOpen);
      if (first !== undefined && first !== paired) rawReader.readImage(at, first);
      for (const { info, read } of renderedReaders) {
        const renderedEnd = info.close[altOpen];
        if (renderedEnd >= 0) read.readImage(at, renderedEnd);
      }
      at = content.indexOf('![', at + 1);
    }
    // An unpaired `]` before `[label]` after an earlier `]` ends the alt text, whatever it held.
    for (const { bang, labelOpen } of raw.labelAfterImage) {
      const info = rawReader.labelAt(labelOpen);
      if (!info || info.blank) continue;
      const related = lookup(info.keys);
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

