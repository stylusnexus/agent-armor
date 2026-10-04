import type { MatcherHit, PatternMatcher } from './types';
import { isLineTerminator, isWhitespace, regexFinder } from './scan-helpers';

/**
 * Exact, linear-time replacements for shipped regexes that open at a marker
 * and run to a closer (#175). Each doc comment states the regex semantics the
 * code reproduces, including which of the engine's backtracking choices wins.
 */

const BIDI_START = /[\u202A-\u202E\u2066-\u2069]/g;
const isBidiStart = (c: number) => (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);
const isBidiEnd = (c: number) => c === 0x202c || c === 0x2069;

/** `<!--([\s\S]*?)-->`: a start with no later `-->` means no later start has one either. */
export const HTML_COMMENT_MATCHER: PatternMatcher = {
  regex: String.raw`<!--([\s\S]*?)-->`,
  flags: 'g',
  extractGroup: 1,
  fuzzAtoms: ['<!--', '-->', '--', '-', '>', '<!', ' ', 'ignore previous', 'x', '\n', '<!-->', '<!---->'],
  match(content) {
    const hits: MatcherHit[] = [];
    let pos = 0;
    for (;;) {
      const open = content.indexOf('<!--', pos);
      if (open < 0) break;
      const close = content.indexOf('-->', open + 4);
      if (close < 0) break;
      hits.push({ index: open, text: content.slice(open, close + 3), extracted: content.slice(open + 4, close) });
      pos = close + 3;
    }
    return hits;
  },
};

/**
 * `\\(?:tiny|scriptsize|footnotesize)\s*\{([^}]+)\}`: `[^}]+` can only stop at
 * the first `}`, so the match needs at least one character before it.
 */
export const LATEX_TINY_MATCHER: PatternMatcher = {
  regex: String.raw`\\(?:tiny|scriptsize|footnotesize)\s*\{([^}]+)\}`,
  flags: 'g',
  extractGroup: 1,
  fuzzAtoms: ['\\tiny', '\\scriptsize', '\\footnotesize', '\\tin', '{', '}', '{}', ' ', '\n', 'ignore all', 'x', '\\'],
  match(content) {
    const hits: MatcherHit[] = [];
    const start = /\\(?:tiny|scriptsize|footnotesize)\s*\{/g;
    let pos = 0;
    for (;;) {
      start.lastIndex = pos;
      const m = start.exec(content);
      if (!m) break;
      const bodyStart = m.index + m[0].length;
      const close = content.indexOf('}', bodyStart);
      if (close < 0) break;
      if (close === bodyStart) {
        pos = m.index + 1;
        continue;
      }
      hits.push({ index: m.index, text: content.slice(m.index, close + 1), extracted: content.slice(bodyStart, close) });
      pos = close + 1;
    }
    return hits;
  },
};

/**
 * `data-[\w-]+\s*=\s*["']([^"']{80,})["']`: the name, the `=` and the opening
 * quote are forced; the value must reach the next quote of either kind and be
 * at least 80 characters. Every `data-` inside one name run fails together.
 */
export const DATA_ATTR_MATCHER: PatternMatcher = {
  regex: String.raw`data-[\w-]+\s*=\s*["']([^"']{80,})["']`,
  flags: 'gi',
  extractGroup: 1,
  fuzzAtoms: ['data-', 'DATA-', 'data-x', 'data-a-b', '=', ' = ', '"', "'", 'x'.repeat(40), 'y'.repeat(81), 'z'.repeat(80), '\n', 'é'],
  match(content) {
    const hits: MatcherHit[] = [];
    const start = /data-/gi;
    const name = /[\w-]+/y;
    const equals = /\s*=\s*["']/y;
    const quote = /["']/g;
    let pos = 0;
    for (;;) {
      start.lastIndex = pos;
      const m = start.exec(content);
      if (!m) break;
      name.lastIndex = m.index + 5;
      const nm = name.exec(content);
      if (!nm) {
        pos = m.index + 1;
        continue;
      }
      const nameEnd = m.index + 5 + nm[0].length;
      equals.lastIndex = nameEnd;
      const em = equals.exec(content);
      if (!em) {
        pos = nameEnd;
        continue;
      }
      const valueStart = nameEnd + em[0].length;
      quote.lastIndex = valueStart;
      const close = quote.exec(content);
      if (!close) break;
      if (close.index - valueStart >= 80) {
        hits.push({
          index: m.index,
          text: content.slice(m.index, close.index + 1),
          extracted: content.slice(valueStart, close.index),
        });
        pos = close.index + 1;
      } else {
        pos = nameEnd;
      }
    }
    return hits;
  },
};

/**
 * `[bidi]+[^]*?[closer]` (g): from the first bidi character of a run the
 * engine takes the whole run, then the nearest closer after it; if there is
 * none it gives characters back and settles on the last closer inside the run.
 */
export const BIDI_OVERRIDE_MATCHER: PatternMatcher = {
  // A plain string, not String.raw: the regex source holds the six characters `\u202A`.
  regex: '[\\u202A-\\u202E\\u2066-\\u2069]+[^]*?[\\u202C\\u2069]',
  flags: 'g',
  extractGroup: 0,
  fuzzAtoms: ['\u202A', '\u202B', '\u202C', '\u202D', '\u202E', '\u2066', '\u2067', '\u2068', '\u2069', 'abc', ' ', '\n', 'x'],
  match(content) {
    const hits: MatcherHit[] = [];
    const n = content.length;
    const findCloser = regexFinder(content, /[\u202C\u2069]/g);
    let pos = 0;
    for (;;) {
      BIDI_START.lastIndex = pos;
      const m = BIDI_START.exec(content);
      if (!m) break;
      const start = m.index;
      let runEnd = start + 1;
      while (runEnd < n && isBidiStart(content.charCodeAt(runEnd))) runEnd++;
      const closer = findCloser(runEnd);
      let end = -1;
      if (closer >= 0) {
        end = closer + 1;
      } else {
        for (let k = runEnd - 1; k > start; k--) {
          if (isBidiEnd(content.charCodeAt(k))) {
            end = k + 1;
            break;
          }
        }
      }
      if (end < 0) {
        pos = runEnd;
        continue;
      }
      hits.push({ index: start, text: content.slice(start, end) });
      pos = end;
    }
    return hits;
  },
};

/**
 * `(?:^|\n)\s*(?:SYSTEM|System)\s*:\s*.{10,}` (gm). The keyword must follow the
 * whitespace run that begins at a line start (or at a `\n`); after the colon
 * the `\s*` gives whitespace back until ten characters of one line are left.
 */
export const SYSTEM_PROMPT_MATCHER: PatternMatcher = {
  regex: String.raw`(?:^|\n)\s*(?:SYSTEM|System)\s*:\s*.{10,}`,
  flags: 'gm',
  extractGroup: 0,
  fuzzAtoms: ['SYSTEM', 'System', 'system', 'SYSTEM:', 'System: ', ':', ' ', '  ', '\n', '\r', ' ', '\t', 'a', 'abcdefghij', 'do the thing now', '\n\n'],
  match(content) {
    const hits: MatcherHit[] = [];
    const n = content.length;
    const keyword = /SYSTEM|System/g;
    let lastEnd = 0;
    for (;;) {
      const m = keyword.exec(content);
      if (!m) break;
      const kp = m.index;
      if (kp < lastEnd) continue;

      // Earliest anchor: a line start, or a `\n` that the whitespace run absorbs.
      let ws = kp;
      while (ws > lastEnd && isWhitespace(content.charCodeAt(ws - 1))) ws--;
      let anchor = -1;
      for (let j = ws; j <= kp; j++) {
        if (j === 0 || isLineTerminator(content.charCodeAt(j - 1)) || (j < kp && content.charCodeAt(j) === 10)) {
          anchor = j;
          break;
        }
      }
      if (anchor < 0) continue;

      let q = kp + 6;
      while (q < n && isWhitespace(content.charCodeAt(q))) q++;
      if (content.charCodeAt(q) !== 58) continue;
      const afterColon = q + 1;
      let runEnd = afterColon;
      while (runEnd < n && isWhitespace(content.charCodeAt(runEnd))) runEnd++;

      // Largest split point p in [afterColon, runEnd] with 10+ non-terminators from p.
      let lineEnd = runEnd;
      while (lineEnd < n && !isLineTerminator(content.charCodeAt(lineEnd))) lineEnd++;
      let end = -1;
      if (lineEnd - runEnd >= 10) {
        end = lineEnd;
      } else {
        let count = lineEnd - runEnd;
        for (let p = runEnd - 1; p >= afterColon; p--) {
          count = isLineTerminator(content.charCodeAt(p)) ? 0 : count + 1;
          if (count >= 10) {
            end = p + count;
            break;
          }
        }
      }
      if (end < 0) continue;

      hits.push({ index: anchor, text: content.slice(anchor, end) });
      lastEnd = end;
      keyword.lastIndex = end;
    }
    return hits;
  },
};

/**
 * `\bD\.?A\.?N\.?\b.*(?:mode|enabled|activated|jailbreak)` (gi). The greedy
 * `.*` ends at the LAST keyword on the line, so the answer for a line is
 * computed once and reused by every `DAN` token on it.
 */
export const DAN_MATCHER: PatternMatcher = {
  regex: String.raw`\bD\.?A\.?N\.?\b.*(?:mode|enabled|activated|jailbreak)`,
  flags: 'gi',
  extractGroup: 0,
  fuzzAtoms: ['DAN', 'dan', 'D.A.N', 'D.A.N.', 'D.AN', 'DANK', 'DAN.', ' mode', 'MODE', 'enabled', 'activated', 'jailbreak', ' ', '.', '\n', 'x', 'é'],
  match(content) {
    const hits: MatcherHit[] = [];
    const n = content.length;
    const token = /\bD\.?A\.?N\.?\b/gi;
    const keyword = /(?:mode|enabled|activated|jailbreak)/iy;
    // Cached answer for the line [lineFrom, lineEnd): the last keyword start in it at or after lineFrom.
    let lineFrom = -1;
    let lineEnd = -1;
    let lastKeyword = -1;
    let pos = 0;
    for (;;) {
      token.lastIndex = pos;
      const m = token.exec(content);
      if (!m) break;
      const afterToken = m.index + m[0].length;
      if (!(afterToken >= lineFrom && afterToken <= lineEnd && lineFrom >= 0)) {
        lineFrom = afterToken;
        lineEnd = afterToken;
        while (lineEnd < n && !isLineTerminator(content.charCodeAt(lineEnd))) lineEnd++;
        lastKeyword = -1;
        for (let p = lineEnd - 1; p >= afterToken; p--) {
          const c = content.charCodeAt(p) | 32;
          if (c !== 109 && c !== 101 && c !== 97 && c !== 106) continue; // m e a j
          keyword.lastIndex = p;
          if (keyword.test(content)) {
            lastKeyword = p;
            break;
          }
        }
      }
      if (lastKeyword < afterToken) {
        pos = m.index + 1;
        continue;
      }
      keyword.lastIndex = lastKeyword;
      const km = keyword.exec(content)!;
      const end = lastKeyword + km[0].length;
      hits.push({ index: m.index, text: content.slice(m.index, end) });
      pos = end;
    }
    return hits;
  },
};
