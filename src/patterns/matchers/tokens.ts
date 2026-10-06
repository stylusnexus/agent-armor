import type { MatcherHit, PatternMatcher } from './types';
import {
  isLineTerminator,
  isWhitespace,
  isWordBoundary,
  isWordChar,
  PositionIndex,
  regexFinder,
  runEndFinder,
} from './scan-helpers';

/**
 * Exact, linear-time replacements for the shipped credential patterns and the
 * `<meta>` and `SYSTEM OVERRIDE` patterns (#175). What they have in common: a
 * long run of one character class followed by a `\b` the engine backtracks
 * over, started again at every position inside the same run.
 */

/** `[A-Za-z0-9_-]` */
const isKeyChar = (c: number) => isWordChar(c) || c === 45;
/** `[A-Za-z0-9/+=]` */
const isBase64Char = (c: number) =>
  (c >= 48 && c <= 57) ||
  (c >= 65 && c <= 90) ||
  (c >= 97 && c <= 122) ||
  c === 47 ||
  c === 43 ||
  c === 61;

const PLACEHOLDER_WORDS = /EXAMPLE|example|xxxx|XXXX|your|YOUR|placeholder|redacted|REDACTED/g;

/**
 * Shared shape of `\bPREFIX(?:optional)?(?!K*placeholder)[A-Za-z0-9_-]{20,}\b`:
 * the optional group never changes the outcome (a shorter prefix only adds
 * characters to the run), so the match is the run that starts after PREFIX,
 * if no placeholder word sits in it and it holds 20+ characters, ending at the
 * LAST `\b` inside the run (the engine backs off from the end until one fits).
 */
function keyMatcher(regex: string, prefix: string, fuzzAtoms: string[]): PatternMatcher {
  return {
    regex,
    flags: 'g',
    extractGroup: 0,
    fuzzAtoms,
    match(content) {
      const hits: MatcherHit[] = [];
      const start = new RegExp(String.raw`\b${prefix}`, 'g');
      const runEnd = runEndFinder(content, isKeyChar);
      const nextPlaceholder = regexFinder(content, new RegExp(PLACEHOLDER_WORDS.source, 'g'));
      let boundaryRunEnd = -1;
      let lastBoundary = -1;
      let pos = 0;
      for (;;) {
        start.lastIndex = pos;
        const m = start.exec(content);
        if (!m) break;
        const bodyStart = m.index + m[0].length;
        const end = runEnd(bodyStart);
        const placeholder = nextPlaceholder(bodyStart);
        if ((placeholder >= 0 && placeholder < end) || end - bodyStart < 20) {
          pos = m.index + 1;
          continue;
        }
        if (boundaryRunEnd !== end) {
          boundaryRunEnd = end;
          lastBoundary = -1;
          for (let j = end; j >= bodyStart; j--) {
            if (isWordBoundary(content, j)) {
              lastBoundary = j;
              break;
            }
          }
        }
        if (lastBoundary < bodyStart + 20) {
          pos = m.index + 1;
          continue;
        }
        hits.push({ index: m.index, text: content.slice(m.index, lastBoundary) });
        pos = lastBoundary;
      }
      return hits;
    },
  };
}

export const OPENAI_KEY_MATCHER = keyMatcher(
  String.raw`\bsk-(?:proj-)?(?![A-Za-z0-9_-]*(?:EXAMPLE|example|xxxx|XXXX|your|YOUR|placeholder|redacted|REDACTED))[A-Za-z0-9_-]{20,}\b`,
  'sk-',
  [
    'sk-',
    'sk-proj-',
    'sk-ant-',
    'sk-sk-',
    '-',
    '_',
    'a',
    'A',
    '0',
    'abcdefghij',
    'ABCDEFGHIJKLMNOPQRST',
    'EXAMPLE',
    'example',
    'xxxx',
    'your',
    'placeholder',
    'redacted',
    ' ',
    '.',
    '"',
    '\n',
  ],
);

export const ANTHROPIC_KEY_MATCHER = keyMatcher(
  String.raw`\bsk-ant-(?:api\d{2}-)?(?![A-Za-z0-9_-]*(?:EXAMPLE|example|xxxx|XXXX|your|YOUR|placeholder|redacted|REDACTED))[A-Za-z0-9_-]{20,}\b`,
  'sk-ant-',
  [
    'sk-ant-',
    'sk-ant-api03-',
    'api03-',
    'api0-',
    'sk-',
    '-',
    '_',
    'a',
    'A',
    '0',
    'abcdefghij',
    'ABCDEFGHIJKLMNOPQRST',
    'EXAMPLE',
    'xxxx',
    'YOUR',
    'redacted',
    ' ',
    '.',
    '"',
    '\n',
  ],
);

/**
 * `\beyJ[K]{10,}\.eyJ[K]{10,}\.[K]{10,}\b`: each run of key characters has to
 * end exactly at the `.`, so every start inside one run succeeds or fails
 * together; the last run backs off to its last `\b`.
 */
export const JWT_MATCHER: PatternMatcher = {
  regex: String.raw`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`,
  flags: 'g',
  extractGroup: 0,
  fuzzAtoms: [
    'eyJ',
    'eyJ-',
    'eyj',
    '.',
    '..',
    '-',
    '_',
    'a',
    'A',
    '0',
    'abcdefghij',
    'abcdefghijk',
    'eyJhbGciOiJIUzI1NiJ9',
    ' ',
    '\n',
    '"',
    'é',
  ],
  match(content) {
    const hits: MatcherHit[] = [];
    const start = /\beyJ/g;
    // One finder per run: they alternate, and a shared one would rescan.
    const firstRunEnd = runEndFinder(content, isKeyChar);
    const secondRunEnd = runEndFinder(content, isKeyChar);
    const thirdRunEnd = runEndFinder(content, isKeyChar);
    let pos = 0;
    for (;;) {
      start.lastIndex = pos;
      const m = start.exec(content);
      if (!m) break;
      const s = m.index;
      const e1 = firstRunEnd(s + 3);
      if (
        e1 - (s + 3) < 10 ||
        content.charCodeAt(e1) !== 46 ||
        !content.startsWith('eyJ', e1 + 1)
      ) {
        pos = s + 1;
        continue;
      }
      const e2 = secondRunEnd(e1 + 4);
      if (e2 - (e1 + 4) < 10 || content.charCodeAt(e2) !== 46) {
        pos = s + 1;
        continue;
      }
      const e3 = thirdRunEnd(e2 + 1);
      let end = -1;
      for (let j = e3; j >= e2 + 11; j--) {
        if (isWordBoundary(content, j)) {
          end = j;
          break;
        }
      }
      if (end < 0) {
        pos = s + 1;
        continue;
      }
      hits.push({ index: s, text: content.slice(s, end) });
      pos = end;
    }
    return hits;
  },
};

/**
 * `aws_?secret_?access_?key\s*[=:]\s*["']?(?![A-Za-z0-9/+=]*EXAMPLE)([A-Za-z0-9/+=]{40})\b`
 * (gi): a 40-character run of base64 characters with no `example` in the rest
 * of its run, followed by a `\b`. The text ends at the 40th character.
 */
export const AWS_SECRET_MATCHER: PatternMatcher = {
  regex: String.raw`aws_?secret_?access_?key\s*[=:]\s*["']?(?![A-Za-z0-9/+=]*EXAMPLE)([A-Za-z0-9/+=]{40})\b`,
  flags: 'gi',
  extractGroup: 0,
  fuzzAtoms: [
    'aws_secret_access_key',
    'AWSSECRETACCESSKEY',
    'awssecretaccesskey',
    'aws_secretaccess_key',
    '=',
    ':',
    ' = ',
    '"',
    "'",
    '/',
    '+',
    'a'.repeat(40),
    'A'.repeat(39),
    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY',
    'example',
    'EXAMPLE',
    'x',
    '-',
    ' ',
    '\n',
  ],
  match(content) {
    const hits: MatcherHit[] = [];
    const head = /aws_?secret_?access_?key\s*[=:]\s*["']?/gi;
    const runEnd = runEndFinder(content, isBase64Char);
    const nextExample = regexFinder(content, /example/gi);
    let pos = 0;
    for (;;) {
      head.lastIndex = pos;
      const m = head.exec(content);
      if (!m) break;
      const valueStart = m.index + m[0].length;
      const end = runEnd(valueStart);
      const example = nextExample(valueStart);
      if (
        (example >= 0 && example < end) ||
        end - valueStart < 40 ||
        !isWordBoundary(content, valueStart + 40)
      ) {
        pos = m.index + 1;
        continue;
      }
      hits.push({ index: m.index, text: content.slice(m.index, valueStart + 40) });
      pos = valueStart + 40;
    }
    return hits;
  },
};

/**
 * `<meta\s+[^>]*content\s*=\s*["']([^"']{50,})["'][^>]*>` (gi). The greedy
 * `[^>]*` makes the engine try `content` occurrences right to left inside the
 * tag's first `>`-free stretch; the value runs to the next quote (and may
 * cross `>`), so it is checked by quote positions, not by scanning from every
 * `<meta`.
 */
export const META_TAG_MATCHER: PatternMatcher = {
  regex: String.raw`<meta\s+[^>]*content\s*=\s*["']([^"']{50,})["'][^>]*>`,
  flags: 'gi',
  extractGroup: 1,
  fuzzAtoms: [
    '<meta ',
    '<META\n',
    '<meta',
    'content',
    'CONTENT',
    ' = ',
    '=',
    '"',
    "'",
    '>',
    '<',
    'x'.repeat(49),
    'y'.repeat(50),
    'z'.repeat(60),
    ' ',
    '\n',
    'name',
    'ignore previous instructions',
  ],
  match(content) {
    const hits: MatcherHit[] = [];
    const n = content.length;
    let gt: PositionIndex | undefined;
    const start = /<meta\s/gi;
    const afterContent = /\s*=\s*["']/y;
    const quote = /["']/g;
    let pos = 0;
    for (;;) {
      start.lastIndex = pos;
      const m = start.exec(content);
      if (!m) break;
      const s = m.index;
      gt ??= new PositionIndex(content, (c) => c === 62);
      const firstGt = gt.next(s + 5);
      const segEnd = firstGt < 0 ? n : firstGt;
      const region = content.slice(s + 6, segEnd);
      const found: number[] = [];
      const word = /content/gi;
      let w: RegExpExecArray | null;
      while ((w = word.exec(region)) !== null) {
        found.push(s + 6 + w.index);
        word.lastIndex = w.index + 1;
      }
      let hit: MatcherHit | null = null;
      for (let k = found.length - 1; k >= 0 && !hit; k--) {
        const t = found[k];
        afterContent.lastIndex = t + 7;
        const am = afterContent.exec(content);
        if (!am) continue;
        const valueStart = t + 7 + am[0].length;
        quote.lastIndex = valueStart;
        const close = quote.exec(content);
        if (!close || close.index - valueStart < 50) continue;
        const tagEnd = gt.next(close.index + 1);
        if (tagEnd < 0) continue;
        hit = {
          index: s,
          text: content.slice(s, tagEnd + 1),
          extracted: content.slice(valueStart, close.index),
        };
      }
      if (hit) {
        hits.push(hit);
        pos = hit.index + hit.text.length;
      } else {
        pos = segEnd;
        if (firstGt < 0) break;
      }
    }
    return hits;
  },
};

/**
 * `(?:SYSTEM|CONTEXT|INSTRUCTION)\s+(?:OVERRIDE|UPDATE|CHANGE)\s*[:\-]?\s*.{10,}`
 * (gm). After the two words the engine tries split points `p` for `.{10,}`
 * from the end of the whitespace-colon-whitespace stretch back to just after
 * the words, and the first `p` with ten non-terminators ahead wins.
 */
export const SYSTEM_OVERRIDE_MATCHER: PatternMatcher = {
  regex: String.raw`(?:SYSTEM|CONTEXT|INSTRUCTION)\s+(?:OVERRIDE|UPDATE|CHANGE)\s*[:\-]?\s*.{10,}`,
  flags: 'gm',
  extractGroup: 0,
  fuzzAtoms: [
    'SYSTEM',
    'CONTEXT',
    'INSTRUCTION',
    'OVERRIDE',
    'UPDATE',
    'CHANGE',
    'system',
    ' ',
    '  ',
    '\n',
    '\r',
    ' ',
    '\t',
    ':',
    '-',
    ': ',
    ' - ',
    'abcdefghij',
    'do the thing now',
    'x',
  ],
  match(content) {
    const hits: MatcherHit[] = [];
    const n = content.length;
    const head = /(?:SYSTEM|CONTEXT|INSTRUCTION)\s+(?:OVERRIDE|UPDATE|CHANGE)/g;
    let pos = 0;
    for (;;) {
      head.lastIndex = pos;
      const m = head.exec(content);
      if (!m) break;
      const afterWords = m.index + m[0].length;
      let e1 = afterWords;
      while (e1 < n && isWhitespace(content.charCodeAt(e1))) e1++;
      let e2 = e1;
      const c1 = content.charCodeAt(e1);
      if (c1 === 58 || c1 === 45) {
        e2 = e1 + 1;
        while (e2 < n && isWhitespace(content.charCodeAt(e2))) e2++;
      }
      let lineEnd = e2;
      while (lineEnd < n && !isLineTerminator(content.charCodeAt(lineEnd))) lineEnd++;
      let count = lineEnd - e2;
      let end = count >= 10 ? lineEnd : -1;
      for (let p = e2 - 1; end < 0 && p >= afterWords; p--) {
        count = isLineTerminator(content.charCodeAt(p)) ? 0 : count + 1;
        if (count >= 10) end = p + count;
      }
      if (end < 0) {
        pos = m.index + 1;
        continue;
      }
      hits.push({ index: m.index, text: content.slice(m.index, end) });
      pos = end;
    }
    return hits;
  },
};
