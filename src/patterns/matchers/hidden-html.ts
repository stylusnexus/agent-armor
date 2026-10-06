import type { MatcherHit, PatternMatcher } from './types';

/*
 * All seven `hh-*` regexes share one shape:
 *
 *   <[^>]+style\s*=\s*["'][^"']*KW[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>   (flags gi)
 *
 * and only KW differs. Walking it the way the backtracking engine does:
 *
 * - A match starts at a `<`. `[^>]+` runs to the first `>` after it, then
 *   gives characters back, so `style` occurrences are tried right to left
 *   (at least one character after the `<`, before that `>`). The first one
 *   for which the rest succeeds wins.
 * - Whether the rest succeeds depends only on where `style` is. Every `<` in
 *   the same `>`-free stretch sees the same `style` candidates, the first
 *   `<` the most, so if the first `<` fails the whole stretch fails.
 * - After `style`, `\s*=\s*` and the opening quote are fixed. The value runs
 *   to the next quote character of either kind, and for all variants but
 *   colour KW must sit inside that quote-free run, which then closes the
 *   attribute. The colour variant's `rgba?\([^)]*` reads up to the first `)`
 *   even past quotes, so its closing quote is the first one after that `)`;
 *   its `color` candidates are tried right to left too.
 * - `[^>]*>` ends at the first `>` after the closing quote. The lazy body ends
 *   at the first `</` that has a non-`>` character and then a `>` after it.
 *
 * Every scan below either covers a region owned by one candidate or uses a
 * binary search over positions collected once per input, so a match call is
 * O(n log n) however the input is crafted.
 */

interface Positions {
  gts: number[];
  lts: number[];
  quotes: number[];
  parens: number[];
  /** For each `)` in `parens`, where its `,\s*0\s*` tail starts, or -1. */
  parenTail: number[];
  styles: number[];
  /** `</` positions that can close the element, and the end of each closer. */
  closers: number[];
  closerEnds: number[];
}

let cached: { content: string; positions: Positions } | null = null;

function lowerBound(arr: number[], x: number): number {
  let lo = 0;
  let hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (arr[mid] < x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** First element of `arr` at or after `x`, or -1. */
function firstAtOrAfter(arr: number[], x: number): number {
  const i = lowerBound(arr, x);
  return i < arr.length ? arr[i] : -1;
}

function positionsOf(content: string): Positions {
  if (cached && cached.content === content) return cached.positions;
  const gts: number[] = [];
  const lts: number[] = [];
  const quotes: number[] = [];
  const parens: number[] = [];
  for (let i = 0; i < content.length; i++) {
    const c = content.charCodeAt(i);
    if (c === 62) gts.push(i);
    else if (c === 60) lts.push(i);
    else if (c === 34 || c === 39) quotes.push(i);
    else if (c === 41) parens.push(i);
  }

  const parenTail: number[] = new Array(parens.length).fill(-1);
  const tailRe = /,\s*0\s*\)/g;
  let pi = 0;
  for (let m = tailRe.exec(content); m; m = tailRe.exec(content)) {
    const close = m.index + m[0].length - 1;
    while (parens[pi] < close) pi++;
    parenTail[pi] = m.index;
  }

  const styles: number[] = [];
  const styleRe = /style/gi;
  for (let m = styleRe.exec(content); m; m = styleRe.exec(content)) styles.push(m.index);

  const closers: number[] = [];
  const closerEnds: number[] = [];
  for (const lt of lts) {
    if (
      content.charCodeAt(lt + 1) !== 47 ||
      lt + 2 >= content.length ||
      content.charCodeAt(lt + 2) === 62
    )
      continue;
    const gt = firstAtOrAfter(gts, lt + 3);
    if (gt < 0) continue;
    closers.push(lt);
    closerEnds.push(gt + 1);
  }

  const positions = { gts, lts, quotes, parens, parenTail, styles, closers, closerEnds };
  cached = { content, positions };
  return positions;
}

interface Hit {
  /** The `>` that ends the opening tag. */
  gt: number;
  /** Where the closing tag starts. */
  closer: number;
  /** End of the whole match. */
  end: number;
}

/** `[^>]*>([\s\S]*?)<\/[^>]+>` from just after the closing quote. */
function rest(p: Positions, closeQuote: number): Hit | null {
  const gt = firstAtOrAfter(p.gts, closeQuote + 1);
  if (gt < 0) return null;
  const i = lowerBound(p.closers, gt + 1);
  if (i >= p.closers.length) return null;
  return { gt, closer: p.closers[i], end: p.closerEnds[i] };
}

/** Tries the value that opens at quote `q`; returns the match it leads to, if any. */
type ValueCheck = (content: string, p: Positions, q: number) => Hit | null;

/** KW must lie in the quote-free run after `q`; the next quote closes it. */
function inRun(kw: (run: string) => boolean): ValueCheck {
  return (content, p, q) => {
    const v = firstAtOrAfter(p.quotes, q + 1);
    if (v < 0 || !kw(content.slice(q + 1, v))) return null;
    return rest(p, v);
  };
}

const COLON = /\s*:\s*/y;
const TRANSPARENT = /transparent/iy;
const RGBA_OPEN = /rgba?\(/iy;

const colorValue: ValueCheck = (content, p, q) => {
  const v = firstAtOrAfter(p.quotes, q + 1);
  const runEnd = v < 0 ? content.length : v;
  const run = content.slice(q + 1, runEnd);
  const colors: number[] = [];
  const colorRe = /color/gi;
  for (let m = colorRe.exec(run); m; m = colorRe.exec(run)) colors.push(q + 1 + m.index);

  for (let k = colors.length - 1; k >= 0; k--) {
    COLON.lastIndex = colors[k] + 5;
    if (!COLON.test(content)) continue;
    const x = COLON.lastIndex;
    let closeQuote = -1;
    TRANSPARENT.lastIndex = x;
    RGBA_OPEN.lastIndex = x;
    if (TRANSPARENT.test(content)) {
      closeQuote = v;
    } else if (RGBA_OPEN.test(content)) {
      const open = RGBA_OPEN.lastIndex - 1;
      const pi = lowerBound(p.parens, open + 1);
      if (pi < p.parens.length && p.parenTail[pi] >= open + 1) {
        closeQuote = firstAtOrAfter(p.quotes, p.parens[pi] + 1);
      }
    }
    if (closeQuote < 0) continue;
    const hit = rest(p, closeQuote);
    if (hit) return hit;
  }
  return null;
};

const AFTER_STYLE = /\s*=\s*["']/y;

function hiddenHtmlMatcher(regex: string, value: ValueCheck, fuzzAtoms: string[]): PatternMatcher {
  return {
    regex,
    flags: 'gi',
    extractGroup: 1,
    fuzzAtoms,
    match(content: string): MatcherHit[] {
      const p = positionsOf(content);
      const n = content.length;
      const hits: MatcherHit[] = [];
      let gi = 0;
      let li = 0;
      let si = 0;
      let a = 0;
      while (a < n) {
        while (gi < p.gts.length && p.gts[gi] < a) gi++;
        const b = gi < p.gts.length ? p.gts[gi] : n;
        while (li < p.lts.length && p.lts[li] < a) li++;
        if (li >= p.lts.length) break;
        const s = p.lts[li];
        if (s >= b) {
          a = b + 1;
          continue;
        }
        while (si < p.styles.length && p.styles[si] < s + 2) si++;
        let sj = si;
        while (sj < p.styles.length && p.styles[sj] < b) sj++;
        let hit: Hit | null = null;
        for (let k = sj - 1; k >= si && !hit; k--) {
          AFTER_STYLE.lastIndex = p.styles[k] + 5;
          if (AFTER_STYLE.test(content)) hit = value(content, p, AFTER_STYLE.lastIndex - 1);
        }
        if (hit) {
          hits.push({
            index: s,
            text: content.slice(s, hit.end),
            extracted: content.slice(hit.gt + 1, hit.closer),
          });
          a = hit.end;
        } else {
          a = b + 1;
        }
      }
      return hits;
    },
  };
}

const SHARED_ATOMS = [
  '<div ',
  '<span ',
  '<a ',
  '<p',
  '<',
  '<<',
  'style',
  'STYLE',
  'Style',
  'stYle',
  'styl',
  'tyle',
  '=',
  ' = ',
  '="',
  "='",
  '= "',
  "= '",
  '"',
  "'",
  '""',
  "''",
  ' ',
  '  ',
  '\t',
  '\n',
  '\u00a0',
  '\ufeff',
  ':',
  ' : ',
  ';',
  '>',
  '>>',
  '</',
  '</div>',
  '</span>',
  '</>',
  '</ >',
  '</a',
  '/>',
  'hello',
  'x',
  'class="c" ',
  "id='i' ",
  'data-x="a>b" ',
];

const STYLE_PREFIX = '<[^>]+style\\s*=\\s*["\'][^"\']*';
const STYLE_SUFFIX = '[^"\']*["\'][^>]*>([\\s\\S]*?)<\\/[^>]+>';

/** Matchers for the seven `hh-*` hidden-HTML patterns (#175). */
export const HIDDEN_HTML_MATCHERS: PatternMatcher[] = [
  hiddenHtmlMatcher(
    `${STYLE_PREFIX}display\\s*:\\s*none${STYLE_SUFFIX}`,
    inRun((run) => /display\s*:\s*none/i.test(run)),
    [
      ...SHARED_ATOMS,
      'display',
      'DISPLAY',
      'display:none',
      'display : none',
      'none',
      'NONE',
      'display:block',
      'displa',
    ],
  ),
  hiddenHtmlMatcher(
    `${STYLE_PREFIX}visibility\\s*:\\s*hidden${STYLE_SUFFIX}`,
    inRun((run) => /visibility\s*:\s*hidden/i.test(run)),
    [
      ...SHARED_ATOMS,
      'visibility',
      'Visibility',
      'visibility:hidden',
      'visibility : hidden',
      'hidden',
      'HIDDEN',
      'visible',
      'hidde',
    ],
  ),
  hiddenHtmlMatcher(
    `${STYLE_PREFIX}(?:left|top|right|bottom)\\s*:\\s*-\\d{3,}px${STYLE_SUFFIX}`,
    inRun((run) => /(?:left|top|right|bottom)\s*:\s*-\d{3,}px/i.test(run)),
    [
      ...SHARED_ATOMS,
      'left',
      'top',
      'RIGHT',
      'bottom',
      'left:-9999px',
      'top : -100px',
      ':-',
      '-',
      '-99',
      '999',
      '9',
      'px',
      'PX',
      'p',
      'left:-99px',
    ],
  ),
  hiddenHtmlMatcher(
    `${STYLE_PREFIX}(?:font-size\\s*:\\s*0|width\\s*:\\s*0|height\\s*:\\s*0)${STYLE_SUFFIX}`,
    inRun((run) => /(?:font-size\s*:\s*0|width\s*:\s*0|height\s*:\s*0)/i.test(run)),
    [
      ...SHARED_ATOMS,
      'font-size',
      'FONT-SIZE',
      'width',
      'height',
      'font-size:0',
      'width : 0',
      'height:0',
      '0',
      '1',
      'font-',
      'size',
    ],
  ),
  hiddenHtmlMatcher(
    `${STYLE_PREFIX}opacity\\s*:\\s*0${STYLE_SUFFIX}`,
    inRun((run) => /opacity\s*:\s*0/i.test(run)),
    [...SHARED_ATOMS, 'opacity', 'OPACITY', 'opacity:0', 'opacity : 0', '0', '1', '.5', 'opacit'],
  ),
  hiddenHtmlMatcher(
    `${STYLE_PREFIX}color\\s*:\\s*(?:transparent|rgba?\\([^)]*,\\s*0\\s*\\))${STYLE_SUFFIX}`,
    colorValue,
    [
      ...SHARED_ATOMS,
      'color',
      'COLOR',
      'color:',
      'color : ',
      'transparent',
      'TRANSPARENT',
      'transparen',
      'rgb(',
      'rgba(',
      'RGBA(',
      'rgba',
      'rgb',
      '(',
      ')',
      ',',
      ', ',
      ',0',
      ', 0',
      '0',
      '0 ',
      '0)',
      ',0)',
      ', 0 )',
      'color:rgba(1,2,3,0)',
      'color:rgb(0,0)',
      'color:rgba(1,"2,0)',
      "color:rgba(',0)",
      'color:red',
    ],
  ),
  hiddenHtmlMatcher(
    `${STYLE_PREFIX}overflow\\s*:\\s*hidden[^"']*(?:max-height|max-width)\\s*:\\s*[01]px${STYLE_SUFFIX}`,
    inRun((run) => {
      const m = /overflow\s*:\s*hidden/i.exec(run);
      if (!m) return false;
      const tail = /(?:max-height|max-width)\s*:\s*[01]px/gi;
      tail.lastIndex = m.index + m[0].length;
      return tail.test(run);
    }),
    [
      ...SHARED_ATOMS,
      'overflow',
      'OVERFLOW',
      'overflow:hidden',
      'overflow : hidden',
      'hidden',
      'max-height',
      'max-width',
      'MAX-HEIGHT',
      'max-height:0px',
      'max-width : 1px',
      'max-height:2px',
      '0px',
      '1px',
      'px',
      '0',
      '1',
      'max-',
    ],
  ),
];
