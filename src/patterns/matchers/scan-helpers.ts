/**
 * Small helpers shared by the hand-written matchers. They exist so a matcher
 * never rescans the same stretch of text for many start positions, which is
 * what makes the backtracking regexes quadratic.
 */

/** Same set as the regex class `\s`. */
export function isWhitespace(code: number): boolean {
  return (
    code === 32 ||
    (code >= 9 && code <= 13) ||
    code === 0xa0 ||
    code === 0x1680 ||
    (code >= 0x2000 && code <= 0x200a) ||
    code === 0x2028 ||
    code === 0x2029 ||
    code === 0x202f ||
    code === 0x205f ||
    code === 0x3000 ||
    code === 0xfeff
  );
}

/** Line terminators: the characters `.` does not match and `^`/`$` respect under `m`. */
export function isLineTerminator(code: number): boolean {
  return code === 10 || code === 13 || code === 0x2028 || code === 0x2029;
}

/**
 * A finder for "the first match at or after x" that remembers its last answer.
 * Asking again from any x between the last query and its answer costs nothing,
 * and once a search finds nothing every later search also finds nothing. This
 * keeps a run of failing start positions from each rescanning to the same far
 * token.
 */
export function memoizedFinder(find: (from: number) => number): (from: number) => number {
  let cachedFrom = -1;
  let cachedIndex = -1;
  let noneFrom = Infinity;
  return (from) => {
    if (from >= noneFrom) return -1;
    if (cachedIndex >= from && cachedFrom <= from) return cachedIndex;
    const index = find(from);
    if (index < 0) {
      noneFrom = from;
      return -1;
    }
    cachedFrom = from;
    cachedIndex = index;
    return index;
  };
}

/** Finder for the first occurrence of a regex match start at or after `from`. */
export function regexFinder(content: string, re: RegExp): (from: number) => number {
  return memoizedFinder((from) => {
    re.lastIndex = from;
    const m = re.exec(content);
    return m ? m.index : -1;
  });
}

/** Finder for the first occurrence of a literal string at or after `from`. */
export function literalFinder(content: string, needle: string): (from: number) => number {
  return memoizedFinder((from) => content.indexOf(needle, from));
}

/** `[A-Za-z0-9_]`, the regex word characters. */
export function isWordChar(code: number): boolean {
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    code === 95
  );
}

/** Regex `\b` at index `j`: exactly one side of the gap is a word character. */
export function isWordBoundary(content: string, j: number): boolean {
  const left = j > 0 && isWordChar(content.charCodeAt(j - 1));
  const right = j < content.length && isWordChar(content.charCodeAt(j));
  return left !== right;
}

/**
 * End of the run of `inClass` characters that holds `from`, remembering the
 * last run so starts inside one long run do not each rescan it.
 */
export function runEndFinder(
  content: string,
  inClass: (code: number) => boolean,
): (from: number) => number {
  const n = content.length;
  let runFrom = -1;
  let runTo = -1;
  return (from) => {
    if (from >= runFrom && from < runTo) return runTo;
    let end = from;
    while (end < n && inClass(content.charCodeAt(end))) end++;
    runFrom = from;
    runTo = end;
    return end;
  };
}

/** Sorted positions of the characters accepted by `test`, with a next-at-or-after lookup. */
export class PositionIndex {
  private readonly positions: Int32Array;

  constructor(content: string, test: (code: number) => boolean) {
    let count = 0;
    for (let i = 0; i < content.length; i++) if (test(content.charCodeAt(i))) count++;
    this.positions = new Int32Array(count);
    let k = 0;
    for (let i = 0; i < content.length; i++)
      if (test(content.charCodeAt(i))) this.positions[k++] = i;
  }

  /** First indexed position at or after `from`, or -1. */
  next(from: number): number {
    const a = this.positions;
    let lo = 0;
    let hi = a.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (a[mid] < from) lo = mid + 1;
      else hi = mid;
    }
    return lo < a.length ? a[lo] : -1;
  }
}
