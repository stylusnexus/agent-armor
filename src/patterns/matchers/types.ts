/** One match, in the shape `RegExp.prototype.exec` would report it. */
export interface MatcherHit {
  /** Where the match starts (`match.index`). */
  index: number;
  /** The whole matched text (`match[0]`). */
  text: string;
  /** The text of the pattern's `extractGroup`; omit when the pattern has none. */
  extracted?: string;
}

/**
 * Hand-written replacement for one shipped regex whose backtracking can stall
 * a scan (#175). It finds exactly the matches the regex finds, in the same
 * order, in time linear in the input.
 *
 * A matcher is bound to the regex's exact source and flags, not to a pattern
 * id: `PatternDetector` uses it only when a pattern's `regex`, `flags` and
 * `extractGroup` are identical to the ones here, and falls back to the regex otherwise
 * (an edited or remote pattern). The equivalence test compares every matcher
 * with `new RegExp(regex, flags)` on generated input.
 */
export interface PatternMatcher {
  /** Source of the regex this matcher reproduces. */
  regex: string;
  /** Flags of the regex this matcher reproduces. */
  flags: string;
  /**
   * The pattern's `extractGroup` (0 when it has none). Part of the binding:
   * the matcher returns that group's text, so a pattern that reuses the regex
   * with a different group must fall back to the regex.
   */
  extractGroup: number;
  /** Every non-overlapping match, left to right, like a `g`-flag `exec` loop. */
  match(content: string): MatcherHit[];
  /**
   * Fragments the equivalence test glues together at random to build inputs.
   * Include the regex's literal pieces, near-misses, and the characters its
   * character classes care about (quotes, brackets, line breaks, whitespace).
   */
  fuzzAtoms: string[];
}
