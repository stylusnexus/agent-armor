/**
 * Dependency-free glob matcher for the pre-execution action gate (#57).
 *
 * Agent Armor ships with zero runtime dependencies, so path-allowlist matching
 * cannot lean on `minimatch`/`picomatch`. This module compiles a POSIX-style
 * glob to an anchored {@link RegExp} with the semantics operators expect:
 *
 * - `*`      matches any run of characters within a single path segment
 *            (never crosses `/`).
 * - `**`     a globstar (a whole segment that is exactly `**`) matches zero or
 *            more segments, crossing `/`. `a/**​/b` matches `a/b`, `a/x/b`,
 *            `a/x/y/b`. A leading `**​/` also matches zero leading segments.
 * - `?`      matches exactly one character that is not `/`.
 * - `[abc]`  character class, with ranges (`[a-z]`) and negation (`[!…]`/`[^…]`).
 * - `{a,b}`  brace alternation, nestable: `src/{a,b/c}.ts`.
 * - `\\x`    backslash escapes the next character, making it literal (`\\*`).
 *
 * Matching is anchored (the whole string must match) and case-sensitive, which
 * is the correct default for a fail-closed security allowlist. Paths are
 * normalized first: a leading `./` is stripped, repeated slashes collapse, and
 * a single trailing slash is dropped, so `./data//x/` and `data/x` are equal.
 */

/** Normalize a path for matching: strip leading `./`, collapse `//`, drop a
 * single trailing slash (so `data/` and `data` are equivalent). */
export function normalizePath(input: string): string {
  let p = input.replace(/\/{2,}/g, "/");
  while (p.startsWith("./")) p = p.slice(2);
  if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return p;
}

/** Escape regex-special characters when a glob char is taken literally. */
function escapeLiteral(ch: string): string {
  return ch.replace(/[.+^${}()|[\]\\*?]/g, "\\$&");
}

/**
 * Expand top-level brace groups, respecting nesting and escaping:
 * `a{b,c{d,e}}` → `["ab", "acd", "ace"]`. A brace group with no top-level comma
 * (e.g. `{foo}`) is treated as a literal and left in place.
 */
export function expandBraces(glob: string): string[] {
  let depth = 0;
  let openAt = -1;
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === "\\") {
      i++;
      continue;
    }
    if (ch === "{") {
      if (depth === 0) openAt = i;
      depth++;
    } else if (ch === "}") {
      if (depth === 0) continue;
      depth--;
      if (depth === 0 && openAt !== -1) {
        const body = glob.slice(openAt + 1, i);
        const parts: string[] = [];
        let inner = 0;
        let start = 0;
        for (let j = 0; j < body.length; j++) {
          const c = body[j];
          if (c === "\\") {
            j++;
            continue;
          }
          if (c === "{") inner++;
          else if (c === "}") inner--;
          else if (c === "," && inner === 0) {
            parts.push(body.slice(start, j));
            start = j + 1;
          }
        }
        parts.push(body.slice(start));
        if (parts.length === 1) {
          // No top-level comma → literal braces; keep scanning past this group.
          openAt = -1;
          continue;
        }
        const prefix = glob.slice(0, openAt);
        const suffix = glob.slice(i + 1);
        const results: string[] = [];
        for (const part of parts) {
          for (const expanded of expandBraces(prefix + part + suffix)) {
            results.push(expanded);
          }
        }
        return results;
      }
    }
  }
  return [glob];
}

/**
 * Compile a single (brace-free) glob alternative to a regex source string.
 *
 * Segments are tokenized; a segment that is exactly `**` becomes a globstar
 * token with cross-segment semantics, everything else a literal-segment token.
 * Globstars absorb their adjacent separators, so the emitted regex is:
 *
 *   whole pattern is `**`  ->  `.*`
 *   leading `**` segment   ->  `(?:[^/]+/)*`   (zero or more leading segments)
 *   any other `**` segment ->  `(?:/[^/]+)*`   (middle / trailing segments)
 *
 * A literal segment emits a `/` separator before it unless it directly follows
 * a leading globstar, whose `(?:[^/]+/)*` form already ends in `/`.
 */
function compileAlternative(glob: string): string {
  type Token = { globstar: true } | { globstar: false; src: string };
  const tokens: Token[] = glob
    .split("/")
    .map((segment): Token =>
      segment === "**"
        ? { globstar: true }
        : { globstar: false, src: compileSegment(segment) }
    );

  let re = "";
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.globstar) {
      if (tokens.length === 1) re += ".*";
      else if (i === 0) re += "(?:[^/]+/)*";
      else re += "(?:/[^/]+)*";
    } else {
      const prev = tokens[i - 1];
      const followsLeadingGlobstar = i === 1 && prev && prev.globstar === true;
      if (i > 0 && !followsLeadingGlobstar) re += "/";
      re += token.src;
    }
  }
  return re;
}

/** Compile one path segment (no `/`, not a bare `**`) to a regex source. */
function compileSegment(segment: string): string {
  let re = "";
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i];
    if (ch === "\\") {
      const next = segment[i + 1];
      if (next !== undefined) {
        re += escapeLiteral(next);
        i++;
      } else {
        re += "\\\\";
      }
    } else if (ch === "*") {
      re += "[^/]*";
    } else if (ch === "?") {
      re += "[^/]";
    } else if (ch === "[") {
      const compiled = compileCharClass(segment, i);
      if (compiled) {
        re += compiled.source;
        i = compiled.endIndex;
      } else {
        re += "\\[";
      }
    } else {
      re += escapeLiteral(ch);
    }
  }
  return re;
}

/**
 * Compile a `[...]` character class starting at `start` (the `[`). Returns the
 * regex source and the index of the closing `]`, or null if unterminated or if
 * it contains a `/` (which can never occur inside a path segment).
 */
function compileCharClass(
  segment: string,
  start: number
): { source: string; endIndex: number } | null {
  let i = start + 1;
  let negated = false;
  if (segment[i] === "!" || segment[i] === "^") {
    negated = true;
    i++;
  }
  let body = "";
  // A `]` immediately after the (optional) negation is a literal member.
  if (segment[i] === "]") {
    body += "\\]";
    i++;
  }
  let closed = false;
  for (; i < segment.length; i++) {
    const ch = segment[i];
    if (ch === "]") {
      closed = true;
      break;
    }
    if (ch === "/") return null;
    if (ch === "\\") {
      const next = segment[i + 1];
      if (next !== undefined) {
        body += "\\" + next;
        i++;
        continue;
      }
    }
    if (ch === "^" || ch === "\\") {
      body += "\\" + ch;
    } else {
      body += ch;
    }
  }
  if (!closed) return null;
  return { source: `[${negated ? "^" : ""}${body}]`, endIndex: i };
}

/**
 * Compile a glob pattern to an anchored {@link RegExp}. Brace alternatives are
 * expanded and joined with `|`; the result matches the entire input string.
 */
export function globToRegExp(glob: string): RegExp {
  const alternatives = expandBraces(glob).map((alt) =>
    compileAlternative(normalizePath(alt))
  );
  return new RegExp(`^(?:${alternatives.join("|")})$`);
}

/** True if `path` matches `glob` under the semantics documented above. */
export function matchGlob(glob: string, path: string): boolean {
  return globToRegExp(glob).test(normalizePath(path));
}

/** True if `path` matches at least one glob in `globs`. */
export function matchAnyGlob(globs: string[], path: string): boolean {
  return globs.some((g) => matchGlob(g, path));
}
