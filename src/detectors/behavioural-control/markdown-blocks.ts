/**
 * A small, linear-time markdown block pass for the reference-image scan (#225).
 *
 * A markdown parser splits text into blocks before it reads any inline text, so
 * a bracket or backtick can never reach across two blocks. This returns where
 * those boundaries are, and which ranges are not inline text at all (fenced and
 * indented code, HTML blocks, link reference definitions), so the scan can read
 * brackets and code spans the way a renderer does.
 *
 * It follows CommonMark: block quotes and list items nest and are matched line
 * by line (a list item continues at its content column), a paragraph continues
 * lazily, a fence or HTML block ends with its container, an ordered list that
 * does not start at 1 or an empty list item cannot interrupt a paragraph, and a
 * line indented four columns is code only when no paragraph is open. With
 * `tables`, GFM table cells are separate inline contexts. With `html`, HTML
 * blocks are recognised.
 *
 * It is an approximation (tabs inside containers, some edge cases of list
 * indentation). That is acceptable: the scan also keeps the raw reading, so a
 * mistake here can add or miss a finding the raw reading does not make, never
 * remove one.
 */

export interface BlockEvents {
  /** Where each boundary or hidden range starts. Nondecreasing. */
  at: number[];
  /** Where scanning resumes after it: the same offset for a boundary, past the range for a hidden one. */
  to: number[];
  /** True when every boundary is the start of a plain paragraph outside any container. */
  plain: boolean;
}

export interface BlockOptions {
  /** Recognise HTML blocks (a renderer with HTML on). */
  html: boolean;
  /** Treat GFM table pipes as cell boundaries. */
  tables: boolean;
  /**
   * Read the way markdown-it does where it differs from the CommonMark spec: a link reference definition is
   * a block of its own (the paragraph ends after it), a line without `>` after a quoted line continues the
   * quote even when no paragraph is open, and a lone `</script>`, `</style>`, `</pre>` or `</textarea>`
   * line starts an HTML block.
   */
  mdit?: boolean;
}

const BLOCK_TAGS = new Set(
  (
    'address article aside base basefont blockquote body caption center col colgroup dd details dialog dir div dl dt ' +
    'fieldset figcaption figure footer form frame frameset h1 h2 h3 h4 h5 h6 head header hr html iframe legend li link ' +
    'main menu menuitem nav noframes ol optgroup option p param search section summary table tbody td tfoot th thead ' +
    'title tr track ul'
  ).split(' '),
);

const HTML_TYPE1 = /^<(?:script|pre|style|textarea)(?:[ \t>]|$)/i;
const HTML_TYPE4 = /^<![A-Za-z]/;
const HTML_TAG_NAME = /^<\/?([A-Za-z][A-Za-z0-9-]*)(?:[ \t/>]|$)/;
const HTML_TYPE7 =
  /^(?:<[A-Za-z][A-Za-z0-9-]*(?:[ \t]+[A-Za-z_:][A-Za-z0-9_.:-]*(?:[ \t]*=[ \t]*(?:[^ \t"'=<>`]+|'[^']*'|"[^"]*"))?)*[ \t]*\/?>|<\/[A-Za-z][A-Za-z0-9-]*[ \t]*>)[ \t]*$/;
const TABLE_DELIMITER = /^\|?[ \t]*:?-+:?[ \t]*(?:\|[ \t]*:?-+:?[ \t]*)*\|?[ \t]*$/;

/** The next occurrence of an unescaped `needle` at or after `from`, cached so repeated searches stay linear. */
function makeFinder(content: string, needle: string, skipEscaped: boolean): (from: number) => number {
  let searched = -1;
  let found = -2;
  return (from: number): number => {
    if (found !== -2 && from >= searched && (found === -1 || from <= found)) return found;
    let at = content.indexOf(needle, from);
    while (skipEscaped && at > 0) {
      let b = at - 1;
      while (b >= 0 && content.charCodeAt(b) === 92) b--;
      if ((at - 1 - b) % 2 === 0) break; // an even run of backslashes does not escape it
      at = content.indexOf(needle, at + 1);
    }
    searched = from;
    found = at;
    return at;
  };
}

export function blockEvents(content: string, opts: BlockOptions): BlockEvents {
  const n = content.length;
  const out: BlockEvents = { at: [], to: [], plain: true };

  const containers: number[] = []; // 0 is a block quote; a positive number is a list item's content width
  let para = false;
  let defChain = false; // the open paragraph so far is only link reference definitions
  let fenceChar = 0;
  let fenceLen = 0;
  let fenceEvent = -1;
  let htmlType = 0;
  let htmlEvent = -1;
  let codeEvent = -1;
  let tableOpen = false;
  let lastAt = -1;
  let skipUntil = 0;

  const findDoubleQuote = makeFinder(content, '"', true);
  const findSingleQuote = makeFinder(content, "'", true);
  const findCommentEnd = makeFinder(content, '-->', false);
  const findPiEnd = makeFinder(content, '?>', false);
  const findCdataEnd = makeFinder(content, ']]>', false);
  const findDeclEnd = makeFinder(content, '>', false);
  // Where the next blank line starts at or after a position, so a title cannot run across one.
  const blankLines: number[] = [];
  {
    for (let i = 0; i <= n; ) {
      let k = i;
      while (k < n && (content.charCodeAt(k) === 32 || content.charCodeAt(k) === 9)) k++;
      if (k >= n || content.charCodeAt(k) === 10 || content.charCodeAt(k) === 13) blankLines.push(i);
      while (k < n && content.charCodeAt(k) !== 10 && content.charCodeAt(k) !== 13) k++;
      if (k >= n) break;
      i = k + (content.charCodeAt(k) === 13 && content.charCodeAt(k + 1) === 10 ? 2 : 1);
    }
  }
  let blankCursor = 0;
  const nextBlank = (from: number): number => {
    while (blankCursor < blankLines.length && blankLines[blankCursor] < from) blankCursor++;
    return blankCursor < blankLines.length ? blankLines[blankCursor] : n + 1;
  };

  const push = (at: number, to: number, trivial: boolean): number => {
    if (to === at && at === lastAt) return out.at.length - 1; // one boundary per position
    out.at.push(at);
    out.to.push(to);
    lastAt = at;
    if (!trivial) out.plain = false;
    return out.at.length - 1;
  };

  const lineEndOf = (from: number): number => {
    let e = from;
    while (e < n && content.charCodeAt(e) !== 10 && content.charCodeAt(e) !== 13) e++;
    return e;
  };
  const nextLineOf = (e: number): number => (e >= n ? n + 1 : e + (content.charCodeAt(e) === 13 && content.charCodeAt(e + 1) === 10 ? 2 : 1));

  /** Unescaped pipes in a table line are cell boundaries. */
  const pushPipes = (from: number, to: number): void => {
    for (let i = from; i < to; i++) {
      if (content.charCodeAt(i) === 124 && !(i > 0 && content.charCodeAt(i - 1) === 92)) push(i, i + 1, false);
    }
  };

  /** How many cells a table line has, by unescaped pipes. */
  const cellCount = (text: string): number => {
    let t = text.trim();
    if (t.startsWith('|')) t = t.slice(1);
    if (t.endsWith('|') && !t.endsWith('\\|')) t = t.slice(0, -1);
    let count = 1;
    for (let i = 0; i < t.length; i++) if (t.charCodeAt(i) === 124 && !(i > 0 && t.charCodeAt(i - 1) === 92)) count++;
    return count;
  };

  const isTableStart = (q: number, lineEnd: number): boolean => {
    if (!opts.tables) return false;
    const next = nextLineOf(lineEnd);
    if (next > n) return false;
    const nextEnd = lineEndOf(next);
    let d = next;
    while (d < nextEnd && (content.charCodeAt(d) === 32 || content.charCodeAt(d) === 9 || content.charCodeAt(d) === 62)) d++;
    const delimiter = content.slice(d, nextEnd);
    if (!TABLE_DELIMITER.test(delimiter)) return false;
    const header = content.slice(q, lineEnd);
    if (!header.includes('|') && !delimiter.includes('|')) return false;
    return cellCount(header) === cellCount(delimiter);
  };

  /** A list marker at `q`: its width including the spaces after it, whether the item is empty, and an ordered number. */
  const listMarker = (q: number, lineEnd: number, col: number): { len: number; width: number; empty: boolean; ordered: number } | undefined => {
    let c = content.charCodeAt(q);
    let len = 0;
    let ordered = -1;
    if (c === 45 || c === 43 || c === 42) {
      len = 1;
    } else if (c >= 48 && c <= 57) {
      let d = q;
      while (d < lineEnd && d - q < 9 && content.charCodeAt(d) >= 48 && content.charCodeAt(d) <= 57) d++;
      c = content.charCodeAt(d);
      if ((c !== 46 && c !== 41) || d === q) return undefined;
      len = d + 1 - q;
      ordered = Number(content.slice(q, d));
    } else {
      return undefined;
    }
    const after = q + len;
    if (after < lineEnd && content.charCodeAt(after) !== 32 && content.charCodeAt(after) !== 9) return undefined;
    let spaces = 0;
    let x = after;
    let cc = col + len;
    while (x < lineEnd && (content.charCodeAt(x) === 32 || content.charCodeAt(x) === 9)) {
      const w = content.charCodeAt(x) === 9 ? 4 - (cc % 4) : 1;
      spaces += w;
      cc += w;
      x++;
    }
    if (x >= lineEnd) return { len, width: len + 1, empty: true, ordered };
    return { len, width: spaces >= 5 ? len + 1 : len + spaces, empty: false, ordered };
  };

  const isThematic = (q: number, lineEnd: number): boolean => {
    const c = content.charCodeAt(q);
    if (c !== 45 && c !== 42 && c !== 95) return false;
    let count = 0;
    for (let i = q; i < lineEnd; i++) {
      const ch = content.charCodeAt(i);
      if (ch === c) count++;
      else if (ch !== 32 && ch !== 9) return false;
    }
    return count >= 3;
  };

  const isAtx = (q: number, lineEnd: number): boolean => {
    if (content.charCodeAt(q) !== 35) return false;
    let h = q;
    while (content.charCodeAt(h) === 35) h++;
    return h - q <= 6 && (h >= lineEnd || content.charCodeAt(h) === 32 || content.charCodeAt(h) === 9);
  };

  const fenceAt = (q: number, lineEnd: number): { ch: number; len: number } | undefined => {
    const c = content.charCodeAt(q);
    if (c !== 96 && c !== 126) return undefined;
    let f = q;
    while (content.charCodeAt(f) === c) f++;
    if (f - q < 3) return undefined;
    if (c === 96) {
      for (let x = f; x < lineEnd; x++) if (content.charCodeAt(x) === 96) return undefined; // a backtick fence's info string has no backtick
    }
    return { ch: c, len: f - q };
  };

  /** HTML block type 1 to 7 starting at `q`, or 0. Type 7 cannot interrupt a paragraph. */
  const htmlStart = (q: number, lineEnd: number, canType7: boolean): number => {
    if (!opts.html || content.charCodeAt(q) !== 60) return 0;
    const text = content.slice(q, Math.min(lineEnd, q + 400));
    if (HTML_TYPE1.test(text)) return 1;
    if (text.startsWith('<!--')) return 2;
    if (text.startsWith('<?')) return 3;
    if (text.startsWith('<![CDATA[')) return 5;
    if (HTML_TYPE4.test(text)) return 4;
    const tag = HTML_TAG_NAME.exec(text);
    if (tag && BLOCK_TAGS.has(tag[1].toLowerCase())) return 6;
    if (canType7 && lineEnd - q <= 400 && HTML_TYPE7.test(text) && (opts.mdit || !/^<\/?(?:script|style|pre|textarea)[ \t>/]/i.test(text))) return 7;
    return 0;
  };

  /** Does the line from `from` contain the end of an HTML block of this type? */
  const htmlEnds = (type: number, from: number, lineEnd: number): boolean => {
    switch (type) {
      case 1: {
        const text = content.slice(from, lineEnd).toLowerCase();
        return text.includes('</script>') || text.includes('</pre>') || text.includes('</style>') || text.includes('</textarea>');
      }
      case 2: {
        const at = findCommentEnd(from);
        return at !== -1 && at < lineEnd;
      }
      case 3: {
        const at = findPiEnd(from);
        return at !== -1 && at < lineEnd;
      }
      case 4: {
        const at = findDeclEnd(from);
        return at !== -1 && at < lineEnd;
      }
      case 5: {
        const at = findCdataEnd(from);
        return at !== -1 && at < lineEnd;
      }
      default:
        return false;
    }
  };

  /** Does any line after the one at `from`, up to `to`, start a block that interrupts a paragraph (so a title cannot continue)? */
  const crossesBlockStart = (from: number, to: number): boolean => {
    let ls = nextLineOf(lineEndOf(from));
    while (ls <= to && ls <= n) {
      const le = lineEndOf(ls);
      let q = ls;
      while (q < le && (content.charCodeAt(q) === 32 || content.charCodeAt(q) === 9 || content.charCodeAt(q) === 62)) q++;
      if (q < le) {
        const marker = listMarker(q, le, 0);
        if (
          isAtx(q, le) ||
          !!fenceAt(q, le) ||
          isThematic(q, le) ||
          htmlStart(q, le, false) !== 0 ||
          (!!marker && !marker.empty && (marker.ordered === -1 || marker.ordered === 1))
        ) {
          return true;
        }
      }
      ls = nextLineOf(le);
    }
    return false;
  };

  /** The end of a link reference definition starting at `q` (after its last line break), or -1. */
  const definitionEnd = (q: number, inQuote: boolean): number => {
    if (content.charCodeAt(q) !== 91) return -1;
    let i = q + 1;
    let any = false;
    while (i < n) {
      const c = content.charCodeAt(i);
      if (c === 92) {
        i += 2;
        any = true;
        continue;
      }
      if (c === 91) return -1;
      if (c === 93) break;
      if (c !== 32 && c !== 9 && c !== 10 && c !== 13) any = true;
      i++;
    }
    if (i >= n || !any || content.charCodeAt(i + 1) !== 58) return -1;
    i += 2;
    const skipBlank = (from: number): number => {
      let x = from;
      while (x < n && (content.charCodeAt(x) === 32 || content.charCodeAt(x) === 9)) x++;
      if (x < n && (content.charCodeAt(x) === 10 || content.charCodeAt(x) === 13)) {
        x = nextLineOf(x);
        while (x < n && (content.charCodeAt(x) === 32 || content.charCodeAt(x) === 9 || (inQuote && content.charCodeAt(x) === 62))) x++;
      }
      return x;
    };
    i = skipBlank(i);
    if (i >= n) return -1;
    // destination
    if (content.charCodeAt(i) === 60) {
      let x = i + 1;
      while (x < n && content.charCodeAt(x) !== 62 && content.charCodeAt(x) !== 10 && content.charCodeAt(x) !== 13 && content.charCodeAt(x) !== 60) x += content.charCodeAt(x) === 92 ? 2 : 1;
      if (content.charCodeAt(x) !== 62) return -1;
      i = x + 1;
    } else {
      const start = i;
      while (i < n && content.charCodeAt(i) !== 32 && content.charCodeAt(i) !== 9 && content.charCodeAt(i) !== 10 && content.charCodeAt(i) !== 13) i++;
      if (i === start) return -1;
    }
    const destLineEnd = (): number => {
      let x = i;
      while (x < n && (content.charCodeAt(x) === 32 || content.charCodeAt(x) === 9)) x++;
      if (x >= n) return n + 1;
      if (content.charCodeAt(x) === 10 || content.charCodeAt(x) === 13) return nextLineOf(x);
      return -1;
    };
    // optional title, separated by whitespace
    const afterDest = i;
    let t = i;
    while (t < n && (content.charCodeAt(t) === 32 || content.charCodeAt(t) === 9)) t++;
    let sep = t > afterDest;
    if (t < n && (content.charCodeAt(t) === 10 || content.charCodeAt(t) === 13)) {
      t = nextLineOf(t);
      while (t < n && (content.charCodeAt(t) === 32 || content.charCodeAt(t) === 9 || (inQuote && content.charCodeAt(t) === 62))) t++;
      sep = true;
    }
    const open = content.charCodeAt(t);
    if (sep && (open === 34 || open === 39 || open === 40)) {
      let close: number;
      if (open === 40) {
        // a parenthesised title ends at the first `)` and cannot contain an unescaped `(`
        close = t + 1;
        const limit = Math.min(nextBlank(t), n);
        while (close < limit && content.charCodeAt(close) !== 41) {
          if (content.charCodeAt(close) === 40) {
            close = -1;
            break;
          }
          close += content.charCodeAt(close) === 92 ? 2 : 1;
        }
        if (close >= limit) close = -1;
      } else {
        close = open === 34 ? findDoubleQuote(t + 1) : findSingleQuote(t + 1);
      }
      if (close !== -1 && close < nextBlank(t) && !crossesBlockStart(t, close)) {
        let x = close + 1;
        while (x < n && (content.charCodeAt(x) === 32 || content.charCodeAt(x) === 9)) x++;
        if (x >= n) return n + 1;
        if (content.charCodeAt(x) === 10 || content.charCodeAt(x) === 13) return nextLineOf(x);
      }
    }
    return destLineEnd();
  };

  let pos = 0;
  while (pos <= n) {
    const lineStart = pos;
    const lineEnd = lineEndOf(lineStart);
    const next = nextLineOf(lineEnd);
    pos = next;
    if (lineStart < skipUntil) continue; // inside a definition already read

    // 1. Match the open containers against this line.
    let p = lineStart;
    let col = 0;
    let matched = 0;
    // Leading whitespace is measured once and consumed column by column, so matching many nested list items
    // costs one step each, not a rescan of the indent.
    let wsCols = -1; // whitespace columns available at `p` (plus `owed` already taken), or -1 if not measured
    let owed = 0; // columns consumed from them that `p` has not yet moved past
    let wsBlank = false;
    const catchUp = (): void => {
      while (owed > 0 && p < lineEnd && (content.charCodeAt(p) === 32 || content.charCodeAt(p) === 9)) {
        const step = content.charCodeAt(p) === 9 ? 4 - (col % 4) : 1;
        owed -= step;
        col += step;
        p++;
      }
      owed = 0;
    };
    for (; matched < containers.length; matched++) {
      const w = containers[matched];
      if (w === 0) {
        catchUp();
        wsCols = -1;
        let q = p;
        let cc = col;
        let spaces = 0;
        while (q < lineEnd && content.charCodeAt(q) === 32 && spaces < 3) {
          q++;
          cc++;
          spaces++;
        }
        if (q < lineEnd && content.charCodeAt(q) === 62) {
          p = q + 1;
          col = cc + 1;
          if (p < lineEnd && (content.charCodeAt(p) === 32 || content.charCodeAt(p) === 9)) {
            col += content.charCodeAt(p) === 9 ? 4 - (col % 4) : 1;
            p++;
          }
          continue;
        }
        break;
      }
      if (wsCols < 0) {
        let q = p;
        let cc = col;
        while (q < lineEnd && (content.charCodeAt(q) === 32 || content.charCodeAt(q) === 9)) {
          cc += content.charCodeAt(q) === 9 ? 4 - (cc % 4) : 1;
          q++;
        }
        wsCols = cc - col;
        wsBlank = q >= lineEnd;
      }
      if (wsBlank) continue; // a blank line stays in a list item
      if (wsCols < w) break;
      wsCols -= w;
      owed += w;
    }
    catchUp();
    const allMatched = matched === containers.length;
    let q = p;
    let indent = 0;
    while (q < lineEnd && (content.charCodeAt(q) === 32 || content.charCodeAt(q) === 9)) {
      indent += content.charCodeAt(q) === 9 ? 4 - ((col + indent) % 4) : 1;
      q++;
    }
    const blank = q >= lineEnd;

    // 2. A leaf block that continues across lines.
    if (fenceChar !== 0) {
      if (allMatched) {
        if (indent < 4 && content.charCodeAt(q) === fenceChar) {
          let f = q;
          while (content.charCodeAt(f) === fenceChar) f++;
          if (f - q >= fenceLen) {
            let r = f;
            while (r < lineEnd && (content.charCodeAt(r) === 32 || content.charCodeAt(r) === 9)) r++;
            if (r >= lineEnd) {
              out.to[fenceEvent] = next > n ? n : next;
              fenceChar = 0;
            }
          }
        }
        continue;
      }
      out.to[fenceEvent] = lineStart; // the container ended, and the fence with it
      fenceChar = 0;
    }
    if (htmlType !== 0) {
      if (allMatched && !((htmlType === 6 || htmlType === 7) && blank)) {
        if (htmlEnds(htmlType, p, lineEnd)) {
          out.to[htmlEvent] = next > n ? n : next;
          htmlType = 0;
        }
        continue;
      }
      out.to[htmlEvent] = lineStart;
      htmlType = 0;
    }
    if (codeEvent !== -1) {
      if (allMatched && (blank || indent >= 4)) continue;
      out.to[codeEvent] = lineStart;
      codeEvent = -1;
    }
    if (tableOpen) {
      if (
        allMatched &&
        !blank &&
        indent < 4 &&
        !isAtx(q, lineEnd) &&
        !fenceAt(q, lineEnd) &&
        !isThematic(q, lineEnd) &&
        content.charCodeAt(q) !== 62 &&
        !listMarker(q, lineEnd, col + indent) &&
        htmlStart(q, lineEnd, false) === 0
      ) {
        push(lineStart, lineStart, false);
        pushPipes(q, lineEnd);
        continue;
      }
      tableOpen = false;
    }

    // 3. A lazy paragraph continuation keeps every container open.
    if (!allMatched) {
      let startsBlock = blank;
      if (!startsBlock) {
        if (indent >= 4) {
          startsBlock = false;
        } else {
          const marker = listMarker(q, lineEnd, col + indent);
          startsBlock =
            content.charCodeAt(q) === 62 ||
            isAtx(q, lineEnd) ||
            !!fenceAt(q, lineEnd) ||
            isThematic(q, lineEnd) ||
            htmlStart(q, lineEnd, false) !== 0 ||
            !!marker || // the paragraph is not the current container here, so any list marker starts a list
            isTableStart(q, lineEnd);
        }
      }
      if (para && !startsBlock) continue;
      if (opts.mdit && !startsBlock && !blank && matched < containers.length && containers[matched] === 0 && !tableOpen) {
        // markdown-it: a line without `>` after a quoted line stays in the quote, as a paragraph
        containers.length = matched + 1;
        if (!para) {
          push(lineStart, lineStart, false);
          para = true;
          defChain = false;
        }
        continue;
      }
      containers.length = matched; // close the containers this line is not in
      para = false;
      defChain = false;
    } else if (blank) {
      para = false;
      defChain = false;
      continue;
    }

    // 4. Start new containers.
    let newBlock = false;
    for (;;) {
      q = p;
      indent = 0;
      while (q < lineEnd && (content.charCodeAt(q) === 32 || content.charCodeAt(q) === 9)) {
        indent += content.charCodeAt(q) === 9 ? 4 - ((col + indent) % 4) : 1;
        q++;
      }
      if (q >= lineEnd || indent >= 4) break;
      if (isThematic(q, lineEnd)) break;
      if (content.charCodeAt(q) === 62) {
        containers.push(0);
        para = false;
      defChain = false;
        newBlock = true;
        p = q + 1;
        col += indent + 1;
        if (p < lineEnd && (content.charCodeAt(p) === 32 || content.charCodeAt(p) === 9)) {
          col += content.charCodeAt(p) === 9 ? 4 - (col % 4) : 1;
          p++;
        }
        continue;
      }
      const marker = listMarker(q, lineEnd, col + indent);
      if (marker && !(para && (marker.empty || (marker.ordered !== -1 && marker.ordered !== 1)))) {
        containers.push(marker.width);
        para = false;
      defChain = false;
        newBlock = true;
        // advance past the marker and the spaces that belong to the item
        let used = marker.len;
        let x = q + marker.len;
        while (x < lineEnd && used < marker.width && (content.charCodeAt(x) === 32 || content.charCodeAt(x) === 9)) {
          used += content.charCodeAt(x) === 9 ? 4 - ((col + indent + used) % 4) : 1;
          x++;
        }
        col += indent + used;
        p = x;
        continue;
      }
      break;
    }
    const trivial = containers.length === 0;

    // 5. Start the leaf block.
    q = p;
    indent = 0;
    while (q < lineEnd && (content.charCodeAt(q) === 32 || content.charCodeAt(q) === 9)) {
      indent += content.charCodeAt(q) === 9 ? 4 - ((col + indent) % 4) : 1;
      q++;
    }
    if (q >= lineEnd) {
      if (newBlock) push(lineStart, lineStart, false); // an empty list item or quote
      para = false;
      defChain = false;
      continue;
    }
    if (indent >= 4) {
      if (para) continue; // paragraph text, whatever it looks like
      codeEvent = push(lineStart, n, false);
      continue;
    }
    if (isAtx(q, lineEnd)) {
      push(lineStart, lineStart, false);
      para = false;
      defChain = false;
      continue;
    }
    const fence = fenceAt(q, lineEnd);
    if (fence) {
      fenceChar = fence.ch;
      fenceLen = fence.len;
      fenceEvent = push(lineStart, n, false);
      para = false;
      defChain = false;
      continue;
    }
    if (para && !newBlock) {
      // setext underline: a run of `=` or `-` directly under a paragraph
      let allSame = true;
      const c0 = content.charCodeAt(q);
      if (c0 === 61 || c0 === 45) {
        let x = q;
        while (x < lineEnd && content.charCodeAt(x) === c0) x++;
        while (x < lineEnd && (content.charCodeAt(x) === 32 || content.charCodeAt(x) === 9)) x++;
        allSame = x >= lineEnd;
      } else {
        allSame = false;
      }
      if (allSame) {
        para = false;
      defChain = false;
        continue;
      }
    }
    if (isThematic(q, lineEnd)) {
      push(lineStart, lineStart, false);
      para = false;
      defChain = false;
      continue;
    }
    const html = htmlStart(q, lineEnd, !para);
    if (html !== 0) {
      htmlType = html;
      htmlEvent = push(lineStart, n, false);
      para = false;
      defChain = false;
      if (htmlEnds(html, q, lineEnd)) {
        out.to[htmlEvent] = next > n ? n : next;
        htmlType = 0;
      }
      continue;
    }
    if (isTableStart(q, lineEnd)) {
      push(lineStart, lineStart, false);
      pushPipes(q, lineEnd);
      tableOpen = true;
      para = false;
      defChain = false;
      continue;
    }
    if (!para || defChain) {
      // Definitions are read from the start of a paragraph, one after another; the rest of the paragraph,
      // and any line after it that is not a new block, is still that paragraph.
      const end = definitionEnd(q, containers.includes(0));
      if (end !== -1) {
        push(lineStart, Math.min(end, n), false);
        skipUntil = end;
        // CommonMark reads definitions from the start of a paragraph, so what follows is still that paragraph;
        // markdown-it makes a definition a block of its own.
        para = !opts.mdit;
        defChain = !opts.mdit;
        continue;
      }
    }
    if (!para) {
      push(lineStart, lineStart, trivial && !newBlock);
      para = true;
    }
    defChain = false;
  }
  return out;
}

/*
 * The simpler block model that shipped in #224: a flat pass over lines that finds blank and quote-only lines,
 * list items, thematic breaks, quote depth changes, headings and fenced code. It does not track list content
 * columns or paragraphs, so it reads some documents differently from a renderer. The scan keeps it as one more
 * reading beside the container-aware one above, so a document it flagged is still flagged.
 */
/** Closing-fence candidates of one fence character, with a pointer to the next candidate whose run is longer. */
interface CloserList {
  line: number[];
  run: number[];
  longer: number[];
  from: number;
}

function buildCloserList(runOfLine: Int32Array, indentOfLine: Int32Array, strict: boolean): CloserList {
  const line: number[] = [];
  const run: number[] = [];
  for (let k = 0; k < runOfLine.length; k++) {
    if (runOfLine[k] > 0 && (!strict || indentOfLine[k] < 4)) {
      line.push(k);
      run.push(runOfLine[k]);
    }
  }
  const longer = new Array<number>(line.length);
  const stack: number[] = [];
  for (let i = line.length - 1; i >= 0; i--) {
    while (stack.length > 0 && run[stack[stack.length - 1]] <= run[i]) stack.pop();
    longer[i] = stack.length > 0 ? stack[stack.length - 1] : line.length;
    stack.push(i);
  }
  return { line, run, longer, from: 0 };
}

/**
 * The block boundaries a markdown parser finds before it reads any inline text,
 * so brackets and code spans never cross them: a blank or quote-only line, a
 * list item, a thematic break, a block quote that starts or deepens, a heading
 * (a boundary on both sides), and a fenced code block, which can sit on a
 * list item's line or inside a quote and hides everything up to its closing
 * fence. An unclosed fence hides nothing: the rest of the text stays readable.
 *
 * Linear: each line is parsed once into tables, and a fence's closing line is
 * found from them by jumping over lines that cannot close it, so a document of
 * thousands of unclosed fences costs no more than one of a single fence.
 */
export function legacyBlockEvents(content: string): BlockEvents {
  const n = content.length;
  const out: BlockEvents = { at: [], to: [], plain: true };
  const isSpace = (c: number): boolean => c === 32 || c === 9;
  /** Any character `String.prototype.trim` removes, other than a line break. */
  const isTrimmed = (c: number): boolean =>
    c === 32 || c === 9 || c === 11 || c === 12 || c === 0xa0 || c === 0x1680 || (c >= 0x2000 && c <= 0x200a) || c === 0x2028 || c === 0x2029 || c === 0x202f || c === 0x205f || c === 0x3000 || c === 0xfeff;
  const nextLineAfter = (from: number): number => {
    let e = from;
    while (e < n && content.charCodeAt(e) !== 10 && content.charCodeAt(e) !== 13) e++;
    return e >= n ? n + 1 : e + (content.charCodeAt(e) === 13 && content.charCodeAt(e + 1) === 10 ? 2 : 1);
  };
  let m = 0;
  for (let i = 0; i <= n; i = nextLineAfter(i)) m++;
  const starts = new Int32Array(m + 1);
  const depthOf = new Int32Array(m);
  const indentOf = new Int32Array(m);
  const restOf = new Int32Array(m); // where the line's text starts, after indent, quote and list markers
  const flags = new Uint8Array(m); // 1 list item, 2 thematic break
  const backtickRun = new Int32Array(m); // a line that is only a run of backticks: its length
  const tildeRun = new Int32Array(m);
  for (let k = 0, i = 0; k < m; k++, i = nextLineAfter(i)) {
    starts[k] = i;
    let q = i;
    let indent = 0;
    while (q < n && isSpace(content.charCodeAt(q))) {
      indent = content.charCodeAt(q) === 9 ? indent + 4 - (indent % 4) : indent + 1;
      q++;
    }
    let depth = 0;
    let flag = 0;
    let allowThematic = true; // checked at the line start and after each `>`, so a long run of markers is scanned once
    for (;;) {
      while (q < n && isSpace(content.charCodeAt(q))) q++;
      const c = content.charCodeAt(q);
      if (allowThematic && (c === 45 || c === 42 || c === 95)) {
        // `---`, `***`, `___`, with spaces between: a thematic break, not a list item
        let x = q;
        let count = 0;
        while (x < n && (content.charCodeAt(x) === c || isSpace(content.charCodeAt(x)))) {
          if (content.charCodeAt(x) === c) count++;
          x++;
        }
        const ch = content.charCodeAt(x);
        if (count >= 3 && (x >= n || ch === 10 || ch === 13)) {
          flag |= 2;
          break;
        }
      }
      allowThematic = false;
      if (c === 62) {
        depth++;
        q++;
        allowThematic = true;
        continue;
      }
      if (c === 45 || c === 42 || c === 43) {
        if (isSpace(content.charCodeAt(q + 1))) {
          flag |= 1;
          q++;
          continue;
        }
      } else if (c >= 48 && c <= 57) {
        let d = q;
        while (d < n && d - q < 9 && content.charCodeAt(d) >= 48 && content.charCodeAt(d) <= 57) d++;
        const mark = content.charCodeAt(d);
        if ((mark === 46 || mark === 41) && isSpace(content.charCodeAt(d + 1))) {
          flag |= 1;
          q = d + 1;
          continue;
        }
      }
      break;
    }
    depthOf[k] = depth;
    indentOf[k] = indent;
    restOf[k] = q;
    flags[k] = flag;
    // Could this line close a fence? Only a run of one fence character, then whitespace.
    const f = content.charCodeAt(q);
    if (f === 96 || f === 126) {
      let h = q;
      while (content.charCodeAt(h) === f) h++;
      let e = h;
      while (e < n && isTrimmed(content.charCodeAt(e))) e++;
      const after = content.charCodeAt(e);
      if (e >= n || after === 10 || after === 13) (f === 96 ? backtickRun : tildeRun)[k] = h - q;
    }
  }
  starts[m] = n + 1;

  // The next line after k whose quote depth is below k's, so a fence ending with its quote is found by jumping.
  const nextShallower = new Int32Array(m);
  {
    const stack: number[] = [];
    for (let k = m - 1; k >= 0; k--) {
      while (stack.length > 0 && depthOf[stack[stack.length - 1]] >= depthOf[k]) stack.pop();
      nextShallower[k] = stack.length > 0 ? stack[stack.length - 1] : m;
      stack.push(k);
    }
  }
  const closers = {
    backtick: [buildCloserList(backtickRun, indentOf, true), buildCloserList(backtickRun, indentOf, false)],
    tilde: [buildCloserList(tildeRun, indentOf, true), buildCloserList(tildeRun, indentOf, false)],
  };
  /** Where a fence opened on line `k` ends: the line to resume at, and whether that line is the closing fence (consumed). */
  const fenceEnd = (k: number, tilde: boolean, len: number, depth: number, container: boolean): { resume: number; consumed: boolean } | undefined => {
    let quoteEnds = k + 1;
    while (quoteEnds < m && depthOf[quoteEnds] >= depth) quoteEnds = nextShallower[quoteEnds];
    const list = (tilde ? closers.tilde : closers.backtick)[container ? 1 : 0];
    while (list.from < list.line.length && list.line[list.from] <= k) list.from++;
    let at = list.from;
    while (at < list.line.length && list.run[at] < len) at = list.longer[at];
    const closing = at < list.line.length ? list.line[at] : m;
    if (quoteEnds < m && quoteEnds <= closing) return { resume: quoteEnds, consumed: false };
    if (closing < m) return { resume: closing + 1, consumed: true };
    return undefined;
  };

  const push = (at: number, to: number, plain = false): void => {
    out.at.push(at);
    out.to.push(to);
    if (!plain) out.plain = false;
  };
  let prevDepth = 0;
  for (let k = 0; k < m; ) {
    const line = starts[k];
    const q = restOf[k];
    const c = content.charCodeAt(q);
    const depth = depthOf[k];
    const container = depth > 0 || (flags[k] & 1) !== 0;
    const blank = q >= n || c === 10 || c === 13;
    const indentedText = !blank && indentOf[k] >= 4 && !container; // indented code cannot interrupt a paragraph
    if (depth > prevDepth && !indentedText) push(line, line); // a block quote starts or deepens
    prevDepth = depth;
    let nextK = k + 1;
    if (!indentedText) {
      if (flags[k] & 2) {
        push(line, line);
      } else {
        if (flags[k] & 1) push(line, line); // a list item starts a new block
        if (blank) {
          push(line, line, depth === 0 && (flags[k] & 1) === 0); // a blank or quote-only line
        } else if (c === 35) {
          let h = q;
          while (content.charCodeAt(h) === 35) h++;
          const after = content.charCodeAt(h);
          if (h - q <= 6 && (h >= n || after === 32 || after === 9 || after === 10 || after === 13)) {
            push(line, line);
            if (k + 1 < m) push(starts[k + 1], starts[k + 1]);
          }
        } else if (c === 96 || c === 126) {
          let f = q;
          while (content.charCodeAt(f) === c) f++;
          const fence = f - q;
          let infoHasBacktick = false;
          if (c === 96) {
            for (let x = f; x < n && content.charCodeAt(x) !== 10 && content.charCodeAt(x) !== 13; x++) {
              if (content.charCodeAt(x) === 96) {
                infoHasBacktick = true;
                break;
              }
            }
          }
          if (fence >= 3 && !infoHasBacktick) {
            const end = fenceEnd(k, c === 126, fence, depth, container);
            if (end) {
              push(line, end.resume < m ? starts[end.resume] : n);
              nextK = end.resume;
            } else {
              push(line, line); // unclosed: the fence hides nothing
            }
          }
        }
      }
    }
    k = nextK;
  }
  return out;
}


/**
 * One linear pass over the lines to find which renderer readings the text needs. Plain scans, not regular
 * expressions, so a long line of pipes or list markers cannot make it slow.
 */
export function blockTriggers(content: string, htmlLike: boolean): { table: boolean; mdit: boolean } {
  const n = content.length;
  let table = false;
  let mdit = false;
  let prevDefinition = false;
  let prevQuote = false;
  let prevHasPipe = false;
  let i = 0;
  while (i <= n) {
    let e = i;
    let hasPipe = false;
    while (e < n && content.charCodeAt(e) !== 10 && content.charCodeAt(e) !== 13) {
      if (content.charCodeAt(e) === 124) hasPipe = true;
      e++;
    }
    // skip quote markers, spaces and list markers
    let q = i;
    let quote = false;
    for (;;) {
      while (q < e && (content.charCodeAt(q) === 32 || content.charCodeAt(q) === 9 || content.charCodeAt(q) === 62)) {
        if (content.charCodeAt(q) === 62) quote = true;
        q++;
      }
      const c = content.charCodeAt(q);
      if ((c === 45 || c === 42 || c === 43) && (content.charCodeAt(q + 1) === 32 || content.charCodeAt(q + 1) === 9)) {
        q++;
        continue;
      }
      if (c >= 48 && c <= 57) {
        let d = q;
        while (d < e && d - q < 9 && content.charCodeAt(d) >= 48 && content.charCodeAt(d) <= 57) d++;
        if ((content.charCodeAt(d) === 46 || content.charCodeAt(d) === 41) && (content.charCodeAt(d + 1) === 32 || content.charCodeAt(d + 1) === 9)) {
          q = d + 1;
          continue;
        }
      }
      break;
    }
    const blank = q >= e;
    // A table needs a delimiter row (`|---|:-:|`) right after a line that has a pipe.
    if (!table && prevHasPipe && !blank && isDelimiterRow(content, q, e)) table = true;
    // markdown-it differs when text follows a definition, when a line without `>` follows a quoted line, or at a lone closing raw tag.
    if (!mdit) {
      if (!blank && prevDefinition) mdit = true;
      else if (!blank && prevQuote && !quote) mdit = true;
      else if (htmlLike && isClosingRawTag(content, i, e)) mdit = true;
    }
    let definition = false;
    if (content.charCodeAt(q) === 91) {
      let x = q + 1;
      while (x < e && content.charCodeAt(x) !== 93 && content.charCodeAt(x) !== 91) x += content.charCodeAt(x) === 92 ? 2 : 1;
      definition = x < e && content.charCodeAt(x) === 93 && content.charCodeAt(x + 1) === 58;
    }
    prevDefinition = definition;
    prevQuote = quote && !blank;
    prevHasPipe = hasPipe;
    if (table && mdit) break;
    if (e >= n) break;
    i = e + (content.charCodeAt(e) === 13 && content.charCodeAt(e + 1) === 10 ? 2 : 1);
  }
  return { table, mdit };
}

/** `|---|:-:|`-style row: optional pipes around dash runs (with optional colons) separated by pipes. */
function isDelimiterRow(content: string, from: number, to: number): boolean {
  let i = from;
  const skipSpace = (): void => {
    while (i < to && (content.charCodeAt(i) === 32 || content.charCodeAt(i) === 9)) i++;
  };
  skipSpace();
  if (content.charCodeAt(i) === 124) i++;
  let cells = 0;
  for (;;) {
    skipSpace();
    if (content.charCodeAt(i) === 58) i++;
    let dashes = 0;
    while (i < to && content.charCodeAt(i) === 45) {
      i++;
      dashes++;
    }
    if (dashes === 0) return cells > 0 && i >= to;
    if (content.charCodeAt(i) === 58) i++;
    skipSpace();
    cells++;
    if (i >= to) return true;
    if (content.charCodeAt(i) !== 124) return false;
    i++;
    skipSpace();
    if (i >= to) return true;
  }
}

function isClosingRawTag(content: string, from: number, to: number): boolean {
  let i = from;
  let spaces = 0;
  while (i < to && content.charCodeAt(i) === 32 && spaces < 3) {
    i++;
    spaces++;
  }
  const head = content.slice(i, Math.min(to, i + 12)).toLowerCase();
  const tag = ['</script>', '</style>', '</pre>', '</textarea>'].find((t) => head.startsWith(t));
  if (!tag) return false;
  i += tag.length;
  while (i < to && (content.charCodeAt(i) === 32 || content.charCodeAt(i) === 9)) i++;
  return i >= to;
}
