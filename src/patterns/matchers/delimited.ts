import type { MatcherHit, PatternMatcher } from './types';
import { isWhitespace, literalFinder, regexFinder } from './scan-helpers';

/**
 * Exact, linear-time replacements for shipped regexes of the shape
 * `opener [^X]* keyword [^X]* X` (#175), where X is a closing character and
 * the keyword has to sit before the first X. The engine's backtracking reduces
 * to: find the first X after the opener, check that a keyword starts before
 * it. Both lookups are memoized (see `scan-helpers`), so a run of openers that
 * all fail does not rescan to the same far X.
 */

const MD_COMMENT_KEYWORD =
  /INSTRUCTION|SYSTEM|OVERRIDE|ignore|disregard|read\s+(?:the|all)|send\s+(?:the|all)|forward|exfiltrat|encode|extract/gi;
const MD_IMAGE_KEYWORD =
  /(?:data|token|secret|key|context|conversation|history|session|password|credential|api[_-]?key|env)\b/gi;
const BOT_KEYWORD = /isBot|is_bot|isRobot|isCrawler|isAgent|isAutomated/gi;

/** `\[//\]:\s*#\s*\([^)]*(?:kw)[^)]*\)`: from the `(`, a keyword before the first `)`. */
export const MARKDOWN_COMMENT_MATCHER: PatternMatcher = {
  regex: String.raw`\[//\]:\s*#\s*\([^)]*(?:INSTRUCTION|SYSTEM|OVERRIDE|ignore|disregard|read\s+(?:the|all)|send\s+(?:the|all)|forward|exfiltrat|encode|extract)[^)]*\)`,
  flags: 'gi',
  extractGroup: 0,
  fuzzAtoms: [
    '[//]:',
    '[//]: #',
    ' # ',
    '(',
    ')',
    'ignore',
    'IGNORE',
    'SYSTEM',
    'read the',
    'read   all',
    'send  the',
    'forward',
    'exfiltrat',
    'encode',
    'x',
    ' ',
    '\n',
    '[//]',
  ],
  match(content) {
    const hits: MatcherHit[] = [];
    const header = /\[\/\/\]:\s*#\s*\(/g;
    const nextClose = literalFinder(content, ')');
    const nextKeyword = regexFinder(content, new RegExp(MD_COMMENT_KEYWORD.source, 'gi'));
    let pos = 0;
    for (;;) {
      header.lastIndex = pos;
      const m = header.exec(content);
      if (!m) break;
      const open = m.index + m[0].length - 1;
      const close = nextClose(open + 1);
      if (close < 0) break;
      const keyword = nextKeyword(open + 1);
      if (keyword < 0) break;
      if (keyword < close) {
        hits.push({ index: m.index, text: content.slice(m.index, close + 1) });
        pos = close + 1;
      } else {
        pos = close; // every opener before this `)` fails the same way
      }
    }
    return hits;
  },
};

/**
 * `!\[[^\]]*\]\(https?:\/\/[^)]*(?:kw)\b[^)]*\)`: the alt text ends at the first
 * `]`, which must be followed by `(http(s)://`; then a keyword before the first
 * `)`. Every `![` before the same `]` shares the outcome.
 */
export const MARKDOWN_IMAGE_MATCHER: PatternMatcher = {
  regex: String.raw`!\[[^\]]*\]\(https?:\/\/[^)]*(?:data|token|secret|key|context|conversation|history|session|password|credential|api[_-]?key|env)\b[^)]*\)`,
  flags: 'gi',
  extractGroup: 0,
  fuzzAtoms: [
    '![',
    '](',
    'http://',
    'https://',
    'HTTP://',
    ')',
    ']',
    '[',
    '!',
    'data',
    'token',
    'secret',
    'key',
    'api_key',
    'api-key',
    'apikey',
    'env',
    'environment',
    'session',
    'x',
    '/',
    '?',
    '=',
    ' ',
    '\n',
  ],
  match(content) {
    const hits: MatcherHit[] = [];
    const start = /!\[/g;
    const scheme = /\]\(https?:\/\//iy;
    const nextBracket = literalFinder(content, ']');
    const nextClose = literalFinder(content, ')');
    const nextKeyword = regexFinder(content, new RegExp(MD_IMAGE_KEYWORD.source, 'gi'));
    let pos = 0;
    for (;;) {
      start.lastIndex = pos;
      const m = start.exec(content);
      if (!m) break;
      const bracket = nextBracket(m.index + 2);
      if (bracket < 0) break;
      scheme.lastIndex = bracket;
      const sm = scheme.exec(content);
      if (!sm) {
        pos = bracket;
        continue;
      }
      const urlStart = bracket + sm[0].length;
      const close = nextClose(urlStart);
      if (close < 0) break;
      const keyword = nextKeyword(urlStart);
      if (keyword < 0) break;
      if (keyword < close) {
        hits.push({ index: m.index, text: content.slice(m.index, close + 1) });
        pos = close + 1;
      } else {
        pos = bracket;
      }
    }
    return hits;
  },
};

/**
 * `if\s*\([^)]*(?:kw)[^)]*\)\s*\{[\s\S]{0,500}\}`: a keyword before the first
 * `)`, then `{`, then the LAST `}` among the next 501 characters.
 */
export const CONDITIONAL_BOT_MATCHER: PatternMatcher = {
  regex: String.raw`if\s*\([^)]*(?:isBot|is_bot|isRobot|isCrawler|isAgent|isAutomated)[^)]*\)\s*\{[\s\S]{0,500}\}`,
  flags: 'gi',
  extractGroup: 0,
  fuzzAtoms: [
    'if',
    'IF',
    'if (',
    'if(',
    'isBot',
    'is_bot',
    'isRobot',
    'isCrawler',
    'isAgent',
    'isAutomated',
    ')',
    ' ',
    '{',
    '}',
    '\n',
    '(',
    'x',
    ' && ',
    'show()',
    ';',
  ],
  match(content) {
    const hits: MatcherHit[] = [];
    const n = content.length;
    const start = /if\s*\(/gi;
    const brace = /\s*\{/y;
    const nextClose = literalFinder(content, ')');
    const nextKeyword = regexFinder(content, new RegExp(BOT_KEYWORD.source, 'gi'));
    let pos = 0;
    for (;;) {
      start.lastIndex = pos;
      const m = start.exec(content);
      if (!m) break;
      const open = m.index + m[0].length - 1;
      const close = nextClose(open + 1);
      if (close < 0) break;
      const keyword = nextKeyword(open + 1);
      if (keyword < 0) break;
      if (keyword >= close) {
        pos = close;
        continue;
      }
      brace.lastIndex = close + 1;
      const bm = brace.exec(content);
      if (!bm) {
        pos = close;
        continue;
      }
      const braceAt = close + 1 + bm[0].length; // `close` is the `)`; this is the index just past `{`
      let last = -1;
      for (let k = Math.min(braceAt + 500, n - 1); k >= braceAt; k--) {
        if (content.charCodeAt(k) === 125) {
          last = k;
          break;
        }
      }
      if (last < 0) {
        pos = close;
        continue;
      }
      hits.push({ index: m.index, text: content.slice(m.index, last + 1) });
      pos = last + 1;
    }
    return hits;
  },
};

const BRACKET_FIRST = String.raw`AI|SYSTEM|ASSISTANT|INSTRUCTION|MEMORY|ADMIN`;
const BRACKET_NEXT = String.raw`SYSTEM|OVERRIDE|INSTRUCTION|COMMAND|UPDATE|NOTE|MEMORY`;

/**
 * `\[(?:A)(?:[\s_](?:B)){1,2}[:\s]([^\]]{20,})\]`: the match always ends at the
 * first `]` after the head. The engine prefers two repeated words, and falls
 * back to one if fewer than 20 characters would remain before the `]`.
 */
export const BRACKET_COMMAND_MATCHER: PatternMatcher = {
  regex: String.raw`\[(?:AI|SYSTEM|ASSISTANT|INSTRUCTION|MEMORY|ADMIN)(?:[\s_](?:SYSTEM|OVERRIDE|INSTRUCTION|COMMAND|UPDATE|NOTE|MEMORY)){1,2}[:\s]([^\]]{20,})\]`,
  flags: 'gi',
  extractGroup: 0,
  fuzzAtoms: [
    '[',
    ']',
    '[AI',
    '[SYSTEM',
    '[ASSISTANT',
    '[ai ',
    '[ADMIN_',
    ' SYSTEM',
    ' NOTE',
    '_NOTE',
    ' memory',
    ' UPDATE',
    ' COMMAND',
    ': ',
    ':',
    ' ',
    '_',
    'from now on recommend acme',
    'xxxxxxxxxxxxxxxxxxxxxxxx',
    'short',
    '\n',
  ],
  match(content) {
    const hits: MatcherHit[] = [];
    const head = new RegExp(String.raw`\[(?:${BRACKET_FIRST})[\s_](?:${BRACKET_NEXT})`, 'gi');
    const secondWord = new RegExp(String.raw`[\s_](?:${BRACKET_NEXT})[:\s]`, 'iy');
    const nextBracket = literalFinder(content, ']');
    let pos = 0;
    for (;;) {
      head.lastIndex = pos;
      const m = head.exec(content);
      if (!m) break;
      const afterSecond = m.index + m[0].length;
      const close = nextBracket(afterSecond);
      if (close < 0) break;
      let bodyStart = -1;
      secondWord.lastIndex = afterSecond;
      const two = secondWord.exec(content);
      if (two && close - (afterSecond + two[0].length) >= 20) {
        bodyStart = afterSecond + two[0].length;
      } else if (afterSecond < content.length) {
        const c = content.charCodeAt(afterSecond);
        if ((c === 58 || isWhitespace(c)) && close - (afterSecond + 1) >= 20)
          bodyStart = afterSecond + 1;
      }
      if (bodyStart < 0) {
        pos = m.index + 1;
        continue;
      }
      hits.push({ index: m.index, text: content.slice(m.index, close + 1) });
      pos = close + 1;
    }
    return hits;
  },
};
