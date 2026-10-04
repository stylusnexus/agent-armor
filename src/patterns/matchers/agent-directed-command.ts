import type { MatcherHit, PatternMatcher } from './types';

/**
 * `jb-agent-directed-command`, copied from the shipped entry. The equivalence
 * test checks it still equals `default-patterns.ts`.
 */
const REGEX =
  '(?:(?:note|message|instructions?)\\s+(?:to|for)\\s+(?:the\\s+)?(?:ai|agent|assistant|model|llm)\\b|(?:^|[.:!>\\n]\\s*|[\\s=](?=["\'\\u201C\\u2018`]))["\'\\u201C\\u2018`]?(?:ai\\s+)?(?:assistant|agent)\\s*[,:]|as\\s+(?:the|an?)\\s+(?:ai|agent|assistant|llm)\\b[^.\\n]{0,40},|when\\s+you\\s+(?:read|see|process|parse)\\s+(?:this|the\\s+(?:above|following)))[\\s\\S]{0,80}?\\b(?:run|execute|exec|invoke|launch)\\b[\\s\\S]{0,60}?(?:\\b(?:curl|wget|bash|sudo|powershell|eval|nc|netcat)\\b|\\bsh\\b|\\brm\\s+-|chmod\\s+\\+x|(?:installer|script|payload|binary)\\s+(?:at|from)\\s+https?:\\/\\/)';

/*
 * The regex is PREFIX W1 VERB W2 TARGET, where W1 = [\s\S]{0,80}? and
 * W2 = [\s\S]{0,60}?. Everything after the prefix depends only on where the
 * prefix ends, so "does the tail match from p, and where does it end" is
 * precomputed for every p in one right-to-left pass. Each prefix branch then
 * has at most one way to match (apart from the comma choice in the `as the
 * ai ..., ` branch), and every \s+ / \s* jumps to the end of its whitespace
 * run through a lookup table. That keeps the whole scan linear.
 *
 * Without the `u` flag, `i` folds ASCII letters only (non-ASCII never folds
 * to ASCII) and \w / \b are ASCII-only, so an ASCII-only lowercase copy of
 * the input is an exact stand-in for case-insensitive matching.
 */

const VERBS = ['run', 'execute', 'exec', 'invoke', 'launch'];
const TARGET_WORDS = ['curl', 'wget', 'bash', 'sudo', 'powershell', 'eval', 'nc', 'netcat'];
const PAYLOAD_NOUNS = ['installer', 'script', 'payload', 'binary'];
const A_OPENERS = ['note', 'message', 'instructions', 'instruction'];
const A_ADDRESSEES = ['ai', 'agent', 'assistant', 'model', 'llm'];
const C_ADDRESSEES = ['ai', 'agent', 'assistant', 'llm'];
const D_VERBS = ['read', 'see', 'process', 'parse'];

/** JavaScript's \s. */
function isSpace(c: number): boolean {
  return (
    (c >= 0x09 && c <= 0x0d) ||
    c === 0x20 ||
    c === 0xa0 ||
    c === 0x1680 ||
    (c >= 0x2000 && c <= 0x200a) ||
    c === 0x2028 ||
    c === 0x2029 ||
    c === 0x202f ||
    c === 0x205f ||
    c === 0x3000 ||
    c === 0xfeff
  );
}

/** ["'“‘`] */
function isQuote(c: number): boolean {
  return c === 0x22 || c === 0x27 || c === 0x201c || c === 0x2018 || c === 0x60;
}

function match(content: string): MatcherHit[] {
  const n = content.length;
  const s = content.replace(/[A-Z]+/g, (m) => m.toLowerCase());

  const word = (i: number): boolean => {
    if (i < 0 || i >= n) return false;
    const c = s.charCodeAt(i);
    return (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c === 0x5f;
  };
  const space = (i: number): boolean => i < n && isSpace(s.charCodeAt(i));

  // wsEnd[i]: first non-whitespace index at or after i.
  const wsEnd = new Int32Array(n + 1);
  wsEnd[n] = n;
  for (let i = n - 1; i >= 0; i--) wsEnd[i] = isSpace(s.charCodeAt(i)) ? wsEnd[i + 1] : i;

  // A word from `list` at i, starting and ending on a \b; returns its end or -1.
  const boundedWord = (i: number, list: string[]): number => {
    if (word(i - 1)) return -1;
    for (const w of list) {
      if (s.startsWith(w, i) && !word(i + w.length)) return i + w.length;
    }
    return -1;
  };

  // End of TARGET starting exactly at r, or -1.
  const targetEnd = (r: number): number => {
    let e = boundedWord(r, TARGET_WORDS);
    if (e >= 0) return e;
    e = boundedWord(r, ['sh']);
    if (e >= 0) return e;
    if (!word(r - 1) && s.startsWith('rm', r) && space(r + 2)) {
      const x = wsEnd[r + 2];
      if (s.charCodeAt(x) === 0x2d) return x + 1;
    }
    if (s.startsWith('chmod', r) && space(r + 5)) {
      const x = wsEnd[r + 5];
      if (s.startsWith('+x', x)) return x + 2;
    }
    for (const noun of PAYLOAD_NOUNS) {
      if (!s.startsWith(noun, r)) continue;
      let x = r + noun.length;
      if (!space(x)) return -1;
      x = wsEnd[x];
      if (s.startsWith('at', x)) x += 2;
      else if (s.startsWith('from', x)) x += 4;
      else return -1;
      if (!space(x)) return -1;
      x = wsEnd[x];
      if (s.startsWith('https://', x)) return x + 8;
      if (s.startsWith('http://', x)) return x + 7;
      return -1;
    }
    return -1;
  };

  // tailEnd[q]: match end when VERB starts at q and the tail succeeds, else -1.
  // nextTail[p]: first q >= p with tailEnd[q] >= 0; NONE when there is none.
  const NONE = 0x3fffffff;
  const tEnd = new Int32Array(n + 1);
  const nextT = new Int32Array(n + 2);
  const nextTail = new Int32Array(n + 2);
  const tailEnd = new Int32Array(n + 1);
  nextT[n + 1] = NONE;
  nextTail[n + 1] = NONE;
  for (let i = n; i >= 0; i--) {
    tEnd[i] = i < n ? targetEnd(i) : -1;
    nextT[i] = tEnd[i] >= 0 ? i : nextT[i + 1];
  }
  for (let q = n; q >= 0; q--) {
    tailEnd[q] = -1;
    const v = boundedWord(q, VERBS);
    if (v >= 0) {
      const r = nextT[v];
      if (r - v <= 60) tailEnd[q] = tEnd[r];
    }
    nextTail[q] = tailEnd[q] >= 0 ? q : nextTail[q + 1];
  }

  // Match end when the prefix ends at p, or -1.
  const finish = (p: number): number => {
    const q = nextTail[p];
    return q - p <= 80 ? tailEnd[q] : -1;
  };

  // `(?:ai\s+)?(?:assistant|agent)\s*[,:]` after an optional quote, from x.
  const addressedEnd = (x: number): number => {
    if (isQuote(s.charCodeAt(x))) x++;
    if (s.startsWith('ai', x) && space(x + 2)) x = wsEnd[x + 2];
    if (s.startsWith('assistant', x)) x += 9;
    else if (s.startsWith('agent', x)) x += 5;
    else return -1;
    x = wsEnd[x];
    const c = s.charCodeAt(x);
    return c === 0x2c || c === 0x3a ? x + 1 : -1;
  };

  // The whole match starting at `at` (prefix branches in regex order), or -1.
  const matchAt = (at: number): number => {
    const c = s.charCodeAt(at);
    let p: number;
    let e: number;

    // (?:note|message|instructions?)\s+(?:to|for)\s+(?:the\s+)?(?:ai|agent|assistant|model|llm)\b
    for (const opener of A_OPENERS) {
      if (!s.startsWith(opener, at)) continue;
      p = at + opener.length;
      if (!space(p)) continue;
      p = wsEnd[p];
      if (s.startsWith('to', p)) p += 2;
      else if (s.startsWith('for', p)) p += 3;
      else break;
      if (!space(p)) break;
      p = wsEnd[p];
      if (s.startsWith('the', p) && space(p + 3)) p = wsEnd[p + 3];
      for (const w of A_ADDRESSEES) {
        if (s.startsWith(w, p) && !word(p + w.length)) {
          e = finish(p + w.length);
          if (e >= 0) return e;
          break;
        }
      }
      break;
    }

    // (?:^|[.:!>\n]\s*|[\s=](?=QUOTE))QUOTE?(?:ai\s+)?(?:assistant|agent)\s*[,:]
    if (at === 0) {
      p = addressedEnd(0);
      if (p >= 0 && (e = finish(p)) >= 0) return e;
    }
    if (c === 0x2e || c === 0x3a || c === 0x21 || c === 0x3e || c === 0x0a) {
      p = addressedEnd(wsEnd[at + 1]);
      if (p >= 0 && (e = finish(p)) >= 0) return e;
    }
    if ((isSpace(c) || c === 0x3d) && at + 1 < n && isQuote(s.charCodeAt(at + 1))) {
      p = addressedEnd(at + 1);
      if (p >= 0 && (e = finish(p)) >= 0) return e;
    }

    // as\s+(?:the|an?)\s+(?:ai|agent|assistant|llm)\b[^.\n]{0,40},
    if (s.startsWith('as', at) && space(at + 2)) {
      p = wsEnd[at + 2];
      if (s.startsWith('the', p)) p += 3;
      else if (s.startsWith('an', p) && space(p + 2)) p += 2;
      else if (s.startsWith('a', p)) p += 1;
      if (space(p)) {
        p = wsEnd[p];
        for (const w of C_ADDRESSEES) {
          if (!s.startsWith(w, p) || word(p + w.length)) continue;
          const from = p + w.length;
          let run = 0;
          while (run < 40 && from + run < n) {
            const d = s.charCodeAt(from + run);
            if (d === 0x2e || d === 0x0a) break;
            run++;
          }
          // Greedy {0,40}: the furthest comma first.
          for (let k = run; k >= 0; k--) {
            if (s.charCodeAt(from + k) === 0x2c && (e = finish(from + k + 1)) >= 0) return e;
          }
          break;
        }
      }
    }

    // when\s+you\s+(?:read|see|process|parse)\s+(?:this|the\s+(?:above|following))
    if (s.startsWith('when', at) && space(at + 4)) {
      p = wsEnd[at + 4];
      if (s.startsWith('you', p) && space(p + 3)) {
        p = wsEnd[p + 3];
        const verb = D_VERBS.find((v) => s.startsWith(v, p));
        if (verb && space(p + verb.length)) {
          p = wsEnd[p + verb.length];
          let end = -1;
          if (s.startsWith('this', p)) end = p + 4;
          else if (s.startsWith('the', p) && space(p + 3)) {
            const x = wsEnd[p + 3];
            if (s.startsWith('above', x)) end = x + 5;
            else if (s.startsWith('following', x)) end = x + 9;
          }
          if (end >= 0 && (e = finish(end)) >= 0) return e;
        }
      }
    }
    return -1;
  };

  const hits: MatcherHit[] = [];
  if (nextTail[0] === NONE) return hits;
  let at = 0;
  while (at < n) {
    const end = matchAt(at);
    if (end >= 0) {
      hits.push({ index: at, text: content.slice(at, end) });
      at = end;
    } else {
      at++;
    }
  }
  return hits;
}

/** Matcher for `jb-agent-directed-command` (#175). */
export const AGENT_DIRECTED_COMMAND_MATCHERS: PatternMatcher[] = [
  {
    regex: REGEX,
    flags: 'gi',
    extractGroup: 0,
    match,
    fuzzAtoms: [
      'note to the ai', 'note for agent', 'message for agent', 'message to the assistant',
      'instructions to the model', 'instruction for llm', 'instructions  for the  ai', 'notes to the ai',
      'as an AI assistant, ', 'as the agent, ', 'as a llm', 'as an ai', ',', ', ', 'as the assistant here, then',
      'when you read this', 'when you see the above', 'when you parse the following', 'when you process thi',
      'assistant,', 'assistant :', 'agent:', 'AI assistant:', 'ai  agent,', 'ai', 'Assistant', 'agents:',
      '. ', ':\n\n', '!', '>', '\n\n\n', '   ', '=', '="', ' "', '"agent:', '“assistant,', '‘agent:', '`agent,', "'",
      'run', 'Run ', 'execute', 'exec', 'executes', 'invoke', 'launch', 'rerun', '_run',
      'curl', 'wget', 'bash', 'sudo', 'powershell', 'eval', 'nc', 'netcat', 'sh', 'shell', 'ssh',
      'rm -', 'rm  -rf', 'rm', 'chmod +x', 'chmod  +X', 'chmod', 'installer at https://', 'script from http://',
      'payload at  HTTPS://', 'binary from httpx', 'installer at', ' x.sh', 'the', 'this', ' ',
      ' ', ' ', '　', 'ſh', 'K', 'İ', '.', '\n',
    ],
  },
];
