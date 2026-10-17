import type { MatcherHit, PatternMatcher } from './types';

/**
 * `jb-agent-directed-command`, copied from the shipped entry. The equivalence
 * test checks it still equals `default-patterns.ts`.
 */
const REGEX =
  '(?:(?:note|message|instructions?)\\s+(?:to|for)\\s+(?:the\\s+)?(?:ai|agent|assistant|model|llm)\\b|(?:^|[.:!?>\\n\\-*+\\u2022]\\s*|[\\s=](?=[\\"\'\\u201C\\u2018`\\u00AB\\u2039\\u201E\\u201A*_]))[*_\\"\'\\u201C\\u2018`\\u00AB\\u2039\\u201E\\u201A]{0,3}(?:(?:dear|hey|hi|hello|thanks)(?:\\s+there)?[\\s,]+)?(?:ai[\\s\\-\\u2010-\\u2015]+)?(?:assistants?|agents?|claude(?:\\s+code)?|chatgpt|gemini(?:\\s+cli)?|(?:github\\s+)?copilot)[*_\\"\'\\u201D\\u2019\\u00BB\\u203A`]{0,3}\\s*[,:]|as\\s+(?:the|an?)\\s+(?:ai|agent|assistant|llm)\\b[^.\\n]{0,40},|when\\s+you\\s+(?:read|see|process|parse)\\s+(?:this|the\\s+(?:above|following)))[\\s\\S]{0,200}?\\b(?:run|execute|exec|invoke|launch|pipe)\\b[\\s\\S]{0,60}?(?:\\b(?:curl|wget|bash|sudo|powershell|eval|nc|netcat)\\b|\\bsh\\b|\\brm\\s+-|chmod\\s+\\+x|(?:installer|script|payload|binary)\\s+(?:at|from)\\s+https?:\\/\\/)';

/*
 * The regex is PREFIX W1 VERB W2 TARGET, where W1 = [\s\S]{0,200}? and
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
 *
 * The addressed branch, OPENER MARKS{0,3} (GREETING(\s+there)?[\s,]+)?
 * (ai[\s\-‐-―]+)? NAME CLOSERS{0,3} \s* [,:], also has one way to match per
 * opener. No piece after MARKS can start with a mark, so backing off
 * MARKS{0,3} leaves a mark where a greeting, `ai` or a name must start: the
 * run of marks is taken whole, and a run longer than 3 fails. Likewise
 * CLOSERS{0,3} is taken whole (neither \s nor [,:] is a closer). Every \s* /
 * \s+ / [\s,]+ / [\s\-‐-―]+ is taken whole for the same reason (backing off
 * leaves whitespace, `,` or a dash where a word or [,:] must start).
 * Greetings start with d/h/t and none is another's prefix, `ai` is no name's
 * prefix, and names start with a/c/g, so the optional greeting and `ai` are
 * each present exactly when their text is there.
 *
 * Optional tails are taken whenever their text is there, because dropping
 * one always fails: without ` there`, [\s,]+ stops at the `t` of `there`
 * (no `ai` or name starts with t); without ` code` / ` cli`, the name is
 * followed by whitespace then a letter, where only CLOSERS \s* [,:] may
 * follow; without `github `, the name must start at the `g` of `github`.
 * Backing off `assistants` to `assistant` (or `agents` to `agent`) leaves an
 * `s` where a closer, \s or [,:] must follow, so the longer word wins too.
 */

const VERBS = ['run', 'execute', 'exec', 'invoke', 'launch', 'pipe'];
const GREETINGS = ['dear', 'hey', 'hi', 'hello', 'thanks'];
const NAMES = [
  'assistants',
  'assistant',
  'agents',
  'agent',
  'claude',
  'chatgpt',
  'gemini',
  'copilot',
  'github',
];
/** Optional words after a name: `claude code`, `gemini cli`, `github copilot` (required for github). */
const NAME_TAILS: Record<string, string> = { claude: 'code', gemini: 'cli', github: 'copilot' };
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

/** [*_"'“‘`«‹„‚]: the opening marks, also the lookahead set after [\s=]. */
function isMark(c: number): boolean {
  return (
    c === 0x2a ||
    c === 0x5f ||
    c === 0x22 ||
    c === 0x27 ||
    c === 0x201c ||
    c === 0x2018 ||
    c === 0x60 ||
    c === 0xab ||
    c === 0x2039 ||
    c === 0x201e ||
    c === 0x201a
  );
}

/** [*_"'”’»›`]: the closing marks after the name. */
function isCloser(c: number): boolean {
  return (
    c === 0x2a ||
    c === 0x5f ||
    c === 0x22 ||
    c === 0x27 ||
    c === 0x201d ||
    c === 0x2019 ||
    c === 0xbb ||
    c === 0x203a ||
    c === 0x60
  );
}

/** [.:!?>\n\-*+•]: the punctuation that may open the addressed branch. */
function isOpener(c: number): boolean {
  return (
    c === 0x2e ||
    c === 0x3a ||
    c === 0x21 ||
    c === 0x3f ||
    c === 0x3e ||
    c === 0x0a ||
    c === 0x2d ||
    c === 0x2a ||
    c === 0x2b ||
    c === 0x2022
  );
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

  // dashEnd[i]: first index at or after i outside [\s\-‐-―].
  // commaEnd[i]: first index at or after i outside [\s,].
  const dashEnd = new Int32Array(n + 1);
  const commaEnd = new Int32Array(n + 1);
  dashEnd[n] = n;
  commaEnd[n] = n;
  for (let i = n - 1; i >= 0; i--) {
    const c = s.charCodeAt(i);
    const sp = isSpace(c);
    dashEnd[i] = sp || c === 0x2d || (c >= 0x2010 && c <= 0x2015) ? dashEnd[i + 1] : i;
    commaEnd[i] = sp || c === 0x2c ? commaEnd[i + 1] : i;
  }

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
    return q - p <= 200 ? tailEnd[q] : -1;
  };

  // `\s+word` at i: the index after `word`, or -1.
  const spacedWord = (i: number, w: string): number =>
    space(i) && s.startsWith(w, wsEnd[i]) ? wsEnd[i] + w.length : -1;

  // MARKS{0,3}(?:GREETING(?:\s+there)?[\s,]+)?(?:ai[\s\-‐-―]+)?NAME
  // CLOSERS{0,3}\s*[,:] from x (see the note at the top: one way to match),
  // or -1.
  const addressedEnd = (x: number): number => {
    let k = 0;
    while (k < 4 && x + k < n && isMark(s.charCodeAt(x + k))) k++;
    if (k > 3) return -1;
    x += k;
    for (const g of GREETINGS) {
      if (s.startsWith(g, x)) {
        let y = x + g.length;
        const t = spacedWord(y, 'there');
        if (t >= 0) y = t;
        if (commaEnd[y] > y) x = commaEnd[y];
        break;
      }
    }
    if (s.startsWith('ai', x) && dashEnd[x + 2] > x + 2) x = dashEnd[x + 2];
    const name = NAMES.find((w) => s.startsWith(w, x));
    if (name === undefined) return -1;
    x += name.length;
    const tail = NAME_TAILS[name];
    if (tail !== undefined) {
      const t = spacedWord(x, tail);
      if (t >= 0) x = t;
      else if (name === 'github') return -1;
    }
    k = 0;
    while (k < 4 && x + k < n && isCloser(s.charCodeAt(x + k))) k++;
    if (k > 3) return -1;
    x = wsEnd[x + k];
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

    // (?:^|[.:!>\n\-*+•]\s*|[\s=](?=MARK))MARKS{0,3}(?:GREETING\s+)?(?:ai[\s-]+)?NAME CLOSERS{0,3}\s*[,:]
    if (at === 0) {
      p = addressedEnd(0);
      if (p >= 0 && (e = finish(p)) >= 0) return e;
    }
    if (isOpener(c)) {
      p = addressedEnd(wsEnd[at + 1]);
      if (p >= 0 && (e = finish(p)) >= 0) return e;
    }
    if ((isSpace(c) || c === 0x3d) && at + 1 < n && isMark(s.charCodeAt(at + 1))) {
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
      'note to the ai',
      'note for agent',
      'message for agent',
      'message to the assistant',
      'instructions to the model',
      'instruction for llm',
      'instructions  for the  ai',
      'notes to the ai',
      'as an AI assistant, ',
      'as the agent, ',
      'as a llm',
      'as an ai',
      ',',
      ', ',
      'as the assistant here, then',
      'when you read this',
      'when you see the above',
      'when you parse the following',
      'when you process thi',
      'assistant,',
      'assistant :',
      'agent:',
      'AI assistant:',
      'ai  agent,',
      'ai',
      'Assistant',
      'agents:',
      '. ',
      ':\n\n',
      '!',
      '>',
      '\n\n\n',
      '   ',
      '=',
      '="',
      ' "',
      '"agent:',
      '“assistant,',
      '‘agent:',
      '`agent,',
      "'",
      'assistants',
      'Assistants:',
      'agents,',
      'claude',
      'Claude:',
      'chatgpt,',
      'ChatGPT',
      'gemini:',
      'copilot,',
      'copilo',
      'claudes:',
      'assistantss,',
      'agentx:',
      'dear ',
      'Hey ',
      'hi ',
      'hello  ',
      'hey',
      'his ',
      'dearest ',
      'hiclaude:',
      'ai-',
      'AI - ',
      'ai -- agent:',
      'ai-assistant,',
      'ai -\n',
      'aI\t-',
      '- ',
      '* ',
      '+ ',
      '• ',
      '-',
      '*',
      '+',
      '•',
      '**',
      '***',
      '****',
      '_',
      '__',
      '«',
      '»',
      '‹',
      '›',
      '„',
      '‚',
      '“',
      '”',
      '‘',
      '’',
      '**AI assistant**:',
      '- **Claude**,',
      '• hey agents:',
      '_assistant_ ,',
      '«agent»:',
      '„ChatGPT“:',
      ' *',
      ' _',
      '=*',
      '="*',
      '*"«',
      '’’’',
      '”*»›',
      '"""',
      '````',
      'run',
      'Run ',
      'execute',
      'exec',
      'executes',
      'invoke',
      'launch',
      'rerun',
      '_run',
      'pipe',
      'Pipe ',
      'pipes',
      'pipe to',
      'curl',
      'wget',
      'bash',
      'sudo',
      'powershell',
      'eval',
      'nc',
      'netcat',
      'sh',
      'shell',
      'ssh',
      'rm -',
      'rm  -rf',
      'rm',
      'chmod +x',
      'chmod  +X',
      'chmod',
      'installer at https://',
      'script from http://',
      'payload at  HTTPS://',
      'binary from httpx',
      'installer at',
      ' x.sh',
      'the',
      'this',
      ' ',
      ' ',
      ' ',
      '　',
      'ſh',
      'K',
      'İ',
      '.',
      '\n',
      '?',
      '? ',
      '?\n',
      ',,',
      ', ,',
      'thanks',
      'Thanks, ',
      'thanks,,',
      'thanks there',
      'thank ',
      'hey ,',
      'hey,',
      'hi there, ',
      'Hey There ',
      ' there',
      'there,',
      'therefore',
      'hello  there,,',
      'thanksgiving ',
      'ai‐',
      'ai‑',
      'AI‒',
      'ai–',
      'ai—',
      'ai―',
      '‐',
      '―',
      '—',
      'ai ‐ –',
      'claude code',
      'Claude Code:',
      'claude  code,',
      'claude codex',
      'claude\ncode',
      'claude cod',
      ' code',
      'code',
      'gemini cli',
      'Gemini CLI:',
      'gemini  cli',
      'gemini clip',
      ' cli',
      'cli',
      'github copilot',
      'GitHub Copilot:',
      'github  copilot',
      'github',
      'github ',
      'githubcopilot',
      ' copilot',
      'hey there, claude code,',
      '? thanks, ai — github copilot:',
      '- hi,gemini cli:',
    ],
  },
];
