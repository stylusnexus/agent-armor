import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { Tokenizer } from '../src/tokenizer';

// Tokenizer's constructor is `private` at the TS level only (plain fields,
// not `#private`), so tests build instances directly against a controlled
// vocab instead of round-tripping through fromFile()'s JSON parsing for
// every case — that keeps the WordPiece algorithm tests independent of file
// I/O, while a dedicated `fromFile` section below exercises the real loader.
const CLS = 101;
const SEP = 102;
const PAD = 103;
const UNK = 0;

function makeTokenizer(vocabEntries: Array<[string, number]>): Tokenizer {
  const vocab = new Map(vocabEntries);
  const specialTokens = { '[UNK]': UNK, '[CLS]': CLS, '[SEP]': SEP, '[PAD]': PAD };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return new (Tokenizer as any)(vocab, specialTokens) as Tokenizer;
}

const BASE_VOCAB: Array<[string, number]> = [
  ['hello', 10],
  ['world', 11],
  ['walk', 12],
  ['##ing', 13],
  ['##ed', 14],
  ['wa', 20], // shorter competing prefix of "walk" — tests greedy longest-match
];

describe('Tokenizer.encode — WordPiece pipeline', () => {
  const tok = makeTokenizer(BASE_VOCAB);

  it('lowercases and splits on whitespace before matching whole words in vocab', () => {
    const { inputIds } = tok.encode('Hello World', 10);
    expect(inputIds[0]).toBe(BigInt(CLS));
    expect(inputIds[1]).toBe(10n); // hello
    expect(inputIds[2]).toBe(11n); // world
    expect(inputIds[3]).toBe(BigInt(SEP));
  });

  it('splits an out-of-vocab word into WordPiece subwords via greedy longest-prefix match', () => {
    const { inputIds } = tok.encode('walking', 10);
    expect(inputIds[1]).toBe(12n); // "walk" (longest prefix), not "wa"
    expect(inputIds[2]).toBe(13n); // "##ing" continuation
    expect(inputIds[3]).toBe(BigInt(SEP));
  });

  it('falls back to [UNK] when no prefix of the word matches the vocab at all', () => {
    const { inputIds } = tok.encode('zzzznotinvocab', 10);
    expect(inputIds[1]).toBe(BigInt(UNK));
    expect(inputIds[2]).toBe(BigInt(SEP));
  });

  it('wraps content with [CLS] ... [SEP]', () => {
    const { inputIds } = tok.encode('hello', 8);
    expect(inputIds[0]).toBe(BigInt(CLS));
    expect(inputIds[2]).toBe(BigInt(SEP));
  });
});

describe('Tokenizer.encode — padding', () => {
  const tok = makeTokenizer(BASE_VOCAB);

  it('pads short input to maxLength with [PAD] and zeroes the attention mask on padded positions', () => {
    const { inputIds, attentionMask } = tok.encode('hello', 8);
    expect(inputIds.length).toBe(8);
    // [CLS, hello, SEP] occupy 0-2; the rest is padding.
    expect(attentionMask[0]).toBe(1n);
    expect(attentionMask[1]).toBe(1n);
    expect(attentionMask[2]).toBe(1n);
    for (let i = 3; i < 8; i++) {
      expect(inputIds[i]).toBe(BigInt(PAD));
      expect(attentionMask[i]).toBe(0n);
    }
  });

  it('defaults maxLength to 512 when not specified', () => {
    const { inputIds, attentionMask } = tok.encode('hello');
    expect(inputIds.length).toBe(512);
    expect(attentionMask.length).toBe(512);
  });
});

describe('Tokenizer.encode — truncation', () => {
  const tok = makeTokenizer(BASE_VOCAB);

  it('truncates content longer than maxLength and forces the last position to [SEP]', () => {
    // 20 unknown words -> 1 UNK token each -> CLS + 20 + SEP = 22 tokens, well over maxLength.
    const words = Array.from({ length: 20 }, (_, i) => `unknownword${i}`);
    const { inputIds, attentionMask } = tok.encode(words.join(' '), 10);

    expect(inputIds.length).toBe(10);
    expect(inputIds[9]).toBe(BigInt(SEP));
    // Truncated output is fully packed — no padding positions remain.
    for (const bit of attentionMask) {
      expect(bit).toBe(1n);
    }
  });
});

describe('Tokenizer.encode — output tensor type', () => {
  const tok = makeTokenizer(BASE_VOCAB);

  it('returns BigInt64Array for both input_ids and attention_mask (ONNX int64 requirement)', () => {
    const { inputIds, attentionMask } = tok.encode('hello world', 8);
    expect(inputIds).toBeInstanceOf(BigInt64Array);
    expect(attentionMask).toBeInstanceOf(BigInt64Array);
    expect(typeof inputIds[0]).toBe('bigint');
    expect(typeof attentionMask[0]).toBe('bigint');
  });
});

describe('Tokenizer.encode — empty / whitespace-only input', () => {
  const tok = makeTokenizer(BASE_VOCAB);

  it('does not crash on an empty string, producing [CLS] immediately followed by [SEP]', () => {
    const { inputIds, attentionMask } = tok.encode('', 6);
    expect(inputIds[0]).toBe(BigInt(CLS));
    expect(inputIds[1]).toBe(BigInt(SEP));
    expect(attentionMask[0]).toBe(1n);
    expect(attentionMask[1]).toBe(1n);
    expect(attentionMask[2]).toBe(0n);
  });

  it('does not crash on whitespace-only input', () => {
    const { inputIds, attentionMask } = tok.encode('   \t\n  ', 6);
    expect(inputIds[0]).toBe(BigInt(CLS));
    expect(inputIds[1]).toBe(BigInt(SEP));
    expect(attentionMask[2]).toBe(0n);
  });
});

describe('Tokenizer.fromFile', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'agentarmor-tokenizer-test-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('loads vocab and resolves special-token ids from added_tokens', async () => {
    const path = join(tempDir, 'tokenizer.json');
    await writeFile(
      path,
      JSON.stringify({
        model: { vocab: { '[UNK]': 0, '[CLS]': 1, '[SEP]': 2, hello: 3, world: 4 } },
        added_tokens: [
          { id: 1, content: '[CLS]' },
          { id: 2, content: '[SEP]' },
          { id: 0, content: '[UNK]' },
        ],
      }),
    );

    const tok = await Tokenizer.fromFile(path);
    const { inputIds } = tok.encode('hello world', 8);
    expect(inputIds[0]).toBe(1n); // [CLS] id from added_tokens
    expect(inputIds[1]).toBe(3n); // hello
    expect(inputIds[2]).toBe(4n); // world
    expect(inputIds[3]).toBe(2n); // [SEP] id from added_tokens
  });

  // BUG FINDING (not fixed — see final report): fromFile() does
  // `for (const token of json.added_tokens)` with no `?? []` fallback. A
  // tokenizer.json missing the `added_tokens` key throws an unguarded
  // TypeError ("undefined is not iterable") instead of a typed
  // AgentArmorModelError, which is what every other load-failure path in
  // this package raises. src/tokenizer.ts:59.
  it('throws an unguarded TypeError when added_tokens is missing from the file', async () => {
    const path = join(tempDir, 'tokenizer.json');
    await writeFile(path, JSON.stringify({ model: { vocab: { hello: 3 } } }));

    await expect(Tokenizer.fromFile(path)).rejects.toThrow();
  });
});
