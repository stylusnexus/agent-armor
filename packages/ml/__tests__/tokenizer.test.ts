import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, writeFile, rm } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { Tokenizer } from '../src/tokenizer';
import { AgentArmorModelError } from '../src/errors';

// The tokenizer itself is the Hugging Face `tokenizers` package; these tests
// cover this wrapper (loading guards, padding, truncation, unknown ratio) on a
// tiny Unigram vocabulary. Agreement with the real model's tokenizer is checked
// by tokenizer-golden.test.ts.

const PAD = 0;
const CLS = 1;
const SEP = 2;
const UNK = 3;

const SPECIAL = [
  { id: PAD, content: '[PAD]' },
  { id: CLS, content: '[CLS]' },
  { id: SEP, content: '[SEP]' },
  { id: UNK, content: '[UNK]' },
].map((t) => ({
  ...t,
  single_word: false,
  lstrip: false,
  rstrip: false,
  normalized: false,
  special: true,
}));

/** A minimal Unigram tokenizer.json: words are "▁hello" style, CLS/SEP are added around each input. */
function tinyUnigram(): object {
  return {
    version: '1.0',
    truncation: null,
    padding: null,
    added_tokens: SPECIAL,
    normalizer: null,
    pre_tokenizer: { type: 'Metaspace', replacement: '▁', prepend_scheme: 'always', split: true },
    post_processor: {
      type: 'TemplateProcessing',
      single: [
        { SpecialToken: { id: '[CLS]', type_id: 0 } },
        { Sequence: { id: 'A', type_id: 0 } },
        { SpecialToken: { id: '[SEP]', type_id: 0 } },
      ],
      pair: [],
      special_tokens: {
        '[CLS]': { id: '[CLS]', ids: [CLS], tokens: ['[CLS]'] },
        '[SEP]': { id: '[SEP]', ids: [SEP], tokens: ['[SEP]'] },
      },
    },
    decoder: { type: 'Metaspace', replacement: '▁', prepend_scheme: 'always', split: true },
    model: {
      type: 'Unigram',
      unk_id: UNK,
      byte_fallback: false,
      vocab: [
        ['[PAD]', 0],
        ['[CLS]', 0],
        ['[SEP]', 0],
        ['[UNK]', 0],
        ['▁hello', -1],
        ['▁world', -1],
      ],
    },
  };
}

let dir: string;
async function write(name: string, body: unknown): Promise<string> {
  const path = join(dir, name);
  await writeFile(path, typeof body === 'string' ? body : JSON.stringify(body));
  return path;
}

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'agentarmor-tokenizer-test-'));
});
afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('Tokenizer.encode', () => {
  it('wraps the words in [CLS] ... [SEP] and pads to maxLength with a zero mask', async () => {
    const tok = await Tokenizer.fromFile(await write('ok.json', tinyUnigram()));
    const { inputIds, attentionMask, unknownRatio } = await tok.encode('hello world', 8);

    expect(Array.from(inputIds)).toEqual([1n, 4n, 5n, 2n, 0n, 0n, 0n, 0n]);
    expect(Array.from(attentionMask)).toEqual([1n, 1n, 1n, 1n, 0n, 0n, 0n, 0n]);
    expect(unknownRatio).toBe(0);
  });

  it('returns BigInt64Array tensors (the ONNX int64 requirement)', async () => {
    const tok = await Tokenizer.fromFile(await write('ok.json', tinyUnigram()));
    const { inputIds, attentionMask } = await tok.encode('hello', 4);
    expect(inputIds).toBeInstanceOf(BigInt64Array);
    expect(attentionMask).toBeInstanceOf(BigInt64Array);
  });

  it('defaults maxLength to 512', async () => {
    const tok = await Tokenizer.fromFile(await write('ok.json', tinyUnigram()));
    const { inputIds } = await tok.encode('hello');
    expect(inputIds.length).toBe(512);
  });

  it('cuts long input to maxLength and ends it with [SEP]', async () => {
    const tok = await Tokenizer.fromFile(await write('ok.json', tinyUnigram()));
    const { inputIds, attentionMask } = await tok.encode('hello '.repeat(50), 8);
    expect(Array.from(inputIds)).toEqual([1n, 4n, 4n, 4n, 4n, 4n, 4n, 2n]);
    expect(Array.from(attentionMask).every((m) => m === 1n)).toBe(true);
  });

  it('ignores the padding and truncation settings stored in the file', async () => {
    const json = tinyUnigram() as Record<string, unknown>;
    json.padding = {
      strategy: { Fixed: 512 },
      direction: 'Right',
      pad_to_multiple_of: null,
      pad_id: PAD,
      pad_type_id: 0,
      pad_token: '[PAD]',
    };
    json.truncation = {
      direction: 'Right',
      max_length: 3,
      strategy: 'LongestFirst',
      stride: 0,
    };
    const tok = await Tokenizer.fromFile(await write('settings.json', json));
    const { inputIds, attentionMask } = await tok.encode('hello world hello world', 8);
    expect(Array.from(attentionMask).filter((m) => m === 1n).length).toBe(6);
    expect(inputIds.length).toBe(8);
  });

  it('handles an empty string as [CLS] [SEP]', async () => {
    const tok = await Tokenizer.fromFile(await write('ok.json', tinyUnigram()));
    const { inputIds, unknownRatio } = await tok.encode('', 4);
    expect(Array.from(inputIds)).toEqual([1n, 2n, 0n, 0n]);
    expect(unknownRatio).toBe(0);
  });

  it('reports the share of unknown content tokens', async () => {
    const tok = await Tokenizer.fromFile(await write('ok.json', tinyUnigram()));
    const { unknownRatio } = await tok.encode('hello zzz', 8);
    // "▁hello" is known; "▁zzz" has no vocabulary entries, so it is one or more unknowns
    expect(unknownRatio).toBeGreaterThan(0.4);
    expect(unknownRatio).toBeLessThanOrEqual(1);
  });
});

describe('Tokenizer.fromFile', () => {
  it('raises a typed MODEL_NOT_FOUND error when the file is not valid JSON', async () => {
    const path = await write('bad.json', '{not json');
    await expect(Tokenizer.fromFile(path)).rejects.toMatchObject({
      name: 'AgentArmorModelError',
      code: 'MODEL_NOT_FOUND',
    });
  });

  it('raises MODEL_NOT_FOUND when model.type is missing', async () => {
    const path = await write('notype.json', { model: {} });
    const err = await Tokenizer.fromFile(path).catch((e) => e);
    expect(err).toBeInstanceOf(AgentArmorModelError);
    expect(err.code).toBe('MODEL_NOT_FOUND');
  });

  it('raises UNSUPPORTED_TOKENIZER for a tokenizer family without golden coverage', async () => {
    const path = await write('wordpiece.json', { model: { type: 'WordPiece', vocab: {} } });
    const err = await Tokenizer.fromFile(path).catch((e) => e);
    expect(err).toBeInstanceOf(AgentArmorModelError);
    expect(err.code).toBe('UNSUPPORTED_TOKENIZER');
    expect(err.message).toContain('WordPiece');
  });

  it('raises UNSUPPORTED_TOKENIZER when a special token is not defined', async () => {
    const json = tinyUnigram() as { added_tokens: Array<{ content: string }> };
    json.added_tokens = json.added_tokens.filter((t) => t.content !== '[SEP]');
    const err = await Tokenizer.fromFile(await write('nosep.json', json)).catch((e) => e);
    expect(err.code).toBe('UNSUPPORTED_TOKENIZER');
    expect(err.message).toContain('[SEP]');
  });
});
