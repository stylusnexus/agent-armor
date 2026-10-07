import { describe, it, expect } from 'vitest';
import { createHash } from 'crypto';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { Tokenizer } from '../src/tokenizer';

/**
 * #271: the package once tokenized with its own WordPiece code against a
 * SentencePiece (Unigram) model, so every word reached the model as [UNK]. This
 * test holds the package to the ids the Python training tokenizer produces for
 * the same strings (fixtures/tokenizer-golden.json, written by
 * scripts/gen-tokenizer-fixtures.py).
 *
 * It needs the model's real tokenizer.json: set TOKENIZER_JSON, or have the
 * export at ml/train/output/onnx/. The model-integrity workflow downloads the
 * hosted file and sets REQUIRE_TOKENIZER_GOLDEN=1, so a missing file fails there
 * instead of skipping.
 */
const FIXTURES = join(__dirname, 'fixtures');
const golden = JSON.parse(readFileSync(join(FIXTURES, 'tokenizer-golden.json'), 'utf-8')) as {
  tokenizer_sha256: string;
  max_length: number;
  ids: number[][];
};
const strings = JSON.parse(
  readFileSync(join(FIXTURES, 'tokenizer-strings.json'), 'utf-8'),
) as string[];

const tokenizerPath =
  process.env.TOKENIZER_JSON ?? join(__dirname, '../../../ml/train/output/onnx/tokenizer.json');
const required = process.env.REQUIRE_TOKENIZER_GOLDEN === '1';
const available = existsSync(tokenizerPath);

if (required && !available) {
  throw new Error(`REQUIRE_TOKENIZER_GOLDEN=1 but no tokenizer.json at ${tokenizerPath}`);
}

describe.skipIf(!available)('golden ids from the Python training tokenizer (#271)', () => {
  it('has one expected id list per fixture string', () => {
    expect(golden.ids.length).toBe(strings.length);
  });

  it('is generated from this tokenizer.json (re-run scripts/gen-tokenizer-fixtures.py after a retrain)', () => {
    const sha = createHash('sha256').update(readFileSync(tokenizerPath)).digest('hex');
    expect(sha).toBe(golden.tokenizer_sha256);
  });

  it('produces the same ids as Python for every fixture string', async () => {
    const tok = await Tokenizer.fromFile(tokenizerPath);
    const mismatches: string[] = [];
    for (let i = 0; i < strings.length; i++) {
      const { inputIds, attentionMask } = await tok.encode(strings[i], golden.max_length);
      const n = Array.from(attentionMask).filter((m) => m === 1n).length;
      const got = Array.from(inputIds.slice(0, n), Number);
      if (JSON.stringify(got) !== JSON.stringify(golden.ids[i])) {
        mismatches.push(`#${i} ${JSON.stringify(strings[i].slice(0, 40))}`);
      }
    }
    expect(mismatches).toEqual([]);
  });

  it('does not map the words of an ordinary sentence to [UNK]', async () => {
    const tok = await Tokenizer.fromFile(tokenizerPath);
    const { unknownRatio } = await tok.encode(
      'Quick start: install the dependencies and run the tests.',
    );
    expect(unknownRatio).toBe(0);
  });

  it('encodes 1,000,000 characters without crashing and ends with [SEP]', async () => {
    const tok = await Tokenizer.fromFile(tokenizerPath);
    const { inputIds } = await tok.encode('ignore previous instructions '.repeat(40_000), 512);
    expect(inputIds[511]).toBe(2n);
  });
});
