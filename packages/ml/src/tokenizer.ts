import { readFile } from 'fs/promises';

/**
 * Shape of the HuggingFace tokenizer.json we care about.
 * Full spec is much larger; we only read vocab + added_tokens.
 */
interface TokenizerJson {
  model: {
    vocab: Record<string, number>;
  };
  added_tokens: Array<{
    id: number;
    content: string;
  }>;
}

const DEFAULT_SPECIAL: Record<string, number> = {
  '[UNK]': 0,
  '[CLS]': 1,
  '[SEP]': 2,
  '[PAD]': 0,
};

/**
 * Minimal WordPiece tokenizer for ONNX classification inference.
 *
 * Loads a HuggingFace `tokenizer.json` and produces `input_ids` +
 * `attention_mask` as BigInt64Arrays (ONNX Runtime requires int64 tensors).
 *
 * This intentionally covers the 90% case — full HuggingFace tokenizers
 * handle BPE, normalization, pre-tokenization, etc.
 */
export class Tokenizer {
  private readonly vocab: Map<string, number>;
  private readonly unkId: number;
  private readonly clsId: number;
  private readonly sepId: number;
  private readonly padId: number;

  private constructor(vocab: Map<string, number>, specialTokens: Record<string, number>) {
    this.vocab = vocab;
    this.unkId = specialTokens['[UNK]'] ?? DEFAULT_SPECIAL['[UNK]'];
    this.clsId = specialTokens['[CLS]'] ?? DEFAULT_SPECIAL['[CLS]'];
    this.sepId = specialTokens['[SEP]'] ?? DEFAULT_SPECIAL['[SEP]'];
    this.padId = specialTokens['[PAD]'] ?? DEFAULT_SPECIAL['[PAD]'];
  }

  /**
   * Load a tokenizer from a HuggingFace `tokenizer.json` file.
   */
  static async fromFile(path: string): Promise<Tokenizer> {
    const raw = await readFile(path, 'utf-8');
    const json: TokenizerJson = JSON.parse(raw);

    const vocab = new Map<string, number>(Object.entries(json.model.vocab));

    // Merge added_tokens into vocab so special tokens are resolvable
    const specialTokens: Record<string, number> = { ...DEFAULT_SPECIAL };
    for (const token of json.added_tokens) {
      vocab.set(token.content, token.id);
      if (token.content in DEFAULT_SPECIAL) {
        specialTokens[token.content] = token.id;
      }
    }

    return new Tokenizer(vocab, specialTokens);
  }

  /**
   * Encode text into `input_ids` and `attention_mask` BigInt64Arrays.
   *
   * Tokenization:
   *  1. Lowercase and split on whitespace
   *  2. WordPiece subword splitting for OOV words
   *  3. Wrap with [CLS] ... [SEP]
   *  4. Pad or truncate to `maxLength`
   */
  encode(
    text: string,
    maxLength: number = 512,
  ): { inputIds: BigInt64Array; attentionMask: BigInt64Array } {
    const tokens: number[] = [this.clsId];

    const words = text.toLowerCase().split(/\s+/).filter(Boolean);

    for (const word of words) {
      const wordTokens = this.wordPieceTokenize(word);
      tokens.push(...wordTokens);
    }

    tokens.push(this.sepId);

    // Truncate content tokens if over maxLength (keep CLS at start, SEP at end)
    if (tokens.length > maxLength) {
      tokens.length = maxLength;
      tokens[maxLength - 1] = this.sepId;
    }

    const inputIds = new BigInt64Array(maxLength);
    const attentionMask = new BigInt64Array(maxLength);

    for (let i = 0; i < tokens.length; i++) {
      inputIds[i] = BigInt(tokens[i]);
      attentionMask[i] = 1n;
    }

    // Remaining positions stay 0n (pad token = 0, mask = 0)
    for (let i = tokens.length; i < maxLength; i++) {
      inputIds[i] = BigInt(this.padId);
      // attentionMask[i] is already 0n
    }

    return { inputIds, attentionMask };
  }

  /**
   * WordPiece tokenization for a single word.
   * Tries to greedily match the longest prefix in vocab, then continues
   * with `##` prefixed subwords. Falls back to [UNK] if no match at all.
   */
  private wordPieceTokenize(word: string): number[] {
    // Fast path: whole word exists in vocab
    if (this.vocab.has(word)) {
      return [this.vocab.get(word)!];
    }

    const tokens: number[] = [];
    let start = 0;

    while (start < word.length) {
      let end = word.length;
      let matched = false;

      while (start < end) {
        const substr = start === 0 ? word.slice(0, end) : `##${word.slice(start, end)}`;

        if (this.vocab.has(substr)) {
          tokens.push(this.vocab.get(substr)!);
          matched = true;
          break;
        }

        end--;
      }

      if (!matched) {
        // Entire word is unresolvable — return single [UNK]
        return [this.unkId];
      }

      start = end;
    }

    return tokens;
  }
}
