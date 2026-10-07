import { readFile } from 'fs/promises';
import { AgentArmorModelError } from './errors';

/**
 * The slice of the model's `tokenizer.json` that this file checks before
 * handing it to the Hugging Face tokenizer. Every field is optional because the
 * file may be hand-assembled or truncated (users can point `modelDir` at their
 * own directory), so `fromFile` validates rather than trusting the annotation.
 */
interface TokenizerJson {
  model?: { type?: string };
  added_tokens?: Array<{ id: number; content: string }>;
}

/** The subset of the `tokenizers` package this wrapper calls. */
interface HfEncoding {
  getIds(): number[];
}
interface HfTokenizer {
  disablePadding(): void;
  disableTruncation(): void;
  encode(
    text: string,
    pair: string | null,
    options: { addSpecialTokens: boolean },
  ): Promise<HfEncoding>;
}
interface HfTokenizersModule {
  Tokenizer: { fromFile(path: string): HfTokenizer };
}

/** Tokenizer families the shipped model has been checked against golden ids for. */
const SUPPORTED_MODEL_TYPES = ['Unigram'];

const REQUIRED_SPECIAL = ['[PAD]', '[CLS]', '[SEP]', '[UNK]'] as const;

/** Result of {@link Tokenizer.encode}. */
export interface Encoded {
  inputIds: BigInt64Array;
  attentionMask: BigInt64Array;
  /** Share of the content tokens (everything except [CLS] and [SEP]) that are [UNK]. */
  unknownRatio: number;
}

/**
 * Turns text into the `input_ids` and `attention_mask` int64 tensors the ONNX
 * classifier expects.
 *
 * Tokenization is done by the Hugging Face `tokenizers` package reading the
 * model's own `tokenizer.json`, so the ids match what the model saw in training
 * (the training script uses the same Rust code through Python). This file holds
 * no tokenization logic of its own. A retrain that ships a new `tokenizer.json`
 * works without a code change, and the golden-id test in
 * `__tests__/tokenizer-golden.test.ts` fails if the output ever drifts from the
 * Python tokenizer.
 */
export class Tokenizer {
  private constructor(
    private readonly hf: HfTokenizer,
    private readonly clsId: number,
    private readonly sepId: number,
    private readonly padId: number,
    private readonly unkId: number,
  ) {}

  /** Load a tokenizer from the model's `tokenizer.json`. */
  static async fromFile(path: string): Promise<Tokenizer> {
    const raw = await readFile(path, 'utf-8');

    let json: TokenizerJson;
    try {
      json = JSON.parse(raw) as TokenizerJson;
    } catch (err) {
      throw new AgentArmorModelError(
        'MODEL_NOT_FOUND',
        `Tokenizer file at ${path} is not valid JSON. The model directory is corrupt or incomplete; re-download or point modelDir at a complete set of artifacts.`,
        err instanceof Error ? err : undefined,
      );
    }

    const type = json.model?.type;
    if (!type) {
      throw new AgentArmorModelError(
        'MODEL_NOT_FOUND',
        `Tokenizer file at ${path} is missing "model.type". The model directory is corrupt or incomplete; re-download or point modelDir at a complete set of artifacts.`,
      );
    }
    if (!SUPPORTED_MODEL_TYPES.includes(type)) {
      throw new AgentArmorModelError(
        'UNSUPPORTED_TOKENIZER',
        `Tokenizer file at ${path} is a "${type}" tokenizer; this version of @stylusnexus/agentarmor-ml only has golden-id coverage for ${SUPPORTED_MODEL_TYPES.join(', ')}. Update the package, or add golden fixtures for the new tokenizer type before using it.`,
      );
    }

    const special: Record<string, number> = {};
    for (const token of json.added_tokens ?? []) special[token.content] = token.id;
    const missing = REQUIRED_SPECIAL.filter((name) => !(name in special));
    if (missing.length > 0) {
      throw new AgentArmorModelError(
        'UNSUPPORTED_TOKENIZER',
        `Tokenizer file at ${path} does not define the special tokens ${missing.join(', ')}.`,
      );
    }

    let mod: HfTokenizersModule;
    try {
      mod = (await import('tokenizers')) as unknown as HfTokenizersModule;
    } catch (err) {
      throw new AgentArmorModelError(
        'TOKENIZER_LOAD_FAILED',
        `Could not load the "tokenizers" package (a native add-on with prebuilt binaries for macOS, Linux and Windows): ${err instanceof Error ? err.message : String(err)}`,
        err instanceof Error ? err : undefined,
      );
    }

    let hf: HfTokenizer;
    try {
      hf = mod.Tokenizer.fromFile(path);
    } catch (err) {
      throw new AgentArmorModelError(
        'MODEL_NOT_FOUND',
        `Tokenizer file at ${path} could not be parsed: ${err instanceof Error ? err.message : String(err)}`,
        err instanceof Error ? err : undefined,
      );
    }
    // The file may carry its own padding and truncation settings (this one pads
    // every input to 512). Turn both off and apply them here, so the output does
    // not depend on whatever the file happens to say.
    hf.disablePadding();
    hf.disableTruncation();

    return new Tokenizer(
      hf,
      special['[CLS]'],
      special['[SEP]'],
      special['[PAD]'],
      special['[UNK]'],
    );
  }

  /**
   * Encode text into `input_ids` and `attention_mask`, padded or cut to exactly
   * `maxLength` positions. Text that is too long is cut after `maxLength - 1`
   * ids and ends with [SEP], like the training tokenizer's truncation.
   */
  async encode(text: string, maxLength: number = 512): Promise<Encoded> {
    const encoding = await this.hf.encode(text, null, { addSpecialTokens: true });
    let ids = encoding.getIds();

    if (ids.length > maxLength) {
      ids = ids.slice(0, maxLength);
      ids[maxLength - 1] = this.sepId;
    }

    const inputIds = new BigInt64Array(maxLength).fill(BigInt(this.padId));
    const attentionMask = new BigInt64Array(maxLength);
    let unknown = 0;
    for (let i = 0; i < ids.length; i++) {
      inputIds[i] = BigInt(ids[i]);
      attentionMask[i] = 1n;
      if (ids[i] === this.unkId) unknown++;
    }

    const content = Math.max(ids.length - 2, 0);
    return { inputIds, attentionMask, unknownRatio: content === 0 ? 0 : unknown / content };
  }
}
