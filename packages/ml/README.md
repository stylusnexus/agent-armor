# @stylusnexus/agentarmor-ml

[![npm version](https://img.shields.io/npm/v/@stylusnexus/agentarmor-ml.svg)](https://www.npmjs.com/package/@stylusnexus/agentarmor-ml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

ML classifier add-on for [Agent Armor](https://github.com/stylusnexus/agent-armor). Runs a DeBERTa-v3-small ONNX model locally for deeper agent trap detection that catches threats regex patterns miss.

## Why Use the ML Classifier?

Regex-based detection handles some explicit attacks: hidden HTML instructions, known jailbreak patterns, and exfiltration patterns with clear hostile signals. Some conversation-to-destination wording is intentionally reported only at `strict` because API tutorials, support messages, and tracing docs can use the same words. Balanced regex results are not an authorization check for outbound actions; use an action or network allowlist to constrain where an agent can send data. More sophisticated attacks use natural language to manipulate behavior through biased framing, subtle persona shifts, or contextual learning traps. These don't have a regex signature.

The ML classifier catches what patterns can't. It's trained on the full [AI Agent Traps](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6372438) taxonomy, runs locally (no API calls, no data leaves your machine), and adds meaningful detection coverage on the semantic manipulation categories where regex falls short.

## Install

```bash
npm install @stylusnexus/agentarmor @stylusnexus/agentarmor-ml
```

## Usage

```typescript
import { AgentArmor } from '@stylusnexus/agentarmor';

const armor = await AgentArmor.create({
  ml: { enabled: true },
});

const result = await armor.scan(content);

// ML-detected threats have source: 'ml'
result.threats.filter((t) => t.source === 'ml');
```

## How It Works

On first use, the model (~165MB quantized ONNX) is downloaded from HuggingFace and cached locally:

- **macOS:** `~/Library/Caches/agentarmor/v2/`
- **Linux:** `~/.cache/agentarmor/v2/`
- **Custom:** Set `AGENTARMOR_CACHE_DIR` or pass `ml.modelDir` in config

Subsequent runs load from cache with no network calls.

## Configuration

```typescript
const armor = await AgentArmor.create({
  ml: {
    enabled: true,
    // Point to a local model directory (skips download)
    modelDir: './models/agentarmor',
    // Behavior when model is unavailable
    onUnavailable: 'warn-and-skip', // 'throw' | 'warn-and-skip' | 'silent-skip'
    // Download options
    download: {
      timeoutMs: 120_000,
      retries: 2,
      onProgress: (received, total) => {
        console.log(`${Math.round((received / total) * 100)}%`);
      },
    },
  },
});
```

## CLI

Pre-download the model or manage the cache:

```bash
# Download model to cache (or custom directory)
agentarmor-ml download
agentarmor-ml download --dir ./models

# Show cache location and file sizes
agentarmor-ml cache-info

# Remove cached model
agentarmor-ml clear-cache
```

## Inference Details

- Tokenizes input to 512 tokens with the Hugging Face [`tokenizers`](https://www.npmjs.com/package/tokenizers) package, reading the model's own `tokenizer.json` (SentencePiece Unigram). A retrained model needs no code change; a test fails if the ids drift from the Python training tokenizer.
- If most of an input's tokens are unknown to the tokenizer, the ML result is dropped and the pattern detectors carry the scan. The scan result lists it in `stats.detectorsSkipped`, and `on.warn` fires once
- Runs ONNX inference with INT8 quantization via `onnxruntime-node`
- Applies sigmoid on logits with strictness-based thresholds: `strict=0.3`, `balanced=0.5`, `permissive=0.7`
- `scan()` (sync) returns empty — ML inference is async-only via `scanAsync()`

## Limits

Treat the classifier as a second opinion for triage, not a gate. The regex result stays the thing that blocks content. Measured on 2026-10-08 on the shipped INT8 model (see the [main README](https://github.com/stylusnexus/agent-armor#how-well-it-works) for the full table):

- **False flags on real documents.** The model in `0.1.7` flags 57% of 1,000 real READMEs, docs, policies, agent files and templates from 215 public repositories at the default threshold (the first model, 35%). The retrained model in `0.1.8` flags 0.3% of them (3 of 1,000; the plausible range is 0.1% to 0.9%) and 9 of 339 short NotInject prompts, and catches 95 of 110 held-out attacks at a 1% false-flag rate. Those 1,000 documents are the set the retrain was built to fix, so treat 0.3% as a tuned result, not a fresh test; 90 of them share 30% or more of their wording with training text, and none were read one by one. The 110 held-out attacks have been reused across seven training runs, and the gain over the previous retrain is in false flags, not detection (84 vs 87 of 110 at the default threshold, not significantly different). A fresh test set is tracked in [#298](https://github.com/stylusnexus/agent-armor/issues/298). If you are on `0.1.7`, use it on short text such as tool outputs and prompts, not on long documents.
- **Languages.** English and Chinese only. In probes, "ignore all previous instructions" in Spanish, German and Russian was not flagged.
- **Long text.** The model reads at most 512 tokens (about 2,000 characters). An attack after about 600 tokens is missed, so split long documents into chunks ([#274](https://github.com/stylusnexus/agent-armor/issues/274)). Detection is lower toward the end of the window.
- **The label is a hint.** It often names a different trap type than a person would.
- **Obfuscation.** Leetspeak and word-joiner characters were missed in probes.
- **Small evaluation sets.** Differences of 10 to 20 samples between model versions are noise.

## Deployment Notes

- **AWS Lambda:** 165MB model + ~40MB onnxruntime = ~205MB, fits the 250MB limit but is tight. Use `modelDir` to bundle the model in your deployment package.
- **Native tokenizer:** `tokenizers` is a native add-on that ships prebuilt binaries for macOS, Linux (glibc and musl, x64 and arm64) and Windows, about 64 MB in `node_modules` in total and about 5 MB for one platform. For Lambda, delete the other platforms' `.node` files in `node_modules/tokenizers/` (as you already do for `onnxruntime-node`). Run so far: macOS arm64 (local) and Linux x64 (CI); Windows, linux-arm64, musl and Lambda have not been run.
- **Vercel Edge:** Not supported (ONNX runtime requires Node.js native bindings).

## Requirements

- Node.js >= 18
- Peer dependency: `@stylusnexus/agentarmor >= 0.2.0`

## License

MIT
