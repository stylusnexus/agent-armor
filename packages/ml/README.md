# @stylusnexus/agentarmor-ml

[![npm version](https://img.shields.io/npm/v/@stylusnexus/agentarmor-ml.svg)](https://www.npmjs.com/package/@stylusnexus/agentarmor-ml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

ML classifier add-on for [Agent Armor](https://github.com/stylusnexus/agent-armor). Runs a DeBERTa-v3-small ONNX model locally for deeper agent trap detection that catches threats regex patterns might miss.

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
result.threats.filter(t => t.source === 'ml');
```

## How It Works

On first use, the model (~140MB quantized ONNX) is downloaded from HuggingFace and cached locally:

- **macOS:** `~/Library/Caches/agentarmor/v1/`
- **Linux:** `~/.cache/agentarmor/v1/`
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
        console.log(`${Math.round(received / total * 100)}%`);
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

- Tokenizes input to 512 tokens (WordPiece)
- Runs ONNX inference with INT8 quantization via `onnxruntime-node`
- Applies sigmoid on logits with strictness-based thresholds: `strict=0.3`, `balanced=0.5`, `permissive=0.7`
- `scan()` (sync) returns empty — ML inference is async-only via `scanAsync()`

## Deployment Notes

- **AWS Lambda:** 140MB model + ~40MB onnxruntime = ~180MB, fits the 250MB limit but is tight. Use `modelDir` to bundle the model in your deployment package.
- **Vercel Edge:** Not supported (ONNX runtime requires Node.js native bindings).

## Requirements

- Node.js >= 18
- Peer dependency: `@stylusnexus/agentarmor >= 0.2.0`

## License

MIT
