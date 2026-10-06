---
name: retrain
description: Retrain the Agent Armor ML classifier (DeBERTa-v3-small, 14-label multi-label). Use when the user says "retrain", "retrain the model", "update the model", "rebuild the classifier", or wants to run the ML training pipeline.
---

# Retrain

Retrain the Agent Armor ML classifier (DeBERTa-v3-small, 14-label multi-label).

Use this skill when the user says "retrain", "retrain the model", "update the model", "rebuild the classifier", or wants to run the ML training pipeline.

## When to Use

- After adding new eval samples or synthetic templates
- After running data augmentation scripts
- When preparing a new model version for HuggingFace
- When the user asks to retrain or update the ML classifier

## Pipeline

The full pipeline has 7 steps. Run them in order. Every ML command MUST be prefixed with `KMP_DUPLICATE_LIB_OK=TRUE` (macOS/Apple Silicon OpenMP workaround).

### Step 1: Regenerate seed data from eval suite

```bash
python3 -m ml.data.seed_from_eval
```

Converts `scripts/eval/samples.ts` to `ml/data/output/seed.jsonl` via npx tsx. Report the sample count.

### Step 2: Generate synthetic samples

```bash
python3 -m ml.data.generate_synthetic
```

Generates ~420 adversarial samples targeting regex-bypass techniques. Writes to `ml/data/output/synthetic.jsonl`.

### Step 3: Generate hard negatives

```bash
python3 -m ml.data.generate_hard_negatives
```

Generates ~29 benign samples using security vocabulary in legitimate contexts. Writes to `ml/data/output/hard_negatives.jsonl`.

### Step 4: Data augmentation (optional, adds ~2,200 samples)

These scripts add external data. Skip if the user only wants a quick retrain on existing data.

```bash
# LLM augmentation (~1,430 samples, requires ANTHROPIC_API_KEY)
ANTHROPIC_API_KEY=<key> python3 -m ml.data.augment_with_llm --max-source 150

# LLMail-Inject ingestion (~600 samples, downloads from HuggingFace)
python3 -m ml.data.ingest_llmail --max-per-label 200

# RAG poisoning generation (~200 samples, local only)
python3 -m ml.data.generate_ragpoison
```

Check if output files already exist before re-running:
- `ml/data/output/augmented.jsonl` — LLM augmentation
- `ml/data/output/llmail.jsonl` — LLMail-Inject
- `ml/data/output/ragpoison.jsonl` — PoisonedRAG

If they exist and the user hasn't changed templates, skip regeneration and go to Step 5.

### Step 5: Validate, deduplicate, and split

```bash
python3 -m ml.data.validate
```

Reads all `ml/data/output/*.jsonl` files, deduplicates (Jaccard trigrams, threshold=0.8), forces eval-suite samples into val set, splits 80/10/10 into train/val/test.

**Check the output carefully:**
- Report total samples, per-label distribution, and split sizes
- Flag if any label has fewer than 50 training samples (model will underperform on that label)
- Flag if total training samples < 1,000 (model may collapse — warn the user)

### Step 6: Train

```bash
KMP_DUPLICATE_LIB_OK=TRUE python3 -m ml.train.train
```

Fine-tunes DeBERTa-v3-small (multi-label, 14 sigmoid outputs) with HuggingFace Trainer on MPS (Apple Silicon). Config: 15 epochs, lr=2e-5, batch_size=8, early stopping patience=5, best model by macro_f1.

**Training takes 3-10 minutes on M-series Macs.**

Saves to `ml/train/output/model/`. Report:
- Final macro F1 and micro F1
- Per-label F1 scores
- Whether early stopping triggered and at which epoch
- **STOP if macro F1 < 0.3** — the model collapsed. Do not proceed to evaluation. Tell the user the dataset is too small or imbalanced.

### Step 7: Evaluate

```bash
KMP_DUPLICATE_LIB_OK=TRUE python3 -m ml.train.evaluate
```

Runs on the held-out test set. Saves `ml/train/output/eval_report.json`. Report:
- Test macro F1 and micro F1
- Per-label precision, recall, F1
- Any labels with F1 = 0.0 (complete failure on that label)
- Threshold sensitivity analysis

**Quality gate:** If macro F1 >= 0.5, the model is publishable. If < 0.5, recommend expanding training data before publishing.

## Publishing (separate step, only on user request)

After evaluation passes the quality gate:

```bash
# Export to ONNX + INT8 quantization
KMP_DUPLICATE_LIB_OK=TRUE python3 -m ml.train.export_onnx

# Push to HuggingFace
KMP_DUPLICATE_LIB_OK=TRUE python3 -m ml.train.push_to_hub
```

After pushing, update `MODEL_CHECKSUM` in `packages/ml/src/constants.ts` with the new SHA-256. The push script reads `ml/train/output/eval_report.json` to populate the model card.

## Model details

- Base: microsoft/deberta-v3-small (~44M params)
- Labels: hidden-html, metadata-injection, dynamic-cloaking, syntactic-masking, embedded-jailbreak, data-exfiltration, sub-agent-spawning, rag-knowledge-poisoning, latent-memory-poisoning, contextual-learning-trap, biased-framing, oversight-evasion, persona-hyperstition, benign
- Inference thresholds by strictness: strict=0.3, balanced=0.5, permissive=0.7
- ONNX export: opset 14, INT8 dynamic quantization (~140MB)
- HuggingFace repo: stylusnexus/agent-armor-classifier

## Data file locations

| File | Source | Gitignored |
|---|---|---|
| `ml/data/output/seed.jsonl` | eval suite | Yes |
| `ml/data/output/synthetic.jsonl` | template generator | Yes |
| `ml/data/output/hard_negatives.jsonl` | manual + synthetic | Yes |
| `ml/data/output/augmented.jsonl` | LLM augmentation | Yes |
| `ml/data/output/llmail.jsonl` | LLMail-Inject | Yes |
| `ml/data/output/ragpoison.jsonl` | PoisonedRAG | Yes |
| `ml/data/output/train.jsonl` | validate.py split | Yes |
| `ml/data/output/val.jsonl` | validate.py split | Yes |
| `ml/data/output/test.jsonl` | validate.py split | Yes |
| `ml/train/output/model/` | training | Yes |
| `ml/train/output/onnx/` | export | Yes |
| `ml/train/output/eval_report.json` | evaluation | Yes |
