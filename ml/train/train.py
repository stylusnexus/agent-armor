"""
Fine-tune DeBERTa-v3-small for multi-label agent trap classification.

Usage:
    KMP_DUPLICATE_LIB_OK=TRUE python3 -m ml.train.train
"""

from __future__ import annotations

import json
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = ROOT / "ml" / "data" / "output"
OUTPUT_DIR = ROOT / "ml" / "train" / "output"
MODEL_DIR = OUTPUT_DIR / "model"
BASE_MODEL = "microsoft/deberta-v3-small"

LABELS = [
    "hidden-html",
    "metadata-injection",
    "dynamic-cloaking",
    "syntactic-masking",
    "embedded-jailbreak",
    "data-exfiltration",
    "sub-agent-spawning",
    "benign",
]

LABEL_TO_IDX = {label: idx for idx, label in enumerate(LABELS)}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def load_jsonl(path: Path) -> list[dict]:
    """Read a JSONL file and return a list of dicts."""
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def labels_to_vector(labels: list[str]) -> list[float]:
    """Convert a list of label strings to a multi-hot float vector of length 8."""
    vector = [0.0] * len(LABELS)
    for label in labels:
        if label in LABEL_TO_IDX:
            vector[LABEL_TO_IDX[label]] = 1.0
    return vector


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _load_model_and_tokenizer():
    """Load DeBERTa model and tokenizer, working around Python 3.14 segfault.

    On Python 3.14 + PyTorch 2.10, importing transformers.Trainer before
    calling torch.load causes a segfault in pickle. We load weights FIRST,
    then import Trainer later.
    """
    import torch
    from huggingface_hub import hf_hub_download
    from transformers import (
        AutoTokenizer,
        DebertaV2Config,
        DebertaV2ForSequenceClassification,
    )

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)

    config = DebertaV2Config.from_pretrained(BASE_MODEL)
    config.num_labels = len(LABELS)
    config.problem_type = "multi_label_classification"
    config.id2label = {i: label for i, label in enumerate(LABELS)}
    config.label2id = LABEL_TO_IDX
    model = DebertaV2ForSequenceClassification(config)

    weights_path = hf_hub_download(BASE_MODEL, "pytorch_model.bin")
    state_dict = torch.load(weights_path, map_location="cpu", weights_only=True)
    model.load_state_dict(state_dict, strict=False)
    print("  Pretrained weights loaded (classifier head randomly initialized)")

    return model, tokenizer


def main() -> None:
    # IMPORTANT: torch must be imported before sklearn to avoid OpenMP
    # segfault on macOS with duplicate libiomp/libomp libraries.
    import torch  # noqa: E402 — must be first
    import numpy as np
    from sklearn.metrics import f1_score, precision_score, recall_score
    from torch.utils.data import Dataset

    # ------------------------------------------------------------------
    # compute_metrics (defined here to capture numpy/sklearn in closure)
    # ------------------------------------------------------------------
    def compute_metrics(eval_pred) -> dict:
        """Compute multi-label classification metrics."""
        logits, label_ids = eval_pred
        probs = 1.0 / (1.0 + np.exp(-logits))  # sigmoid
        preds = (probs >= 0.5).astype(int)
        label_ids = label_ids.astype(int)

        metrics = {
            "macro_f1": f1_score(
                label_ids, preds, average="macro", zero_division=0
            ),
            "micro_f1": f1_score(
                label_ids, preds, average="micro", zero_division=0
            ),
            "macro_precision": precision_score(
                label_ids, preds, average="macro", zero_division=0
            ),
            "macro_recall": recall_score(
                label_ids, preds, average="macro", zero_division=0
            ),
        }

        per_label_f1 = f1_score(
            label_ids, preds, average=None, zero_division=0
        )
        for i, label_name in enumerate(LABELS):
            metrics[f"f1_{label_name}"] = per_label_f1[i]

        return metrics

    # ------------------------------------------------------------------
    # TrapDataset
    # ------------------------------------------------------------------
    class TrapDataset(Dataset):
        """PyTorch dataset for agent trap classification."""

        def __init__(self, samples, tokenizer, max_length=512):
            texts = [s["text"] for s in samples]
            label_vectors = [labels_to_vector(s["labels"]) for s in samples]

            self.encodings = tokenizer(
                texts,
                truncation=True,
                padding="max_length",
                max_length=max_length,
                return_tensors="pt",
            )
            self.labels = torch.tensor(label_vectors, dtype=torch.float)

        def __len__(self):
            return len(self.labels)

        def __getitem__(self, idx):
            item = {key: val[idx] for key, val in self.encodings.items()}
            item["labels"] = self.labels[idx]
            return item

    # ------------------------------------------------------------------
    # Load data
    # ------------------------------------------------------------------
    print(f"Loading data from {DATA_DIR}")
    train_samples = load_jsonl(DATA_DIR / "train.jsonl")
    val_samples = load_jsonl(DATA_DIR / "val.jsonl")
    print(f"  Train: {len(train_samples)} samples")
    print(f"  Val:   {len(val_samples)} samples")

    # ------------------------------------------------------------------
    # Load model and tokenizer (before Trainer import)
    # ------------------------------------------------------------------
    print(f"Loading model: {BASE_MODEL}")
    model, tokenizer = _load_model_and_tokenizer()

    # ------------------------------------------------------------------
    # Create datasets
    # ------------------------------------------------------------------
    train_dataset = TrapDataset(train_samples, tokenizer)
    val_dataset = TrapDataset(val_samples, tokenizer)

    # Device detection
    use_mps = torch.backends.mps.is_available()
    print(f"MPS available: {use_mps}")

    # ------------------------------------------------------------------
    # Now safe to import Trainer (weights already loaded)
    # ------------------------------------------------------------------
    from transformers import (
        EarlyStoppingCallback,
        Trainer,
        TrainingArguments,
    )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    checkpoints_dir = OUTPUT_DIR / "checkpoints"

    training_args = TrainingArguments(
        output_dir=str(checkpoints_dir),
        num_train_epochs=15,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=16,
        learning_rate=2e-5,
        weight_decay=0.01,
        warmup_ratio=0.1,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="macro_f1",
        greater_is_better=True,
        save_total_limit=3,
        logging_steps=10,
        report_to="none",
        fp16=False,
        dataloader_num_workers=0,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=5)],
    )

    # ------------------------------------------------------------------
    # Train
    # ------------------------------------------------------------------
    print("Starting training...")
    train_result = trainer.train()

    # Save best model and tokenizer
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(MODEL_DIR))
    tokenizer.save_pretrained(str(MODEL_DIR))
    print(f"Model saved to {MODEL_DIR}")

    # Save metrics
    train_metrics = train_result.metrics
    with open(OUTPUT_DIR / "train_metrics.json", "w") as f:
        json.dump(train_metrics, f, indent=2)

    eval_metrics = trainer.evaluate()
    with open(OUTPUT_DIR / "eval_metrics.json", "w") as f:
        json.dump(eval_metrics, f, indent=2)

    # Print final results
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print(f"  Macro F1: {eval_metrics.get('eval_macro_f1', 'N/A'):.4f}")
    print(f"  Micro F1: {eval_metrics.get('eval_micro_f1', 'N/A'):.4f}")
    print("\nPer-label F1:")
    for label_name in LABELS:
        key = f"eval_f1_{label_name}"
        val = eval_metrics.get(key, "N/A")
        if isinstance(val, float):
            print(f"  {label_name:25s} {val:.4f}")
        else:
            print(f"  {label_name:25s} {val}")


if __name__ == "__main__":
    main()
