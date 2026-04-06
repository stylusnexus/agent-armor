"""
Evaluate the trained DeBERTa-v3-small model on test and validation sets.

Usage:
    KMP_DUPLICATE_LIB_OK=TRUE python3 -m ml.train.evaluate
"""

from __future__ import annotations

import json
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = ROOT / "ml" / "data" / "output"
MODEL_DIR = ROOT / "ml" / "train" / "output" / "model"
OUTPUT_DIR = ROOT / "ml" / "train" / "output"

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


def predict_batch(
    model, tokenizer, texts: list[str], device, threshold: float = 0.5
):
    """Tokenize, run inference with torch.no_grad, sigmoid, threshold.

    Returns (preds, probs) as numpy arrays.
    """
    import torch
    import numpy as np

    encodings = tokenizer(
        texts,
        truncation=True,
        padding="max_length",
        max_length=512,
        return_tensors="pt",
    )
    encodings = {k: v.to(device) for k, v in encodings.items()}

    with torch.no_grad():
        outputs = model(**encodings)
        logits = outputs.logits
        probs = torch.sigmoid(logits).cpu().numpy()

    preds = (probs >= threshold).astype(int)
    return preds, probs


def main() -> None:
    # IMPORTANT: torch must be imported before sklearn to avoid OpenMP
    # segfault on macOS with duplicate libiomp/libomp libraries.
    import torch  # noqa: E402 — must be first
    import numpy as np
    from sklearn.metrics import (
        classification_report,
        f1_score,
        multilabel_confusion_matrix,
    )
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    # ------------------------------------------------------------------
    # Load data
    # ------------------------------------------------------------------
    print(f"Loading data from {DATA_DIR}")
    test_samples = load_jsonl(DATA_DIR / "test.jsonl")
    val_samples = load_jsonl(DATA_DIR / "val.jsonl")
    print(f"  Test: {len(test_samples)} samples")
    print(f"  Val:  {len(val_samples)} samples")

    # ------------------------------------------------------------------
    # Load model and tokenizer
    # ------------------------------------------------------------------
    print(f"Loading model from {MODEL_DIR}")
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))
    model = AutoModelForSequenceClassification.from_pretrained(str(MODEL_DIR))
    model.eval()

    device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    model.to(device)
    print(f"  Device: {device}")

    # ------------------------------------------------------------------
    # Prepare ground truth
    # ------------------------------------------------------------------
    test_texts = [s["text"] for s in test_samples]
    test_true = np.array([labels_to_vector(s["labels"]) for s in test_samples])

    # ------------------------------------------------------------------
    # Run inference in batches of 16
    # ------------------------------------------------------------------
    batch_size = 16
    all_preds = []
    all_probs = []
    for i in range(0, len(test_texts), batch_size):
        batch_texts = test_texts[i : i + batch_size]
        preds, probs = predict_batch(model, tokenizer, batch_texts, device)
        all_preds.append(preds)
        all_probs.append(probs)

    test_preds = np.vstack(all_preds)
    test_probs = np.vstack(all_probs)

    # ------------------------------------------------------------------
    # Classification report
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("CLASSIFICATION REPORT (Test Set, threshold=0.5)")
    print("=" * 60)
    report_str = classification_report(
        test_true, test_preds, target_names=LABELS, zero_division=0
    )
    print(report_str)

    # ------------------------------------------------------------------
    # Macro / Micro F1
    # ------------------------------------------------------------------
    macro_f1 = f1_score(test_true, test_preds, average="macro", zero_division=0)
    micro_f1 = f1_score(test_true, test_preds, average="micro", zero_division=0)
    print(f"Macro F1: {macro_f1:.4f}")
    print(f"Micro F1: {micro_f1:.4f}")

    # ------------------------------------------------------------------
    # Per-label confusion matrices
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("PER-LABEL CONFUSION MATRICES (TN, FP, FN, TP)")
    print("=" * 60)
    mcm = multilabel_confusion_matrix(test_true, test_preds)
    per_label_metrics = {}
    for i, label_name in enumerate(LABELS):
        tn, fp, fn, tp = mcm[i].ravel()
        print(f"  {label_name:25s}  TN={tn}  FP={fp}  FN={fn}  TP={tp}")

        # Per-label precision/recall/f1
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        per_label_metrics[label_name] = {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        }

    # ------------------------------------------------------------------
    # Threshold sensitivity analysis
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("THRESHOLD SENSITIVITY ANALYSIS")
    print("=" * 60)
    thresholds = [0.3, 0.4, 0.5, 0.6, 0.7]
    threshold_results = {}
    for t in thresholds:
        t_preds = (test_probs >= t).astype(int)
        t_macro_f1 = f1_score(
            test_true, t_preds, average="macro", zero_division=0
        )
        threshold_results[str(t)] = round(t_macro_f1, 4)
        print(f"  threshold={t:.1f}  macro_f1={t_macro_f1:.4f}")

    # ------------------------------------------------------------------
    # Save eval_report.json
    # ------------------------------------------------------------------
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "test_size": len(test_samples),
        "macro_f1": round(macro_f1, 4),
        "micro_f1": round(micro_f1, 4),
        "per_label": per_label_metrics,
        "threshold_sensitivity": threshold_results,
    }
    report_path = OUTPUT_DIR / "eval_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to {report_path}")


if __name__ == "__main__":
    main()
