"""
Export trained DeBERTa model to ONNX format with INT8 dynamic quantization.

Usage:
    KMP_DUPLICATE_LIB_OK=TRUE python3 -m ml.train.export_onnx
"""

from __future__ import annotations

# CRITICAL: import torch before other heavy imports to avoid OpenMP segfault
import torch  # noqa: E402 — must be first

import json
import shutil
from pathlib import Path

import numpy as np
import onnxruntime as ort
from onnxruntime.quantization import QuantType, quantize_dynamic
from transformers import AutoModelForSequenceClassification, AutoTokenizer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent.parent
MODEL_DIR = ROOT / "ml" / "train" / "output" / "model"
ONNX_DIR = ROOT / "ml" / "train" / "output" / "onnx"
DATA_DIR = ROOT / "ml" / "data" / "output"

LABELS = [
    "hidden-html",
    "metadata-injection",
    "dynamic-cloaking",
    "syntactic-masking",
    "embedded-jailbreak",
    "data-exfiltration",
    "sub-agent-spawning",
    "rag-knowledge-poisoning",
    "latent-memory-poisoning",
    "contextual-learning-trap",
    "biased-framing",
    "oversight-evasion",
    "persona-hyperstition",
    "benign",
]


def load_jsonl(path: Path) -> list[dict]:
    """Read a JSONL file and return a list of dicts."""
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def main() -> None:
    ONNX_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 1. Load trained model and tokenizer
    # ------------------------------------------------------------------
    print("Loading model and tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))
    model = AutoModelForSequenceClassification.from_pretrained(str(MODEL_DIR))
    model.eval()
    model.cpu()
    print(f"  Model loaded from {MODEL_DIR}")

    # ------------------------------------------------------------------
    # 2. Export to ONNX
    # ------------------------------------------------------------------
    print("\nExporting to ONNX...")
    dummy_input = tokenizer(
        "test input",
        padding="max_length",
        truncation=True,
        max_length=512,
        return_tensors="pt",
    )

    # Determine which inputs the model actually accepts
    input_names = ["input_ids", "attention_mask"]
    dummy_args = (
        dummy_input["input_ids"],
        dummy_input["attention_mask"],
    )

    # DeBERTa-v3 may or may not use token_type_ids
    if "token_type_ids" in dummy_input:
        input_names.append("token_type_ids")
        dummy_args = dummy_args + (dummy_input["token_type_ids"],)

    onnx_path = ONNX_DIR / "model.onnx"
    quantized_path = ONNX_DIR / "model_quantized.onnx"

    dynamic_axes = {
        "input_ids": {0: "batch_size", 1: "sequence_length"},
        "attention_mask": {0: "batch_size", 1: "sequence_length"},
        "logits": {0: "batch_size"},
    }
    if "token_type_ids" in input_names:
        dynamic_axes["token_type_ids"] = {0: "batch_size", 1: "sequence_length"}

    torch.onnx.export(
        model,
        dummy_args,
        str(onnx_path),
        input_names=input_names,
        output_names=["logits"],
        dynamic_axes=dynamic_axes,
        opset_version=14,
        do_constant_folding=True,
        dynamo=False,
    )
    print(f"  ONNX model saved to {onnx_path}")

    # ------------------------------------------------------------------
    # 3. Quantize with INT8 dynamic quantization
    # ------------------------------------------------------------------
    print("\nQuantizing with INT8 dynamic quantization...")
    quantize_dynamic(
        model_input=str(onnx_path),
        model_output=str(quantized_path),
        weight_type=QuantType.QInt8,
    )
    print(f"  Quantized model saved to {quantized_path}")

    # ------------------------------------------------------------------
    # 4. Copy tokenizer files to ONNX dir
    # ------------------------------------------------------------------
    print("\nCopying tokenizer files...")
    tokenizer_files = [
        "tokenizer.json",
        "tokenizer_config.json",
        "special_tokens_map.json",
    ]
    for fname in tokenizer_files:
        src = MODEL_DIR / fname
        if src.exists():
            shutil.copy2(str(src), str(ONNX_DIR / fname))
            print(f"  Copied {fname}")
        else:
            print(f"  Warning: {fname} not found in model dir")

    # ------------------------------------------------------------------
    # 5. Save label_map.json
    # ------------------------------------------------------------------
    label_map = {str(i): label for i, label in enumerate(LABELS)}
    label_map_path = ONNX_DIR / "label_map.json"
    with open(label_map_path, "w", encoding="utf-8") as f:
        json.dump(label_map, f, indent=2)
    print(f"\nLabel map saved to {label_map_path}")

    # ------------------------------------------------------------------
    # 6. Validate both ONNX models
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("VALIDATION")
    print("=" * 60)

    test_samples = load_jsonl(DATA_DIR / "test.jsonl")[:3]

    for model_name, model_path in [
        ("Original ONNX", onnx_path),
        ("Quantized ONNX (INT8)", quantized_path),
    ]:
        print(f"\n--- {model_name}: {model_path.name} ---")
        session = ort.InferenceSession(str(model_path))
        session_input_names = [inp.name for inp in session.get_inputs()]

        for i, sample in enumerate(test_samples):
            text = sample["text"][:100]  # truncate for display
            true_labels = sample["labels"]

            enc = tokenizer(
                sample["text"],
                padding="max_length",
                truncation=True,
                max_length=512,
                return_tensors="np",
            )

            ort_inputs = {}
            for name in session_input_names:
                if name in enc:
                    ort_inputs[name] = enc[name]

            outputs = session.run(None, ort_inputs)
            logits = outputs[0]
            probs = 1.0 / (1.0 + np.exp(-logits))  # sigmoid

            pred_labels = [
                LABELS[j] for j in range(len(LABELS)) if probs[0][j] >= 0.5
            ]

            print(f"\n  Sample {i + 1}: {text!r}...")
            print(f"    True labels:      {true_labels}")
            print(f"    Predicted labels: {pred_labels}")
            print(f"    Probabilities:    {[f'{p:.4f}' for p in probs[0]]}")

    # ------------------------------------------------------------------
    # 7. Print file sizes
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("FILE SIZES")
    print("=" * 60)
    for path in [onnx_path, quantized_path]:
        size_mb = path.stat().st_size / (1024 * 1024)
        print(f"  {path.name}: {size_mb:.1f} MB")

    print("\nONNX export complete!")


if __name__ == "__main__":
    main()
