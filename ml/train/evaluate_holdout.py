"""Score a trained model on sets it was never trained on (#212).

Three sets, none of them used for training any model in the comparison:

- the held-out attacks (ml/data/holdout/holdout_attacks.jsonl): 110 original
  and web-sourced attack samples, written after the training data was fixed;
- the eval-suite attacks in val.jsonl (source "eval-suite"): the repo's own
  adversarial eval samples, which validate.py forces into validation only;
- the eval-suite benign samples in val.jsonl: the repo's own honest text.

It reports, at the inference thresholds (strict 0.3, balanced 0.5, permissive
0.7): how many held-out attacks get any trap label, how many honest rows get
one, the split of honest flags by source, per-label recall, and the ranking
quality (AUC and detection at fixed false-positive rates) that does not depend
on where the threshold sits. Compare models with the ranking numbers: a model
that flags everything looks good on raw detection.

An attack counts as detected when the model reports at least one trap label at
the threshold. A benign row counts as flagged when it does the same.

Usage:
    KMP_DUPLICATE_LIB_OK=TRUE python3 -m ml.train.evaluate_holdout
    KMP_DUPLICATE_LIB_OK=TRUE python3 -m ml.train.evaluate_holdout --model-dir <dir> --out <file.json>
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
HOLDOUT_PATH = ROOT / "ml" / "data" / "holdout" / "holdout_attacks.jsonl"
VAL_PATH = ROOT / "ml" / "data" / "output" / "val.jsonl"
DEFAULT_MODEL_DIR = ROOT / "ml" / "train" / "output" / "model"
DEFAULT_OUT = ROOT / "ml" / "train" / "output" / "holdout_report.json"

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
BENIGN_IDX = LABELS.index("benign")
# The thresholds the inference package uses: strict, balanced, permissive.
THRESHOLDS = {"strict": 0.3, "balanced": 0.5, "permissive": 0.7}


def load_jsonl(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def main() -> None:
    # torch must be imported before sklearn/transformers (OpenMP crash on macOS).
    import torch  # noqa: E402
    import numpy as np
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    attacks = load_jsonl(HOLDOUT_PATH)
    val_rows = load_jsonl(VAL_PATH)
    honest = [s for s in val_rows if s["labels"] == ["benign"]]
    suite_attacks = [s for s in val_rows if s.get("source") == "eval-suite" and s["labels"] != ["benign"]]
    suite_honest = [s for s in honest if s.get("source") == "eval-suite"]
    print(
        f"Held-out attacks: {len(attacks)}   eval-suite attacks: {len(suite_attacks)}   "
        f"honest rows from val: {len(honest)} (eval-suite: {len(suite_honest)})"
    )

    tokenizer = AutoTokenizer.from_pretrained(str(args.model_dir))
    model = AutoModelForSequenceClassification.from_pretrained(str(args.model_dir))
    model.eval()
    device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    model.to(device)

    def probabilities(texts: list[str]) -> np.ndarray:
        out = []
        for i in range(0, len(texts), 16):
            enc = tokenizer(
                texts[i : i + 16],
                truncation=True,
                padding="max_length",
                max_length=512,
                return_tensors="pt",
            )
            enc = {k: v.to(device) for k, v in enc.items()}
            with torch.no_grad():
                out.append(torch.sigmoid(model(**enc).logits).cpu().numpy())
        return np.vstack(out)

    attack_probs = probabilities([s["text"] for s in attacks])
    honest_probs = probabilities([s["text"] for s in honest])
    suite_attack_probs = probabilities([s["text"] for s in suite_attacks])
    trap_idx = [i for i in range(len(LABELS)) if i != BENIGN_IDX]
    trap_score = lambda p: p[:, trap_idx].max(axis=1)  # noqa: E731

    # Ranking quality: how well the highest trap score separates attacks from
    # honest text, independent of the threshold.
    a_score, h_score = trap_score(attack_probs), trap_score(honest_probs)
    auc = float(np.mean([(x > y) + 0.5 * (x == y) for x in a_score for y in h_score]))
    ranking: dict = {"auc": round(auc, 3)}
    for fpr in (0.05, 0.10, 0.20):
        cut = np.quantile(h_score, 1 - fpr)
        ranking[f"detected_at_{int(fpr * 100)}pct_false_flags"] = round(float((a_score > cut).mean()), 3)

    honest_groups = {
        "eval-suite": [i for i, s in enumerate(honest) if s.get("source") == "eval-suite"],
        "other": [i for i, s in enumerate(honest) if s.get("source") != "eval-suite"],
    }

    report: dict = {
        "model_dir": str(args.model_dir),
        "attacks": len(attacks),
        "eval_suite_attacks": len(suite_attacks),
        "honest": len(honest),
        "ranking": ranking,
    }
    print(f"ranking: {ranking}")
    for name, thr in THRESHOLDS.items():
        flagged_attack = (attack_probs[:, trap_idx] >= thr).any(axis=1)
        flagged_honest = (honest_probs[:, trap_idx] >= thr).any(axis=1)
        flagged_suite_attack = (suite_attack_probs[:, trap_idx] >= thr).any(axis=1)
        per_label: dict[str, dict] = {}
        for label in LABELS[:-1]:
            rows = [i for i, s in enumerate(attacks) if label in s["labels"]]
            if not rows:
                continue
            hit = sum(1 for i in rows if attack_probs[i, LABELS.index(label)] >= thr)
            per_label[label] = {"samples": len(rows), "labelled_correctly": hit}
        report[name] = {
            "threshold": thr,
            "attack_detection_rate": round(float(flagged_attack.mean()), 4),
            "attacks_detected": int(flagged_attack.sum()),
            "eval_suite_attacks_detected": int(flagged_suite_attack.sum()),
            "honest_flag_rate": round(float(flagged_honest.mean()), 4),
            "honest_flagged": int(flagged_honest.sum()),
            "honest_flagged_by_source": {
                group: f"{int(flagged_honest[idx].sum())}/{len(idx)}" for group, idx in honest_groups.items()
            },
            "per_label": per_label,
        }
        print(
            f"{name:<10} thr={thr}  held-out attacks {int(flagged_attack.sum())}/{len(attacks)}"
            f"  eval-suite attacks {int(flagged_suite_attack.sum())}/{len(suite_attacks)}"
            f"  honest flagged {int(flagged_honest.sum())}/{len(honest)}"
            f" (eval-suite {report[name]['honest_flagged_by_source']['eval-suite']})"
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
