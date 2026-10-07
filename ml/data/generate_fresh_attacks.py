"""Write the fresh adversarial samples (#212) to JSONL.

Training samples go to ml/data/output/fresh_attacks.jsonl, which validate.py
reads. The held-out samples go to ml/data/holdout/holdout_attacks.jsonl, which
validate.py never reads, so the classifier is never trained on them.
"""

from __future__ import annotations

from pathlib import Path

from ml.data.fresh_attacks import (
    FRESH_ATTACKS,
    FRESH_ATTACKS_R3,
    FRESH_ATTACKS_REFRESH,
    HOLDOUT_ATTACKS,
    HOLDOUT_WEB_ATTACKS,
)
from ml.data.schema import TrainingSample, write_jsonl

ROOT = Path(__file__).resolve().parent.parent.parent


def build(items: list[tuple[str, str, list[str], str]]) -> list[TrainingSample]:
    """Convert tuples into validated TrainingSample objects."""
    samples: list[TrainingSample] = []
    for sample_id, text, labels, description in items:
        sample = TrainingSample(
            text=text,
            labels=labels,
            source="manual",
            difficulty="hard",
            id=sample_id,
            metadata={"generator": "generate_fresh_attacks", "description": description},
        )
        errors = sample.validate()
        if errors:
            raise ValueError(f"Invalid sample {sample_id}: {errors}")
        samples.append(sample)
    return samples


def main() -> None:
    train = build(FRESH_ATTACKS) + build(FRESH_ATTACKS_R3) + build(FRESH_ATTACKS_REFRESH)
    holdout = build(HOLDOUT_ATTACKS) + build(HOLDOUT_WEB_ATTACKS)

    train_path = ROOT / "ml" / "data" / "output" / "fresh_attacks.jsonl"
    holdout_path = ROOT / "ml" / "data" / "holdout" / "holdout_attacks.jsonl"
    holdout_path.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(train, train_path)
    write_jsonl(holdout, holdout_path)

    print(f"Generated {len(train)} training attacks -> {train_path}")
    print(f"Generated {len(holdout)} held-out attacks -> {holdout_path}")

    from collections import Counter

    counts = Counter(label for s in train for label in s.labels)
    for label, cnt in sorted(counts.items()):
        print(f"  {label}: {cnt}")


if __name__ == "__main__":
    main()
