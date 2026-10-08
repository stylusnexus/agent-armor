"""Write the Chinese attack samples (ml/data/zh_attacks.jsonl) as training rows.

The model had almost no Chinese in training, so it read ordinary Chinese
requests as attacks (NotInject, #275). These attacks keep it from learning that
Chinese text is harmless. They were written from scratch; the separate Chinese
held-out set (ml/data/holdout/holdout_zh_attacks.jsonl) is never trained on.
"""

from __future__ import annotations

import json
from pathlib import Path

from ml.data.schema import TrainingSample, write_jsonl

ROOT = Path(__file__).resolve().parent.parent.parent
SRC = ROOT / "ml" / "data" / "zh_attacks.jsonl"
OUT = ROOT / "ml" / "data" / "output" / "zh_attacks.jsonl"


def build_samples() -> list[TrainingSample]:
    samples = []
    for line in SRC.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        s = TrainingSample(
            text=r["text"],
            labels=r["labels"],
            source="manual",
            difficulty="moderate",
            id=r["id"],
            metadata={"generator": "generate_zh_attacks", "language": "zh"},
        )
        errors = s.validate()
        if errors:
            raise ValueError(f"Invalid sample {r['id']}: {errors}")
        samples.append(s)
    return samples


def main() -> None:
    samples = build_samples()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(samples, OUT)
    print(f"Wrote {len(samples)} samples to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
