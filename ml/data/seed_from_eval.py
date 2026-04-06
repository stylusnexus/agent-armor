"""Convert existing eval samples from scripts/eval/samples.ts to JSONL training format.

Runs a small TypeScript extractor via `npx tsx` to import the eval samples,
then maps them to TrainingSample objects and writes to ml/data/output/seed.jsonl.

These 42 seed samples serve as held-out validation data to ensure the ML
classifier does not regress on known cases.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from ml.data.schema import TRAP_LABELS, TrainingSample, write_jsonl

ROOT = Path(__file__).resolve().parent.parent.parent
SAMPLES_TS = ROOT / "scripts" / "eval" / "samples.ts"
OUTPUT_PATH = ROOT / "ml" / "data" / "output" / "seed.jsonl"

EXTRACTOR_TS = """\
import { ALL_SAMPLES } from './scripts/eval/samples';
console.log(JSON.stringify(ALL_SAMPLES));
"""


def extract_samples_from_ts() -> list[dict]:
    """Run a temporary TypeScript file to extract eval samples as JSON."""
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".ts",
        dir=str(ROOT),
        delete=True,
    ) as f:
        f.write(EXTRACTOR_TS)
        f.flush()

        result = subprocess.run(
            ["npx", "tsx", f.name],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=30,
        )

    if result.returncode != 0:
        print(f"Error running TypeScript extractor:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    return json.loads(result.stdout)


def convert_sample(raw: dict) -> TrainingSample:
    """Map an eval sample dict to a TrainingSample."""
    expected: list[str] = raw.get("expected", [])

    if not expected:
        labels = ["benign"]
    else:
        labels = [l for l in expected if l in TRAP_LABELS]
        if not labels:
            labels = ["benign"]

    return TrainingSample(
        text=raw["content"],
        labels=labels,
        source="eval-suite",
        difficulty=raw.get("difficulty"),
        id=raw["id"],
        metadata={
            "eval_source": raw.get("source", ""),
            "description": raw.get("description", ""),
            "category": raw.get("category", ""),
        },
    )


def main() -> None:
    print(f"Extracting eval samples from {SAMPLES_TS.relative_to(ROOT)} ...")
    raw_samples = extract_samples_from_ts()

    samples = [convert_sample(s) for s in raw_samples]

    # Validate all samples
    errors: list[str] = []
    for s in samples:
        errs = s.validate()
        if errs:
            errors.append(f"  {s.id}: {errs}")
    if errors:
        print(f"Validation errors:\n" + "\n".join(errors), file=sys.stderr)
        sys.exit(1)

    write_jsonl(samples, OUTPUT_PATH)

    adversarial = sum(1 for s in samples if "benign" not in s.labels)
    benign = sum(1 for s in samples if "benign" in s.labels)

    print(f"Wrote {len(samples)} samples to {OUTPUT_PATH.relative_to(ROOT)}")
    print(f"  adversarial: {adversarial}")
    print(f"  benign:      {benign}")


if __name__ == "__main__":
    main()
