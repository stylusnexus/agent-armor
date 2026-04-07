"""Ingest and label samples from Microsoft LLMail-Inject dataset.

Maps LLMail-Inject's 13 objective classes to Agent Armor's 14-label taxonomy.
Downloads from HuggingFace, filters to mappable objectives, samples a balanced
subset, and writes to JSONL.

Usage:
    python -m ml.data.ingest_llmail [--max-per-label N] [--dry-run]

Requires: pip install datasets
Outputs: ml/data/output/llmail.jsonl
"""

from __future__ import annotations

import random
from pathlib import Path

from ml.data.schema import TrainingSample, write_jsonl

random.seed(42)

OUTPUT_DIR = Path("ml/data/output")
OUTPUT_FILE = OUTPUT_DIR / "llmail.jsonl"

# ---------------------------------------------------------------------------
# Objective-to-taxonomy mapping
# ---------------------------------------------------------------------------
# LLMail-Inject objectives → Agent Armor labels
# Only objectives with a clear mapping are included.
# Some map to multiple labels (multi-label).

OBJECTIVE_MAP: dict[str, list[str]] = {
    # Exfiltration-related objectives
    "exfiltrate_email_content": ["data-exfiltration"],
    "exfiltrate_contact_info": ["data-exfiltration"],
    "exfiltrate_calendar": ["data-exfiltration"],
    "exfiltrate_files": ["data-exfiltration"],
    "exfiltrate_credentials": ["data-exfiltration"],
    # Jailbreak / instruction override
    "hijack_response": ["embedded-jailbreak"],
    "override_instructions": ["embedded-jailbreak"],
    "ignore_safety": ["embedded-jailbreak", "oversight-evasion"],
    # Agent manipulation
    "execute_code": ["sub-agent-spawning"],
    "send_email": ["data-exfiltration", "sub-agent-spawning"],
    "modify_settings": ["sub-agent-spawning"],
    # RAG/context poisoning (if email is used as RAG source)
    "inject_false_info": ["rag-knowledge-poisoning", "biased-framing"],
}

# Objectives we skip (no clean mapping to our taxonomy)
SKIP_OBJECTIVES = {
    "unknown",
    "other",
}


def load_dataset_samples(max_rows: int = 50000) -> list[dict]:
    """Load LLMail-Inject from HuggingFace."""
    try:
        from datasets import load_dataset
    except ImportError:
        print("ERROR: Install datasets library: pip install datasets")
        raise SystemExit(1)

    print("Downloading LLMail-Inject from HuggingFace...")
    # Dataset has Phase1/Phase2 splits, not train/test
    from itertools import chain
    ds1 = load_dataset("microsoft/llmail-inject-challenge", split="Phase1", streaming=True)
    ds2 = load_dataset("microsoft/llmail-inject-challenge", split="Phase2", streaming=True)
    ds = chain(ds1, ds2)

    rows = []
    for i, row in enumerate(ds):
        if i >= max_rows:
            break
        rows.append(row)
        if (i + 1) % 10000 == 0:
            print(f"  Loaded {i + 1} rows...")

    print(f"  Loaded {len(rows)} rows total")
    return rows


def map_row(row: dict) -> TrainingSample | None:
    """Map a single LLMail-Inject row to a TrainingSample, or None if unmappable."""
    import json as _json

    body = row.get("body", "").strip()
    if not body or len(body) < 20:
        return None

    # Parse objectives JSON string: {"email.retrieved": true, "exfil.sent": false, ...}
    objectives_raw = row.get("objectives", "{}")
    try:
        if isinstance(objectives_raw, str):
            obj_flags = _json.loads(objectives_raw)
        elif isinstance(objectives_raw, dict):
            obj_flags = objectives_raw
        else:
            return None
    except _json.JSONDecodeError:
        return None

    # Map outcome flags to our labels
    labels: set[str] = set()

    # All samples are adversarial email injection attempts → embedded-jailbreak
    labels.add("embedded-jailbreak")

    # Exfiltration flags
    if obj_flags.get("exfil.sent") or obj_flags.get("exfil.destination") or obj_flags.get("exfil.content"):
        labels.add("data-exfiltration")

    # If exfil succeeded, the attack bypassed defenses → also oversight-evasion
    if obj_flags.get("exfil.sent") and obj_flags.get("defense.undetected"):
        labels.add("oversight-evasion")

    is_successful = bool(obj_flags.get("exfil.sent")) or bool(obj_flags.get("defense.undetected"))

    return TrainingSample(
        text=body,
        labels=sorted(labels),
        source="benchmark-llmail",
        difficulty="moderate" if is_successful else "hard",
        id="",
        metadata={
            "generator": "ingest_llmail",
            "scenario": row.get("scenario", ""),
            "successful": is_successful,
        },
    )


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--max-per-label", type=int, default=200,
                        help="Max samples per label (default: 200)")
    parser.add_argument("--max-rows", type=int, default=50000,
                        help="Max rows to scan from dataset (default: 50000)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show mapping stats without downloading")
    args = parser.parse_args()

    if args.dry_run:
        print("Dry run: showing objective mapping")
        print(f"\nMapped objectives ({len(OBJECTIVE_MAP)}):")
        for obj, labels in sorted(OBJECTIVE_MAP.items()):
            print(f"  {obj:<30} -> {', '.join(labels)}")
        print(f"\nSkipped objectives: {SKIP_OBJECTIVES}")
        print(f"\nWould sample up to {args.max_per_label} per label")
        return

    rows = load_dataset_samples(max_rows=args.max_rows)

    # Map all rows
    mapped: list[TrainingSample] = []
    unmapped = 0
    for row in rows:
        sample = map_row(row)
        if sample:
            mapped.append(sample)
        else:
            unmapped += 1

    print(f"\nMapped: {len(mapped)}, Unmapped: {unmapped}")

    # Count per label
    label_pools: dict[str, list[TrainingSample]] = {}
    for s in mapped:
        for label in s.labels:
            label_pools.setdefault(label, []).append(s)

    print("\nPer-label pool sizes:")
    for label, pool in sorted(label_pools.items()):
        print(f"  {label:<30} {len(pool)}")

    # Stratified sampling: up to max_per_label per label
    selected_ids: set[int] = set()
    selected: list[TrainingSample] = []

    for label, pool in sorted(label_pools.items()):
        # Prefer successful attacks
        successful = [s for s in pool if s.metadata.get("successful")]
        other = [s for s in pool if not s.metadata.get("successful")]

        candidates = successful + other
        count = 0
        for s in candidates:
            sample_id = id(s)
            if sample_id not in selected_ids and count < args.max_per_label:
                selected_ids.add(sample_id)
                selected.append(s)
                count += 1

    # Assign IDs
    for i, s in enumerate(selected):
        s.id = f"llmail-{i:04d}"

    # Validate
    valid = []
    for s in selected:
        errors = s.validate()
        if errors:
            print(f"  WARNING: Skipping {s.id}: {errors}")
        else:
            valid.append(s)

    write_jsonl(valid, OUTPUT_FILE)

    print(f"\nWrote {len(valid)} samples to {OUTPUT_FILE}")

    # Final label distribution
    final_labels: dict[str, int] = {}
    for s in valid:
        for label in s.labels:
            final_labels[label] = final_labels.get(label, 0) + 1
    print("\nFinal per-label counts:")
    for label, count in sorted(final_labels.items()):
        print(f"  {label:<30} {count}")


if __name__ == "__main__":
    main()
