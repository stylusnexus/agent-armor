"""Validate, deduplicate, and split training data into train/val/test sets."""

from __future__ import annotations

import random
from collections import Counter, defaultdict
from pathlib import Path

from ml.data.schema import TrainingSample, ALL_LABELS, read_jsonl, write_jsonl

ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = ROOT / "ml" / "data" / "output"

TRAIN_RATIO = 0.80
VAL_RATIO = 0.10
TEST_RATIO = 0.10


# ---------------------------------------------------------------------------
# Deduplication helpers
# ---------------------------------------------------------------------------

def text_fingerprint(text: str) -> set[tuple[str, ...]]:
    """Return the set of word trigrams from the text."""
    words = text.lower().split()
    if len(words) < 3:
        return {tuple(words)}
    return {(words[i], words[i + 1], words[i + 2]) for i in range(len(words) - 2)}


def jaccard_similarity(a: set, b: set) -> float:
    """Jaccard index between two sets."""
    if not a and not b:
        return 1.0
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union else 0.0


def deduplicate(samples: list[TrainingSample], threshold: float = 0.8) -> list[TrainingSample]:
    """Remove near-duplicates using Jaccard similarity on word trigrams."""
    fingerprints: list[set[tuple[str, ...]]] = []
    kept: list[TrainingSample] = []

    for sample in samples:
        fp = text_fingerprint(sample.text)
        is_dup = False
        for existing_fp in fingerprints:
            if jaccard_similarity(fp, existing_fp) >= threshold:
                is_dup = True
                break
        if not is_dup:
            kept.append(sample)
            fingerprints.append(fp)

    removed = len(samples) - len(kept)
    print(f"  Deduplication: removed {removed} near-duplicates ({len(kept)} remaining)")
    return kept


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def print_stats(name: str, samples: list[TrainingSample]) -> None:
    """Print formatted stats block for a set of samples."""
    print(f"\n{'=' * 60}")
    print(f"  {name}: {len(samples)} samples")
    print(f"{'=' * 60}")

    if not samples:
        print("  (empty)")
        return

    # Per-label counts
    label_counts: Counter[str] = Counter()
    for s in samples:
        for label in s.labels:
            label_counts[label] += 1

    max_count = max(label_counts.values()) if label_counts else 1
    bar_width = 30

    print("\n  Labels:")
    for label in ALL_LABELS:
        count = label_counts.get(label, 0)
        bar_len = int((count / max_count) * bar_width) if max_count else 0
        bar = "#" * bar_len
        print(f"    {label:<25s} {count:>4d}  {bar}")

    # Per-source counts
    source_counts: Counter[str] = Counter(s.source for s in samples)
    print("\n  Sources:")
    for source, count in source_counts.most_common():
        print(f"    {source:<30s} {count:>4d}")

    # Per-difficulty counts
    diff_counts: Counter[str] = Counter(str(s.difficulty) for s in samples)
    print("\n  Difficulty:")
    for diff, count in diff_counts.most_common():
        print(f"    {diff:<15s} {count:>4d}")


# ---------------------------------------------------------------------------
# Stratified split
# ---------------------------------------------------------------------------

def stratified_split(
    samples: list[TrainingSample],
    train_ratio: float,
    val_ratio: float,
    test_ratio: float,
) -> tuple[list[TrainingSample], list[TrainingSample], list[TrainingSample]]:
    """Split samples into train/val/test, stratified by primary label."""
    by_label: defaultdict[str, list[TrainingSample]] = defaultdict(list)
    for s in samples:
        primary = s.labels[0]
        by_label[primary].append(s)

    train, val, test = [], [], []

    for label in sorted(by_label.keys()):
        group = by_label[label]
        random.shuffle(group)
        n = len(group)
        n_train = max(1, round(n * train_ratio))
        n_val = max(0, round(n * val_ratio))
        # test gets the rest
        train.extend(group[:n_train])
        val.extend(group[n_train : n_train + n_val])
        test.extend(group[n_train + n_val :])

    return train, val, test


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def main() -> None:
    random.seed(42)

    # 1. Read source files
    print("Loading source files...")
    all_samples: list[TrainingSample] = []
    for filename in ("seed.jsonl", "synthetic.jsonl", "hard_negatives.jsonl", "augmented.jsonl", "llmail.jsonl", "ragpoison.jsonl"):
        path = OUTPUT_DIR / filename
        if path.exists():
            samples = read_jsonl(path)
            print(f"  {filename}: {len(samples)} samples")
            all_samples.extend(samples)
        else:
            print(f"  {filename}: NOT FOUND, skipping")

    print(f"\n  Total loaded: {len(all_samples)} samples")

    # 2. Validate
    print("\nValidating samples...")
    invalid_count = 0
    valid_samples: list[TrainingSample] = []
    for s in all_samples:
        errors = s.validate()
        if errors:
            invalid_count += 1
            print(f"  INVALID [{s.id or 'no-id'}]: {errors}")
        else:
            valid_samples.append(s)

    print(f"  Valid: {len(valid_samples)}, Invalid: {invalid_count}")

    # 3. Deduplicate
    print("\nDeduplicating...")
    deduped = deduplicate(valid_samples)

    # 4. Stratified split
    # Seed samples (source="eval-suite") go to validation ONLY
    seed_samples = [s for s in deduped if s.source == "eval-suite"]
    non_seed = [s for s in deduped if s.source != "eval-suite"]

    print(f"\n  Seed samples (eval-suite, val only): {len(seed_samples)}")
    print(f"  Non-seed samples (to split): {len(non_seed)}")

    train, val_extra, test = stratified_split(
        non_seed, TRAIN_RATIO, VAL_RATIO, TEST_RATIO,
    )

    # Final val = seed + val_extra
    val = seed_samples + val_extra

    print(f"\n  Split sizes: train={len(train)}, val={len(val)}, test={len(test)}")

    # 5. Write splits
    write_jsonl(train, OUTPUT_DIR / "train.jsonl")
    write_jsonl(val, OUTPUT_DIR / "val.jsonl")
    write_jsonl(test, OUTPUT_DIR / "test.jsonl")
    print(f"\n  Written to {OUTPUT_DIR}/{{train,val,test}}.jsonl")

    # 6. Print stats
    print_stats("Combined (after dedup)", deduped)
    print_stats("Train", train)
    print_stats("Validation", val)
    print_stats("Test", test)


if __name__ == "__main__":
    main()
