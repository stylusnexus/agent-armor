"""LLM-based augmentation of existing synthetic training samples.

For each synthetic sample, generates variants via the Anthropic API:
- 5 paraphrase variants (same attack, different phrasing)
- 3 obfuscation variants (encoding tricks, zero-width chars, case mixing)
- 2 context-embedded variants (attack wrapped in realistic document)

Labels carry over from the original sample.

Usage:
    python -m ml.data.augment_with_llm [--max-source N] [--dry-run]

Requires: ANTHROPIC_API_KEY environment variable.
Outputs: ml/data/output/augmented.jsonl
"""

from __future__ import annotations

import json
import os
import random
import sys
import time
from pathlib import Path

from ml.data.schema import TrainingSample, read_jsonl, write_jsonl

random.seed(42)

OUTPUT_DIR = Path("ml/data/output")
OUTPUT_FILE = OUTPUT_DIR / "augmented.jsonl"
SYNTHETIC_FILE = OUTPUT_DIR / "synthetic.jsonl"

MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 2048


def call_anthropic(prompt: str, system: str = "") -> str:
    """Call the Anthropic API. Returns the text response."""
    import anthropic

    client = anthropic.Anthropic()
    msg = client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=system if system else anthropic.NOT_GIVEN,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text


SYSTEM_PROMPT = """You are a security researcher generating adversarial test samples for an AI agent security classifier. You will be given an adversarial text sample and asked to generate variants. Each variant must:
1. Preserve the same attack intent and technique
2. Use different phrasing, structure, or obfuscation
3. Be a complete, standalone sample (not a fragment)
4. Be realistic — something that could appear in real content an AI agent ingests

Return ONLY a JSON array of strings, one per variant. No explanation or commentary."""


def generate_variants(sample: TrainingSample) -> list[str]:
    """Generate 10 variants of a sample via the Anthropic API."""
    labels_str = ", ".join(sample.labels)
    prompt = f"""Here is an adversarial text sample labeled as [{labels_str}]:

---
{sample.text}
---

Generate exactly 10 variants as a JSON array of strings:
- Variants 1-5: Paraphrase (same attack technique, completely different wording and structure)
- Variants 6-8: Obfuscation (use techniques like Unicode substitution, base64 fragments, mixed case, zero-width characters, or encoded instructions)
- Variants 9-10: Context-embedded (wrap the attack naturally inside a realistic document like an email, wiki page, API response, or chat log)

Return ONLY the JSON array. No other text."""

    response = call_anthropic(prompt, system=SYSTEM_PROMPT)

    # Parse JSON array from response
    try:
        # Handle markdown code blocks
        text = response.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
            text = text.rsplit("```", 1)[0]
        variants = json.loads(text)
        if not isinstance(variants, list):
            raise ValueError("Response is not a JSON array")
        return [str(v) for v in variants if isinstance(v, str) and len(v) >= 10]
    except (json.JSONDecodeError, ValueError) as e:
        print(f"  WARNING: Failed to parse response for {sample.id}: {e}")
        return []


def main() -> None:
    """Generate augmented samples from existing synthetic data."""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--max-source", type=int, default=None,
                        help="Max source samples to augment (default: all)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print plan without calling API")
    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY") and not args.dry_run:
        print("ERROR: ANTHROPIC_API_KEY not set. Use --dry-run to preview.")
        sys.exit(1)

    if not SYNTHETIC_FILE.exists():
        print(f"ERROR: {SYNTHETIC_FILE} not found. Run generate_synthetic first.")
        sys.exit(1)

    source_samples = read_jsonl(SYNTHETIC_FILE)
    print(f"Loaded {len(source_samples)} synthetic samples")

    # Sample a balanced subset if --max-source is set
    if args.max_source and args.max_source < len(source_samples):
        # Stratified sampling by label
        by_label: dict[str, list[TrainingSample]] = {}
        for s in source_samples:
            key = s.labels[0] if s.labels else "unknown"
            by_label.setdefault(key, []).append(s)

        per_label = max(1, args.max_source // len(by_label))
        selected: list[TrainingSample] = []
        for label, samples in by_label.items():
            selected.extend(random.sample(samples, min(per_label, len(samples))))
        source_samples = selected[:args.max_source]
        print(f"Selected {len(source_samples)} samples (stratified)")

    if args.dry_run:
        label_counts: dict[str, int] = {}
        for s in source_samples:
            for label in s.labels:
                label_counts[label] = label_counts.get(label, 0) + 1

        total_variants = len(source_samples) * 10
        print(f"\nDry run: would generate ~{total_variants} variants from {len(source_samples)} samples")
        print("\nPer-label source distribution:")
        for label, count in sorted(label_counts.items()):
            print(f"  {label:<30} {count:>4} sources -> ~{count * 10} variants")
        print(f"\nEstimated API calls: {len(source_samples)}")
        print(f"Estimated cost: ~${len(source_samples) * 0.003:.2f}")
        return

    augmented: list[TrainingSample] = []
    errors = 0

    for i, sample in enumerate(source_samples):
        print(f"[{i + 1}/{len(source_samples)}] Augmenting {sample.id} ({', '.join(sample.labels)})...")

        try:
            variants = generate_variants(sample)
        except Exception as e:
            print(f"  ERROR: {e}")
            errors += 1
            if errors > 5:
                print("Too many errors, stopping.")
                break
            time.sleep(2)
            continue

        for j, variant_text in enumerate(variants):
            aug_sample = TrainingSample(
                text=variant_text,
                labels=sample.labels,
                source="synthetic-augmented",
                difficulty=sample.difficulty,
                id=f"aug-{sample.id}-{j:02d}",
                metadata={
                    "generator": "augment_with_llm",
                    "source_id": sample.id,
                    "variant_type": "paraphrase" if j < 5 else "obfuscation" if j < 8 else "context-embedded",
                },
            )
            validation_errors = aug_sample.validate()
            if validation_errors:
                print(f"  WARNING: Invalid variant {aug_sample.id}: {validation_errors}")
                continue
            augmented.append(aug_sample)

        print(f"  Generated {len(variants)} variants")

        # Rate limiting: ~1 request per second
        if i < len(source_samples) - 1:
            time.sleep(1)

    write_jsonl(augmented, OUTPUT_FILE)
    print(f"\nDone. Wrote {len(augmented)} augmented samples to {OUTPUT_FILE}")

    # Summary
    label_counts: dict[str, int] = {}
    for s in augmented:
        for label in s.labels:
            label_counts[label] = label_counts.get(label, 0) + 1
    print("\nPer-label augmented counts:")
    for label, count in sorted(label_counts.items()):
        print(f"  {label:<30} {count}")


if __name__ == "__main__":
    main()
