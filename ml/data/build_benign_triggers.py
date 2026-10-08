"""Build ml/data/benign_triggers.jsonl from raw drafted honest texts.

The drafts are honest sentences and paragraphs that contain words an attack
classifier over-reacts to (see #275). This step removes near-duplicates and any
draft too close to text the model is judged on, so evaluation stays honest:

- the held-out attacks and web attacks (ml/data/holdout, never trained on)
- the eval-suite samples (scripts/eval/samples.ts via ml/data/output/seed.jsonl)
- NotInject (leolee99/NotInject, MIT; evaluation only), when --notinject is given
- the rest of the training data, so the new rows add something

Usage:
    python3 -m ml.data.build_benign_triggers --drafts DIR [--notinject FILE.parquet ...]
"""

from __future__ import annotations

import argparse
import glob
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = ROOT / "ml" / "data"
DATA = ROOT / "ml" / "data" / "output"
HOLDOUT = ROOT / "ml" / "data" / "holdout"

OVERLAP = 0.5  # word-trigram Jaccard at or above this counts as "too close"
DUPLICATE = 0.8  # among the drafts themselves


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def _is_cjk(n: str) -> bool:
    return sum("\u3040" <= c <= "\u9fff" for c in n) >= 0.3 * max(len(n), 1)


def _grams(text: str) -> frozenset:
    n = _norm(text)
    # Chinese and Japanese have no spaces, so use character 4-grams there.
    if _is_cjk(n):
        return frozenset(n[i : i + 4] for i in range(max(len(n) - 3, 1)))
    w = n.split()
    if len(w) < 3:
        return frozenset({tuple(w)})
    return frozenset(tuple(w[i : i + 3]) for i in range(len(w) - 2))


def _jaccard(a: frozenset, b: frozenset) -> float:
    return len(a & b) / len(a | b) if (a or b) else 1.0


def _read_texts(path: Path) -> list[str]:
    out = []
    if path.exists():
        for line in path.open():
            line = line.strip()
            if line:
                out.append(json.loads(line)["text"])
    return out


def _reference_sets(notinject: list[str]) -> dict[str, list[str]]:
    refs: dict[str, list[str]] = {
        "held-out": [t for p in sorted(HOLDOUT.glob("*.jsonl")) for t in _read_texts(p)],
        "eval-suite": _read_texts(DATA / "seed.jsonl"),
        "training": [
            t
            for name in ("synthetic", "hard_negatives", "fresh_attacks", "augmented", "llmail", "ragpoison")
            for t in _read_texts(DATA / f"{name}.jsonl")
        ],
    }
    ni: list[str] = []
    if notinject:
        import pandas as pd

        for p in notinject:
            df = pd.read_parquet(p)
            col = next(c for c in df.columns if c.lower() in ("prompt", "text", "sentence"))
            ni += [str(t) for t in df[col]]
    refs["notinject"] = ni
    return refs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--drafts", required=True, help="directory of *.jsonl drafts")
    ap.add_argument("--notinject", nargs="*", default=[], help="NotInject parquet files")
    ap.add_argument(
        "--out",
        default="benign_triggers.jsonl",
        help="file name under ml/data/ (benign_triggers*.jsonl is loaded by benign_triggers.py)",
    )
    ap.add_argument("--id-prefix", default="bt", help="id prefix for the kept rows")
    args = ap.parse_args()

    rows = []
    for f in sorted(glob.glob(str(Path(args.drafts) / "*.jsonl"))):
        for line in Path(f).read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                r["batch"] = Path(f).stem
                rows.append(r)
    print(f"read {len(rows)} drafts")

    refs = _reference_sets(args.notinject)
    ref_grams = {k: [_grams(t) for t in v] for k, v in refs.items()}
    ref_norm = {k: {_norm(t) for t in v} for k, v in refs.items()}

    kept: list[dict] = []
    kept_grams: list[frozenset] = []
    dropped = {"exact": 0, "self-duplicate": 0, **{f"close to {k}": 0 for k in refs}}
    for r in rows:
        text = r["text"].strip()
        n = _norm(text)
        # TrainingSample needs at least 10 characters
        too_short = len(text) < 10 or (len(n.split()) < 3 and not _is_cjk(n))
        if too_short or any(n in s for s in ref_norm.values()):
            dropped["exact"] += 1
            continue
        g = _grams(text)
        hit = next((k for k, gs in ref_grams.items() if any(_jaccard(g, x) >= OVERLAP for x in gs)), None)
        if hit:
            dropped[f"close to {hit}"] += 1
            continue
        if any(_jaccard(g, x) >= DUPLICATE for x in kept_grams):
            dropped["self-duplicate"] += 1
            continue
        kept.append(
            {
                "id": f"{args.id_prefix}-{len(kept) + 1:04d}",
                "text": text,
                "trigger_words": r.get("trigger_words", []),
                "form": r.get("form", ""),
            }
        )
        kept_grams.append(g)

    OUT = DATA_DIR / args.out
    OUT.write_text("".join(json.dumps(k, ensure_ascii=False) + "\n" for k in kept))
    print(f"kept {len(kept)}; dropped {dropped}")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
