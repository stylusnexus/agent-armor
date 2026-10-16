"""Drop training-pool documents that are near-copies of evaluation documents (#294).

The evaluation list (real_honest_list.jsonl) and the training pool
(real_honest_train_list.jsonl) share no repository, but the same boilerplate
(issue templates, codes of conduct) appears in many
repositories. A pool document is dropped when its first 3,000 characters share
at least 60% of their word 4-grams (Jaccard) with the first 3,000 characters of
any evaluation document. Run 7 dropped 154 of 3,000 this way.

Reads and rewrites the fetched pool in place:
    python3 -m ml.data.filter_real_pool
which needs both fetched sets (see ml/data/fetch_real_honest.py).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
EVAL = ROOT / "ml" / "data" / "holdout" / "real_honest.jsonl"
POOL = ROOT / "ml" / "data" / "output" / "real_honest_train.jsonl"
THRESHOLD = 0.6
CHARS = 3000


def grams(text: str) -> frozenset:
    words = re.sub(r"\s+", " ", text[:CHARS].lower()).split()
    return frozenset(tuple(words[i : i + 4]) for i in range(max(len(words) - 3, 1)))


def main() -> None:
    evaluation = [json.loads(line) for line in EVAL.read_text(encoding="utf-8").splitlines() if line.strip()]
    pool = [json.loads(line) for line in POOL.read_text(encoding="utf-8").splitlines() if line.strip()]
    eval_grams = [grams(d["text"]) for d in evaluation]

    kept = []
    for doc in pool:
        g = grams(doc["text"])
        if any(len(g & e) / max(len(g | e), 1) >= THRESHOLD for e in eval_grams):
            continue
        kept.append(doc)

    POOL.write_text("".join(json.dumps(d, ensure_ascii=False) + "\n" for d in kept), encoding="utf-8")
    print(f"Training pool: {len(pool)} documents, kept {len(kept)}, dropped {len(pool) - len(kept)} near-copies of evaluation documents")


if __name__ == "__main__":
    main()
