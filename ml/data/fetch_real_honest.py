"""Fetch the real honest documents listed in ml/data/real_honest_list.jsonl (#276).

The list is committed; the text is not (it belongs to its authors). This reads
each document from raw.githubusercontent.com at the commit the list pinned,
checks the SHA-256 and the license, and writes ml/data/holdout/real_honest.jsonl
(ignored by git) for ml.train.evaluate_holdout to score. The documents in
real_honest_list.jsonl are for evaluation only and are never trained on; the
training pool (real_honest_train_list.jsonl) comes from different repositories.

A document is dropped, and counted, when its license is not on the allow-list,
when it cannot be fetched (a deleted repository), or when its text no longer
matches the recorded SHA-256.

Usage:
    python3 -m ml.data.fetch_real_honest
    # the training pool (#294), kept apart from the evaluation documents:
    python3 -m ml.data.fetch_real_honest --list ml/data/real_honest_train_list.jsonl \
        --out ml/data/output/real_honest_train.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
LIST = ROOT / "ml" / "data" / "real_honest_list.jsonl"
OUT = ROOT / "ml" / "data" / "holdout" / "real_honest.jsonl"

ALLOWED_LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "CC0-1.0"}


def fetch(item: dict) -> tuple[dict, str | None, str]:
    """Return (item, text or None, reason)."""
    if item["license"] not in ALLOWED_LICENSES:
        return item, None, "license not allowed"
    url = f"https://raw.githubusercontent.com/{item['repo']}/{item['commit']}/{item['path']}"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            text = r.read().decode("utf-8")
    except Exception as err:  # deleted repository, network error, not UTF-8
        return item, None, f"fetch failed ({type(err).__name__})"
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != item["sha256"]:
        return item, None, "text no longer matches the recorded SHA-256"
    return item, text, "ok"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", type=Path, default=LIST)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()
    out_path = args.out
    items = [json.loads(line) for line in args.list.read_text().splitlines() if line.strip()]
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(fetch, items))

    rows, dropped = [], {}
    for item, text, reason in results:
        if text is None:
            dropped[reason] = dropped.get(reason, 0) + 1
            continue
        rows.append(
            {
                "id": f"{item['repo']}:{item['path']}",
                "repo": item["repo"],
                "path": item["path"],
                "kind": item["kind"],
                "license": item["license"],
                "text": text,
            }
        )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    print(f"Fetched {len(rows)} of {len(items)} documents from {len({r['repo'] for r in rows})} repositories")
    if dropped:
        print(f"Dropped: {dropped}")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
