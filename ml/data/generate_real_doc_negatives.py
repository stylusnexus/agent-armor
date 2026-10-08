"""Training rows from real documents (#294).

Run 6 learned honest text from short, drafted samples and flagged 57% of real
READMEs, policies and templates. This turns a pool of real documents into
training rows, from repositories that share nothing with the evaluation set
(ml/data/real_honest_list.jsonl, #276):

- benign: the start of each document (what the model reads) and, for long
  documents, a later section;
- attack: the start of other documents with one training attack inserted at a
  paragraph boundary, labelled with that attack's labels. This teaches the model
  to find the injected text inside real document style, instead of treating the
  style as the signal.

Attacks come from the training attack files only, never the held-out sets.
Needs the pool fetched first:
    python3 -m ml.data.fetch_real_honest --list ml/data/real_honest_train_list.jsonl \\
        --out ml/data/output/real_honest_train.jsonl
Usage:
    python3 -m ml.data.generate_real_doc_negatives [--docs 2400] [--seed 294]
"""

from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path

from ml.data.schema import TrainingSample, read_jsonl, write_jsonl

ROOT = Path(__file__).resolve().parent.parent.parent
DOCS = ROOT / "ml" / "data" / "output" / "real_honest_train.jsonl"
OUT = ROOT / "ml" / "data" / "output" / "real_doc_negatives.jsonl"
EVAL_LIST = ROOT / "ml" / "data" / "real_honest_list.jsonl"
ATTACK_FILES = ("synthetic.jsonl", "fresh_attacks.jsonl", "augmented.jsonl")

BENIGN_CHARS = 1800  # about 450 tokens: the model reads 512
INJECTED_CHARS = 1300  # leaves room for an attack of up to 500 characters
MIN_CHARS = 400
CJK = re.compile(r"[぀-鿿]")


def cut(text: str, start: int, size: int) -> str:
    """A slice of about `size` characters that starts and ends at a line break."""
    end = min(len(text), start + size)
    if end < len(text):
        nl = text.rfind("\n", start + MIN_CHARS, end)
        end = nl if nl != -1 else end
    chunk = text[start:end].strip()
    return chunk


def paragraphs(chunk: str) -> list[str]:
    return [p for p in re.split(r"\n\s*\n", chunk) if p.strip()]


def inject(chunk: str, attack: str, rng: random.Random) -> str:
    parts = paragraphs(chunk) or [chunk]
    at = rng.choice([0, len(parts) // 2, len(parts)])  # start, middle or end
    return "\n\n".join(parts[:at] + [attack.strip()] + parts[at:])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--docs", type=int, default=2400)
    ap.add_argument("--seed", type=int, default=294)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    eval_repos = {json.loads(l)["repo"].lower() for l in EVAL_LIST.read_text().splitlines() if l.strip()}
    docs = [d for d in read_jsonl_dicts(DOCS) if d["repo"].lower() not in eval_repos]
    rng.shuffle(docs)
    docs = docs[: args.docs]

    attacks = []
    for name in ATTACK_FILES:
        path = ROOT / "ml" / "data" / "output" / name
        if path.exists():
            for r in read_jsonl_dicts(path):
                t = r["text"]
                if "benign" not in r["labels"] and 40 <= len(t) <= 500 and not CJK.search(t):
                    attacks.append(r)
    if not attacks:
        raise SystemExit("no attack samples found; run the attack generators first")

    samples: list[TrainingSample] = []

    def add(text: str, labels: list[str], doc: dict, what: str) -> None:
        s = TrainingSample(
            text=text,
            labels=labels,
            source="manual",
            difficulty="hard",
            id=f"rd-{len(samples) + 1:05d}",
            metadata={"generator": "generate_real_doc_negatives", "kind": doc["kind"], "what": what, "repo": doc["repo"]},
        )
        errors = s.validate()
        if errors:
            return
        samples.append(s)

    n_inject = int(len(docs) * 0.5)
    for i, doc in enumerate(docs):
        text = doc["text"]
        head = cut(text, 0, BENIGN_CHARS)
        if len(head) >= MIN_CHARS:
            add(head, ["benign"], doc, "head")
        if len(text) > 4000 and rng.random() < 0.35:
            start = rng.randint(BENIGN_CHARS, len(text) - 1200)
            mid = cut(text, start, BENIGN_CHARS)
            if len(mid) >= MIN_CHARS:
                add(mid, ["benign"], doc, "middle")
        if i < n_inject:
            base = cut(text, 0, INJECTED_CHARS)
            if len(base) >= MIN_CHARS:
                atk = rng.choice(attacks)
                add(inject(base, atk["text"], rng), list(atk["labels"]), doc, "injected")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(samples, OUT)
    benign = sum(1 for s in samples if s.labels == ["benign"])
    print(
        f"Wrote {len(samples)} samples to {OUT.relative_to(ROOT)} "
        f"({benign} benign, {len(samples) - benign} with an injected attack) from {len(docs)} documents "
        f"in {len({d['repo'] for d in docs})} repositories"
    )


def read_jsonl_dicts(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


if __name__ == "__main__":
    main()
