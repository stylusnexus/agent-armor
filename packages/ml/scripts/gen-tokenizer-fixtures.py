"""Regenerate __tests__/fixtures/tokenizer-golden.json from the training tokenizer.

Run after every retrain/export, with the model directory that will be published:

    KMP_DUPLICATE_LIB_OK=TRUE python3 packages/ml/scripts/gen-tokenizer-fixtures.py ml/train/output/onnx

The expected ids come from the Python tokenizer (transformers AutoTokenizer),
the same one used for training, so the TypeScript package is held to what the
model actually saw. The file records the SHA-256 of tokenizer.json; the test
fails when the tokenizer changes without this script being re-run.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import tokenizers
import transformers
from transformers import AutoTokenizer

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "__tests__" / "fixtures"
MAX_LENGTH = 512


def npm_tokenizers_version() -> str:
    """The `tokenizers` npm version the TypeScript package is pinned to."""
    pkg = json.loads((HERE.parent / "package.json").read_text())
    return pkg["dependencies"]["tokenizers"]


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: gen-tokenizer-fixtures.py <model-dir containing tokenizer.json>")
    model_dir = Path(sys.argv[1])
    tok_path = model_dir / "tokenizer.json"
    strings = json.loads((FIXTURES / "tokenizer-strings.json").read_text())

    tok = AutoTokenizer.from_pretrained(str(model_dir))
    ids = [
        tok(s, add_special_tokens=True, truncation=True, max_length=MAX_LENGTH)["input_ids"]
        for s in strings
    ]
    out = {
        "tokenizer_sha256": hashlib.sha256(tok_path.read_bytes()).hexdigest(),
        "transformers_version": transformers.__version__,
        "tokenizers_version": tokenizers.__version__,
        "tokenizers_npm_version": npm_tokenizers_version(),
        "max_length": MAX_LENGTH,
        "ids": ids,
    }
    (FIXTURES / "tokenizer-golden.json").write_text(json.dumps(out) + "\n")
    print(f"wrote {len(ids)} golden id lists for tokenizer {out['tokenizer_sha256'][:12]}")


if __name__ == "__main__":
    main()
