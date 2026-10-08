"""Honest texts that contain words an attack classifier over-reacts to (#275).

Loaded from benign_triggers.jsonl, which ml/data/build_benign_triggers.py writes
from drafted texts after removing anything close to the held-out attacks, the
eval suite or NotInject. Each row becomes one benign hard negative.
"""

from __future__ import annotations

import json
from pathlib import Path

_DIR = Path(__file__).parent


def _load() -> list[tuple[str, str, str]]:
    rows = []
    for path in sorted(_DIR.glob("benign_triggers*.jsonl")):
        for line in path.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                words = ", ".join(r.get("trigger_words", []))
                rows.append((r["id"], r["text"], f"honest text using: {words}"))
    return rows


BENIGN_TRIGGERS: list[tuple[str, str, str]] = _load()
