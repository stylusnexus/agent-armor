"""Training data schema and label taxonomy for the ML classifier pipeline."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Literal


TRAP_LABELS: list[str] = [
    "hidden-html",
    "metadata-injection",
    "dynamic-cloaking",
    "syntactic-masking",
    "embedded-jailbreak",
    "data-exfiltration",
    "sub-agent-spawning",
    "rag-knowledge-poisoning",
    "latent-memory-poisoning",
    "contextual-learning-trap",
    "biased-framing",
    "oversight-evasion",
    "persona-hyperstition",
]

ALL_LABELS: list[str] = TRAP_LABELS + ["benign"]

Source = Literal[
    "eval-suite",
    "synthetic",
    "benchmark-wasp",
    "benchmark-agentdojo",
    "benchmark-jailbreakbench",
    "manual",
]

Difficulty = Literal["easy", "moderate", "hard"]

VALID_SOURCES: set[str] = set(Source.__args__)  # type: ignore[attr-defined]
VALID_DIFFICULTIES: set[str | None] = {*Difficulty.__args__, None}  # type: ignore[attr-defined]


@dataclass
class TrainingSample:
    """A single training sample for the ML classifier."""

    text: str
    labels: list[str]
    source: Source
    difficulty: Difficulty | None = None
    id: str = ""
    metadata: dict = field(default_factory=dict)

    def validate(self) -> list[str]:
        """Return a list of validation error strings. Empty list means valid."""
        errors: list[str] = []

        if not self.text:
            errors.append("text must not be empty")

        if not self.labels:
            errors.append("labels must not be empty")

        unknown = [l for l in self.labels if l not in ALL_LABELS]
        if unknown:
            errors.append(f"unknown labels: {unknown}")

        if "benign" in self.labels and len(self.labels) > 1:
            errors.append("'benign' cannot be combined with other labels")

        if self.text and len(self.text) < 10:
            errors.append("text must be at least 10 characters")

        if self.source not in VALID_SOURCES:
            errors.append(f"unknown source: {self.source!r}")

        if self.difficulty not in VALID_DIFFICULTIES:
            errors.append(f"unknown difficulty: {self.difficulty!r}")

        return errors

    def to_jsonl(self) -> str:
        """Serialize to a single JSON line string."""
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_jsonl(cls, line: str) -> TrainingSample:
        """Deserialize from a single JSON line string."""
        data = json.loads(line)
        return cls(**data)


def write_jsonl(samples: list[TrainingSample], path: str | Path) -> None:
    """Write a list of TrainingSamples to a JSONL file, creating parent dirs."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for sample in samples:
            f.write(sample.to_jsonl() + "\n")


def read_jsonl(path: str | Path) -> list[TrainingSample]:
    """Read a JSONL file into a list of TrainingSamples."""
    samples: list[TrainingSample] = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(TrainingSample.from_jsonl(line))
    return samples
