"""Detection at fixed low false-flag rates, with confidence intervals (#276).

Pure functions on score arrays, so the maths can be tested without a model.
A "score" is the highest trap-label probability for one text.

With N honest documents the lowest false-flag rate that can be resolved is
about 1/N. Asking for 0.1% with fewer than 1,000 honest documents puts the
threshold on a single document, so `detection_at_fpr` reports whether the rate
is resolvable and the caller must say so next to the number.
"""

from __future__ import annotations

import math

import numpy as np


def wilson_interval(flagged: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion (works at 0 flags, unlike the normal one)."""
    if n <= 0:
        return (0.0, 1.0)
    p = flagged / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def threshold_for_fpr(honest_scores: np.ndarray, fpr: float) -> float:
    """Smallest threshold t such that at most `fpr` of honest scores are strictly above t."""
    n = len(honest_scores)
    allowed = int(math.floor(fpr * n))
    ordered = np.sort(honest_scores)[::-1]  # descending
    if allowed >= n:
        return float(-np.inf)
    return float(ordered[allowed])  # the (allowed+1)-th highest; scores above it are the `allowed` highest


def resolvable(n_honest: int, fpr: float) -> bool:
    """True when `fpr` allows at least one honest document above the threshold."""
    return math.floor(fpr * n_honest) >= 1


def detection_at_fpr(honest_scores: np.ndarray, attack_scores: np.ndarray, fpr: float) -> dict:
    """Fraction of attacks scoring strictly above the threshold that lets `fpr` of honest text through."""
    t = threshold_for_fpr(honest_scores, fpr)
    return {
        "fpr": fpr,
        "threshold": round(t, 4),
        "detected": int((attack_scores > t).sum()),
        "attacks": int(len(attack_scores)),
        "detection_rate": round(float((attack_scores > t).mean()), 4) if len(attack_scores) else 0.0,
        "resolvable": resolvable(len(honest_scores), fpr),
    }


def cluster_bootstrap_detection(
    honest_scores: np.ndarray,
    honest_groups: np.ndarray,
    attack_scores: np.ndarray,
    fpr: float,
    rounds: int = 1000,
    seed: int = 0,
) -> tuple[float, float]:
    """95% interval for detection at `fpr`, resampling whole repositories (honest) and attacks.

    Documents from one repository are not independent, so the honest side is
    resampled by repository, not by document.
    """
    rng = np.random.default_rng(seed)
    groups = np.unique(honest_groups)
    by_group = {g: honest_scores[honest_groups == g] for g in groups}
    rates = []
    for _ in range(rounds):
        picked = rng.choice(groups, size=len(groups), replace=True)
        h = np.concatenate([by_group[g] for g in picked])
        a = rng.choice(attack_scores, size=len(attack_scores), replace=True)
        rates.append(float((a > threshold_for_fpr(h, fpr)).mean()))
    lo, hi = np.percentile(rates, [2.5, 97.5])
    return (round(float(lo), 4), round(float(hi), 4))
