"""Statistics — a regression must be STATISTICALLY significant to fail the build.

pass^k (consistency lower bound, NOT pass@k), seeded bootstrap confidence intervals,
and the paired McNemar test for A/B regression. Deterministic given a seed.
"""

from __future__ import annotations

import random
from collections.abc import Sequence


def pass_hat_k(trials: Sequence[Sequence[bool]]) -> float:
    """pass^k: fraction of tasks that passed on ALL k trials. trials = [[bool]*k per task]."""
    if not trials:
        return 1.0
    return round(sum(1 for t in trials if all(t)) / len(trials), 4)


def pass_at_k(trials: Sequence[Sequence[bool]]) -> float:
    """pass@k: fraction of tasks that passed on AT LEAST ONE trial (reported for contrast)."""
    if not trials:
        return 1.0
    return round(sum(1 for t in trials if any(t)) / len(trials), 4)


def bootstrap_ci(
    successes: Sequence[bool], seed: int = 0, iters: int = 2000, alpha: float = 0.05
) -> tuple[float, float, float]:
    """Seeded bootstrap CI for a pass-rate. Returns (point, lo, hi)."""
    n = len(successes)
    if n == 0:
        return (1.0, 1.0, 1.0)
    xs = [1.0 if s else 0.0 for s in successes]
    point = sum(xs) / n
    rng = random.Random(seed)  # nosec B311 - statistical bootstrap resampling, not cryptographic use
    means = []
    for _ in range(iters):
        s = sum(xs[rng.randrange(n)] for _ in range(n)) / n
        means.append(s)
    means.sort()
    lo = means[int((alpha / 2) * iters)]
    hi = means[min(iters - 1, int((1 - alpha / 2) * iters))]
    return (round(point, 4), round(lo, 4), round(hi, 4))


def mcnemar(baseline: Sequence[bool], candidate: Sequence[bool]) -> dict:
    """Paired McNemar test: did candidate regress vs baseline on the same tasks?

    Returns discordant counts, a chi-square (with continuity correction), and
    `significant` at p<0.05 (chi-square > 3.841, df=1).
    """
    assert len(baseline) == len(candidate), "paired samples must be equal length"
    pairs = list(zip(baseline, candidate, strict=True))
    b = sum(1 for x, y in pairs if x and not y)  # was pass, now fail (regression)
    c = sum(1 for x, y in pairs if not x and y)  # was fail, now pass (improvement)
    if b + c == 0:
        return {"regressions": b, "improvements": c, "chi_square": 0.0, "significant": False}
    chi = (abs(b - c) - 1) ** 2 / (b + c)
    return {
        "regressions": b,
        "improvements": c,
        "chi_square": round(chi, 4),
        "significant": chi > 3.841 and b > c,  # significant AND net-negative
    }
