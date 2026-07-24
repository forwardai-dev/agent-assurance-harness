"""Leakage linter — a merge gate on golden sets (the no-leakage guardrail).

Flags golden items that overlap a known training/eval corpus (n-gram overlap + canary
strings) or that lack provenance. A leaky benchmark gives the WRONG-signed result, so
this refuses contaminated goldens rather than silently scoring them.
"""

from __future__ import annotations

from dataclasses import dataclass


def _ngrams(text: str, n: int = 5) -> set[str]:
    toks = text.lower().split()
    return {" ".join(toks[i : i + n]) for i in range(max(0, len(toks) - n + 1))}


def ngram_overlap(candidate: str, corpus_texts: list[str], n: int = 5) -> float:
    """Fraction of test n-grams also present in the training text."""
    cand = _ngrams(candidate, n)
    if not cand:
        return 0.0
    corpus = set()
    for t in corpus_texts:
        corpus |= _ngrams(t, n)
    return round(len(cand & corpus) / len(cand), 4)


@dataclass
class LeakReport:
    """Result of a train/test contamination (leakage) check."""

    item_id: str
    overlap: float
    has_canary: bool
    has_provenance: bool
    threshold: float = 0.5

    @property
    def leaked(self) -> bool:
        """True if n-gram overlap exceeds the (caller-set) leakage threshold."""
        return self.overlap > self.threshold or self.has_canary or not self.has_provenance


def lint_golden(
    items: list[dict],
    known_corpus: list[str],
    canaries: tuple[str, ...] = ("CANARY-DO-NOT-TRAIN",),
    threshold: float = 0.5,
) -> list[LeakReport]:
    """items: [{'id','text','provenance'}]. Returns a report per item; any leaked=True should block merge."""
    reports = []
    for it in items:
        text = it.get("text", "")
        ov = ngram_overlap(text, known_corpus)
        canary = any(c in text for c in canaries)
        prov = bool(it.get("provenance"))
        reports.append(LeakReport(it.get("id", "?"), ov, canary, prov, threshold))
    return reports
