"""Evaluate + sweep rerankers on a labeled set. "Generate the best method" = a
search-plus-eval loop, honestly: it finds the best reranker for THIS set, reports the
win margin over the no-rerank baseline, and emits Findings into the evidence object.
"""

from __future__ import annotations

from dataclasses import dataclass
from statistics import mean

from ..core.finding import Axis, ControlRef, Finding, Severity
from . import metrics as M
from .rerankers import IdentityReranker, Reranker


@dataclass(frozen=True)
class RerankCase:
    """One labeled reranking case: query, candidates, and relevance labels."""

    query: str
    candidates: list[str]  # retrieved doc ids, in retrieval order
    relevant: object  # set[str] or {doc_id: grade}


@dataclass
class RerankResult:
    """Averaged retrieval metrics for one reranker."""

    name: str
    ndcg: float
    mrr: float
    map: float
    recall: float
    hit: float

    def as_dict(self) -> dict:
        """Return the metrics as a JSON-serializable dict."""
        return {
            "reranker": self.name,
            "ndcg@k": self.ndcg,
            "mrr": self.mrr,
            "map": self.map,
            "recall@k": self.recall,
            "hit@k": self.hit,
        }


def evaluate(cases: list[RerankCase], reranker: Reranker, k: int = 10) -> RerankResult:
    """Evaluate a reranker over labeled cases and return averaged metrics."""
    ndcgs, mrrs, maps, recalls, hits = [], [], [], [], []
    for c in cases:
        ranked = reranker.rerank(c.query, c.candidates)
        ndcgs.append(M.ndcg_at_k(ranked, c.relevant, k))
        mrrs.append(M.mrr(ranked, c.relevant))
        maps.append(M.average_precision(ranked, c.relevant))
        recalls.append(M.recall_at_k(ranked, c.relevant, k))
        hits.append(M.hit_at_k(ranked, c.relevant, k))

    def avg(xs: list[float]) -> float:
        return round(mean(xs), 4) if xs else 0.0

    return RerankResult(reranker.name, avg(ndcgs), avg(mrrs), avg(maps), avg(recalls), avg(hits))


@dataclass
class SweepResult:
    """Result of sweeping rerankers: ranking, winner, and margin over baseline."""

    ranked: list[RerankResult]  # best first, by the chosen metric
    baseline_ndcg: float
    winner: RerankResult
    win_margin: float  # winner ndcg - baseline ndcg

    def to_findings(self, k: int = 10) -> list[Finding]:
        """Emit one INFO Finding per reranker (winner flagged) for the evidence object."""
        out = []
        for i, res in enumerate(self.ranked):
            out.append(
                Finding(
                    id=f"eval.rerank.{res.name.split('(')[0].strip()}",
                    axis=Axis.EVAL,
                    title=f"Reranker: {res.name} (nDCG@{k}={res.ndcg})",
                    passed=True,
                    severity=Severity.INFO,
                    controls=(ControlRef("NIST-AI-RMF", "MEASURE-2.3", "retrieval quality"),),
                    metrics={
                        **res.as_dict(),
                        "rank": i,
                        "is_winner": i == 0,
                        "win_margin_vs_baseline": self.win_margin if i == 0 else None,
                    },
                )
            )
        return out


def sweep(
    cases: list[RerankCase], rerankers: dict[str, Reranker], metric: str = "ndcg", k: int = 10
) -> SweepResult:
    """Compare rerankers; pick the winner by `metric`; report the margin over no-rerank."""
    results = [evaluate(cases, rr, k) for rr in rerankers.values()]
    baseline = evaluate(cases, IdentityReranker(), k)
    key = {
        "ndcg": lambda r: r.ndcg,
        "mrr": lambda r: r.mrr,
        "map": lambda r: r.map,
        "recall": lambda r: r.recall,
    }.get(metric, lambda r: r.ndcg)
    ranked = sorted(results, key=key, reverse=True)
    winner = ranked[0]
    return SweepResult(ranked, baseline.ndcg, winner, round(winner.ndcg - baseline.ndcg, 4))
