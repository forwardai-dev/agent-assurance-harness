"""Deterministic IR metrics for retrieval/reranking evaluation — the money math.

nDCG@k, MRR, MAP, Recall@k, Hit@k over a ranked list of doc ids given relevance
judgments (binary set or graded dict). Pure Python, no dependencies, fully reproducible.
"""

from __future__ import annotations

import math
from collections.abc import Mapping


def _rel(doc_id: str, relevant) -> float:
    if isinstance(relevant, Mapping):
        return float(relevant.get(doc_id, 0.0))
    return 1.0 if doc_id in relevant else 0.0


def dcg_at_k(ranked: list[str], relevant, k: int) -> float:
    """Discounted cumulative gain at rank k."""
    dcg = 0.0
    for i, doc in enumerate(ranked[:k]):
        rel = _rel(doc, relevant)
        if rel:
            dcg += (2**rel - 1) / math.log2(i + 2)
    return dcg


def ndcg_at_k(ranked: list[str], relevant, k: int) -> float:
    """Normalized discounted cumulative gain at rank k."""
    dcg = dcg_at_k(ranked, relevant, k)
    if isinstance(relevant, Mapping):
        ideal = sorted(relevant.values(), reverse=True)
    else:
        ideal = [1.0] * len(relevant)
    idcg = sum((2**r - 1) / math.log2(i + 2) for i, r in enumerate(ideal[:k]))
    return round(dcg / idcg, 4) if idcg > 0 else 0.0


def mrr(ranked: list[str], relevant) -> float:
    """Mean reciprocal rank of the first relevant result."""
    for i, doc in enumerate(ranked):
        if _rel(doc, relevant) > 0:
            return round(1.0 / (i + 1), 4)
    return 0.0


def average_precision(ranked: list[str], relevant) -> float:
    """Average precision over the ranked results."""
    hits, total = 0, 0.0
    n_rel = len(relevant) if not isinstance(relevant, Mapping) else sum(1 for v in relevant.values() if v > 0)
    for i, doc in enumerate(ranked):
        if _rel(doc, relevant) > 0:
            hits += 1
            total += hits / (i + 1)
    return round(total / n_rel, 4) if n_rel else 0.0


def recall_at_k(ranked: list[str], relevant, k: int) -> float:
    """Fraction of relevant items retrieved within the top k."""
    n_rel = len(relevant) if not isinstance(relevant, Mapping) else sum(1 for v in relevant.values() if v > 0)
    if not n_rel:
        return 0.0
    found = sum(1 for doc in ranked[:k] if _rel(doc, relevant) > 0)
    return round(found / n_rel, 4)


def hit_at_k(ranked: list[str], relevant, k: int) -> float:
    """1.0 if any relevant item appears in the top k, else 0.0."""
    return 1.0 if any(_rel(doc, relevant) > 0 for doc in ranked[:k]) else 0.0
