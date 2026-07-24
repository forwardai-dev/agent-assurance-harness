"""Reranker interface + offline mock rerankers. Real rerankers (cross-encoder, LLM
listwise, Cohere/BGE) plug in behind this one Protocol; the mocks keep the suite
offline and deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class Reranker(Protocol):
    """Protocol for a reranker: reorder candidates for a query."""

    name: str

    def rerank(self, query: str, candidates: list[str]) -> list[str]:
        """Return the candidates reordered for the query."""
        ...


@dataclass
class IdentityReranker:
    """No-op baseline: returns retrieval order unchanged."""

    name: str = "identity(no-rerank baseline)"

    def rerank(self, query: str, candidates: list[str]) -> list[str]:
        """Return the candidates unchanged (no-rerank baseline)."""
        return list(candidates)


@dataclass
class OracleMockReranker:
    """Deterministic mock that moves known-relevant ids up by a tunable strength.

    Simulates a strong reranker for offline demo/testing WITHOUT a model. `strength`
    in [0,1]: 1.0 = perfect (all relevant first), 0.0 = identity.
    """

    relevant_by_query: dict[str, set[str]]
    strength: float = 1.0
    name: str = "mock-oracle"

    def rerank(self, query: str, candidates: list[str]) -> list[str]:
        """Move known-relevant ids toward the top by relevance-set membership, scaled by strength."""
        rel = self.relevant_by_query.get(query, set())
        if self.strength >= 1.0:
            rels = [c for c in candidates if c in rel]
            nons = [c for c in candidates if c not in rel]
            return rels + nons
        # partial: stable score = base rank minus a boost for relevant, scaled by strength
        n = len(candidates)
        scored = []
        for i, c in enumerate(candidates):
            boost = (n if c in rel else 0) * self.strength
            scored.append((-(boost) + i, i, c))  # lower is better; i breaks ties (stable)
        scored.sort()
        return [c for _, _, c in scored]


@dataclass
class ReciprocalRankFusion:
    """RRF over multiple retrieval lists (cheap hybrid baseline). k=60 per the paper."""

    lists: dict[str, list[str]]  # query -> already-fused? No: caller supplies per-call
    k: int = 60
    name: str = "rrf"

    def rerank(self, query: str, candidates: list[str]) -> list[str]:
        """Rerank by reciprocal-rank score 1/(k+rank); single-list RRF degenerates to identity."""
        scores = {c: 1.0 / (self.k + i + 1) for i, c in enumerate(candidates)}
        return sorted(candidates, key=lambda c: -scores[c])
