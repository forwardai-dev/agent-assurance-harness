# Spec Addendum — `rerank-eval` module (retrieval + reranking optimization)

First-class module of the Agent Assurance Harness eval side. Added per user request 2026-07-19. Merge into the functional + technical spec produced by the council swarm.

## Why it belongs
RAG/agent answer quality is gated by retrieval order. Most "best reranker" claims are guesses because teams lack a labeled eval set. This module turns reranking into a measured, reproducible, CI-gated optimization — consistent with the harness's determinism + audit thesis.

## Functional capabilities
- **Measure** retrieval/reranking quality on a golden set: nDCG@k, MRR, MAP, Recall@k, Hit@k (deterministic IR metrics).
- **Sweep + select**: compare candidate rerankers across top-k values, pick the best by a chosen metric (default nDCG@10), and report the win margin over the no-rerank baseline.
- **Optimize honestly**: "generate the best method" = a search-plus-eval loop over {retriever, reranker, top-k}, not magic. Surface the tradeoff (quality vs latency/cost) per config.
- **Governance tie-in**: every run stamps the chosen config + dataset hash into the audit log (reproducible); CI gate fails the build on nDCG regression beyond a threshold.

## Reranker families supported (pluggable interface, not hard deps)
- **Cross-encoder** rerankers (BGE-reranker, mxbai-rerank, Jina; API: Cohere Rerank, Voyage).
- **LLM listwise** rerankers (RankGPT / RankLLM: RankZephyr, RankVicuna).
- **Reciprocal Rank Fusion (RRF)** for hybrid dense+BM25 (cheap baseline).
- The harness ships **mock deterministic rerankers** so tests + demo run OFFLINE with no models/APIs; real rerankers plug in via one interface.

## Technical interface (Python, mirrors the harness's other engines)
```
@dataclass
class RerankCase:      # one labeled query
    query: str
    candidates: list[str]           # doc ids in retrieved order
    relevant: set[str]              # qrels: relevant doc ids (optionally graded)

class Reranker(Protocol):
    def rerank(self, query: str, candidates: list[str]) -> list[str]: ...   # reordered ids

def evaluate(cases: list[RerankCase], reranker: Reranker, ks=(1,5,10)) -> RerankResult
def sweep(cases, rerankers: dict[str, Reranker], metric="ndcg@10") -> SweepResult   # ranked table + winner
```
- **Metrics engine**: small pure-Python IR metrics (nDCG/MRR/MAP/Recall/Hit) — no heavy dep; optional `ir_measures` adapter for parity with TREC tooling.
- **Offline strategy**: a `MockReranker` (seeded, moves known-relevant ids up by a tunable amount) + a synthetic golden set generator, so `pytest` is green with zero network. Real rerankers are optional extras.
- **Repo location** (as built): `src/aah/rerank_eval/` (metrics.py, rerankers.py, evaluate.py — `sweep()` lives in evaluate.py, there is no separate sweep.py) + `tests/unit/test_stats_rerank.py`. Results feed the dashboard's eval panel (a reranker-comparison table + nDCG-by-config chart).

## Build order (within Phase 3)
1. IR metrics (deterministic, unit-tested first — this is the money math).
2. `RerankCase` + `Reranker` protocol + `MockReranker` + synthetic golden set.
3. `evaluate` + `sweep` (winner selection + baseline delta) + audit stamping.
4. Pluggable adapters (cross-encoder, LLM-listwise, RRF) as optional, credential-gated.
5. Dashboard panel: reranker leaderboard + nDCG@k bars + latency/quality tradeoff note.

## Honest caveats (state in README)
- Off-the-shelf metric numbers are only as good as the golden set (need ~100-300 labeled queries on real data). The module makes this explicit and ships only synthetic data by default.
- "Best method" is dataset-specific; the sweep finds the best for THIS set, not universally.
