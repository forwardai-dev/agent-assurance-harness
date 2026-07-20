from aah.eval.leakage_linter import lint_golden
from aah.eval.statistics import bootstrap_ci, mcnemar, pass_at_k, pass_hat_k
from aah.rerank_eval import metrics as M
from aah.rerank_eval.evaluate import RerankCase, sweep
from aah.rerank_eval.rerankers import IdentityReranker, OracleMockReranker


def test_pass_hat_k_vs_pass_at_k():
    trials = [[True, True], [True, False], [False, False]]
    assert pass_hat_k(trials) == round(1 / 3, 4)  # all-pass only for task 0
    assert pass_at_k(trials) == round(2 / 3, 4)  # any-pass for tasks 0,1


def test_bootstrap_is_seed_deterministic():
    xs = [True, True, False, True, False, True, True, False]
    assert bootstrap_ci(xs, seed=42) == bootstrap_ci(xs, seed=42)
    p, lo, hi = bootstrap_ci(xs, seed=42)
    assert lo <= p <= hi


def test_mcnemar_flags_significant_regression():
    base = [True] * 20
    cand = [False] * 12 + [True] * 8  # 12 regressions, 0 improvements
    res = mcnemar(base, cand)
    assert res["regressions"] == 12 and res["significant"] is True
    assert mcnemar(base, base)["significant"] is False


def test_leakage_linter_blocks_contaminated_and_uncited():
    corpus = ["the quick brown fox jumps over the lazy dog every single morning"]
    items = [
        {
            "id": "clean",
            "text": "an entirely novel unrelated sentence about turbines",
            "provenance": "internal-2026",
        },
        {
            "id": "leaked",
            "text": "the quick brown fox jumps over the lazy dog every single morning",
            "provenance": "x",
        },
        {"id": "nocite", "text": "some new text", "provenance": ""},
        {"id": "canary", "text": "contains CANARY-DO-NOT-TRAIN token", "provenance": "y"},
    ]
    reps = {r.item_id: r for r in lint_golden(items, corpus)}
    assert reps["clean"].leaked is False
    assert reps["leaked"].leaked is True
    assert reps["nocite"].leaked is True
    assert reps["canary"].leaked is True


def test_ndcg_identity_vs_oracle():
    ranked_bad = ["d3", "d4", "d1", "d2"]  # relevant d1,d2 buried
    relevant = {"d1", "d2"}
    ideal = ["d1", "d2", "d3", "d4"]
    assert M.ndcg_at_k(ideal, relevant, 4) == 1.0
    assert M.ndcg_at_k(ranked_bad, relevant, 4) < 1.0
    assert M.recall_at_k(ranked_bad, relevant, 2) == 0.0
    assert M.mrr(ranked_bad, relevant) == round(1 / 3, 4)


def test_sweep_picks_best_reranker_over_baseline():
    cases = [
        RerankCase("q1", ["d3", "d4", "d1", "d2"], {"d1", "d2"}),
        RerankCase("q2", ["b2", "b3", "b1"], {"b1"}),
    ]
    rel = {"q1": {"d1", "d2"}, "q2": {"b1"}}
    rerankers = {
        "identity": IdentityReranker(),
        "oracle": OracleMockReranker(relevant_by_query=rel, strength=1.0),
    }
    res = sweep(cases, rerankers, metric="ndcg", k=10)
    assert res.winner.name == "mock-oracle"
    assert res.win_margin > 0  # beats the no-rerank baseline
    findings = res.to_findings(k=10)
    assert findings[0].metrics["is_winner"] is True


def test_partial_strength_oracle_is_between_identity_and_perfect():
    from aah.rerank_eval.evaluate import evaluate

    cases = [RerankCase("q1", ["d3", "d4", "d1", "d2"], {"d1", "d2"})]
    rel = {"q1": {"d1", "d2"}}
    identity = evaluate(cases, IdentityReranker(), k=10).ndcg
    partial = evaluate(cases, OracleMockReranker(relevant_by_query=rel, strength=0.5), k=10).ndcg
    perfect = evaluate(cases, OracleMockReranker(relevant_by_query=rel, strength=1.0), k=10).ndcg
    assert identity <= partial <= perfect


def test_reciprocal_rank_fusion_reranks_deterministically():
    from aah.rerank_eval.evaluate import evaluate
    from aah.rerank_eval.rerankers import ReciprocalRankFusion

    cases = [RerankCase("q1", ["d1", "d2", "d3"], {"d1"})]
    rrf = ReciprocalRankFusion(lists={})
    r1 = rrf.rerank("q1", ["d1", "d2", "d3"])
    r2 = rrf.rerank("q1", ["d1", "d2", "d3"])
    assert r1 == r2  # deterministic
    assert evaluate(cases, rrf, k=10).ndcg > 0.0
