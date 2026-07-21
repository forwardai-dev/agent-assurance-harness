# ADR-0002: Deterministic policy gate — no LLM judge in the money-path

- **Status:** Accepted
- **Date:** 2026-07-19
- **Deciders:** Sanju Goswami (ForwardAI)
- **Standards:** NIST AI RMF (MEASURE/MANAGE); reproducible-build principles

## In plain English

A lot of tools let one AI grade whether another AI passed. The problem: ask it twice, you can get two answers — you can't reproduce or audit that. So the pass/fail decision in my system is plain, boring math over fixed inputs: **same evidence in, same verdict out, every single time**. An AI can suggest a score, but it never gets to be the judge that actually decides.

## Context
Much of the eval market (LLM-as-judge tooling) puts a model in the position of *deciding*
pass/fail. A non-deterministic decider means the same evidence can gate differently on two
runs, and the CI outcome can't be reproduced or audited. For an artifact whose entire value
is offline re-verification (ADR-0001), a decision that can't be replayed is worthless — an
auditor re-running the gate must arrive at the identical verdict.

## Decision
We will make the gate a **pure deterministic function of pinned inputs**: `verdict =
f(findings, policy)`, with no network and no model call in the decision path. An LLM judge
may *produce a scored signal* that a policy reads (e.g. a rubric score compared against a
threshold), but it is **never the decider**. The recorded verdict is re-derivable by anyone
holding the evidence object and the policy — "decision replay" is a first-class verification
step alongside hash-integrity and signature.

## Consequences
- **Positive:** The verdict is reproducible and forgery-evident: replay recomputes the truth
  even if the producer *claims* a different verdict. Enables the demo's third catch
  (recorded=PASS vs replayed=FAIL).
- **Negative / trade-offs:** Nuanced, fuzzy judgments (tone, subtle helpfulness) can't be the
  *gate*; they can only inform a policy threshold. Richer judged evaluation is deferred to a
  v2 "judged track" with an explicit bias / κ-qualification harness.
- **Compliance impact:** Satisfies the reproducibility auditors expect; keeps the money-path
  free of the model-nondeterminism that makes LLM-judge gates non-auditable.

## Alternatives considered
- **LLM-judge decides pass/fail** — the market-common posture (Galileo/DeepEval/Braintrust
  lean judge-heavy). Rejected: non-reproducible, un-auditable, and directly contradicts the
  offline-verify thesis.
- **Judge decides, but cache the score** — still bakes a non-deterministic artifact into the
  gate and invites contamination/version drift. Rejected in favor of policy-reads-a-signal.
