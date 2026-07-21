# ADR-0006: Frozen v1 attack corpus, honestly labeled (adaptive = v2)

- **Status:** Accepted
- **Date:** 2026-07-19
- **Deciders:** Sanju Goswami (ForwardAI)
- **Standards:** OWASP-Agentic (ASI Top 10); MITRE ATLAS; Anthropic sabotage/monitor evals

## In plain English

The strongest security test adapts to the target as it goes. I don't do that yet — v1 uses a fixed set of attacks. The honest move is to say so plainly, because passing a fixed test means **"it survived these attacks," not "it's safe."** I'd rather under-claim and be trusted than oversell and get caught. The adaptive version is clearly labeled as coming later, not hidden.

## Context
An adaptive, feedback-guided red-team (attacks that mutate against the target's responses) is
the strongest form of security testing — and it is also expensive, non-deterministic, and out
of scope for a v1 built to run offline and reproducibly. The temptation is to imply adaptive
coverage the tool doesn't have. Unlabeled, a *fixed* battery gives false comfort: passing it
means "robust to *this* attacker," not "robust."

## Decision
We will ship a **frozen (fixed) attack corpus in v1 and label it as exactly that** on every
artifact. Robustness claims are scoped to "resisted a fixed attacker on the tested surface."
Adaptive / black-box generation is named explicitly as v2, not implied as present. We add
*variety* honestly instead — one obfuscation-evasion variant matrix over the base scenarios
(encoding, homoglyph, zero-width, roleplay, authority, etc.) — which tests whether a defense
*generalizes* across surfaces, while remaining a deterministic, frozen set.

## Consequences
- **Positive:** The evidence object's residual-risk statement is truthful; a PASS is not
  over-claimed. Determinism (ADR-0002) is preserved. The variant matrix adds real coverage
  without pretending to be adaptive.
- **Negative / trade-offs:** A fixed corpus can be "taught to" over time (overfitting to the
  known battery); it does not find novel attack classes. This is disclosed, not hidden.
- **Compliance impact:** Honest scoping is a feature — the mandatory residual-risk statement
  prevents the tool from being mistaken for a safety *guarantee*.

## Alternatives considered
- **Imply adaptive coverage** — dishonest and dangerous (inverts the risk signal). Rejected as
  a hard line ("do NOT" in the design brief).
- **Ship adaptive generation in v1** — non-deterministic, expensive, breaks offline
  reproducibility, and unfinished. Deferred to v2 with its own qualification harness.
