# ADR-0001: Ship an offline-verifiable evidence *standard*, not a unified harness

- **Status:** Accepted
- **Date:** 2026-07-19
- **Deciders:** Sanju Goswami (ForwardAI)
- **Standards:** SLSA, in-toto, SBOM (provenance analogues); OWASP-Agentic; NIST AI RMF

## In plain English

If I just built another testing tool, I'd be fighting well-funded companies on their own turf and losing. So I flipped it: instead of a tool, I built a standard — a signed "receipt" for an AI safety test that anyone can re-check themselves, offline, without taking my word for it. **That's the one thing a big cloud vendor can't copy**, because letting you verify without them would kill their own lock-in.

## Context
The obvious framing for an eval + security + governance tool is a "unified harness."
That framing is table-stakes — promptfoo, DeepTeam, garak, DeepEval and Inspect already
ship eval + red-team + OWASP mapping — and it collapses on contact as "just a wrapper"
around engines other people maintain. A solo-authored wrapper competing with funded
platforms on breadth loses by definition. The project needs a defensible core that a
hosted incumbent *structurally cannot* copy.

## Decision
We will position the product as a **standard**: the **Agent Assurance Evidence Object
(AAEO)** — a portable, signed, hash-chained record emitted once per assurance run, pinning
model / seed / harness-version / dataset-hash / policy-version plus every per-check result —
together with a gate that emits it. The load-bearing property is **vendor-neutral offline
attestation**: an auditor re-verifies the evidence **air-gapped, from the artifact alone,
with no network** (tamper-evidence); authorship is a separate check against a producer key
the verifier pins (`aah verify --trusted-key`). Existing tools become pluggable
*producers* that emit *into* the AAEO via a common `Finding` schema. Think "SLSA / SBOM /
in-toto, for agent assurance."

## Consequences
- **Positive:** Independence stops being a solo-dev liability and becomes the whole point —
  a SaaS incumbent can't ship a "re-verify-without-me" artifact without cannibalizing its own
  lock-in. The standard wraps engines instead of rebuilding them, so breadth is additive.
- **Negative / trade-offs:** "Standard" is a harder story to tell than "tool"; adoption
  depends on the evidence object being genuinely useful, not just novel. Bus-factor risk on a
  solo standard is real (mitigation: a working-group home — OWASP-GenAI / AIVSS).
- **Compliance impact:** Aligns the artifact with provenance norms (SLSA/in-toto) auditors
  already understand; the crosswalk to OWASP-ASI / NIST is mechanical, not hand-attested.

## Alternatives considered
- **Unified harness (the default)** — table-stakes, reads as a wrapper, undefendable by a
  solo author against funded incumbents. Rejected as the *headline* (we still unify, we just
  don't lead with it).
- **Hosted SaaS assurance platform** — would deliver the same reports but forecloses the one
  differentiator (offline re-verification) and demands an SLA/bus-factor a solo project can't
  honor. Rejected.
