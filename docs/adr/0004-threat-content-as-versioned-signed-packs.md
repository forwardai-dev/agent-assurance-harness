# ADR-0004: Threat content as versioned, signed data packs (engine/content split)

- **Status:** Accepted
- **Date:** 2026-07-20
- **Deciders:** Sanju Goswami (ForwardAI)
- **Standards:** OWASP-Agentic (ASI Top 10); MITRE ATLAS; AIVSS; SBOM (versioned-content analogue)

## In plain English

The list of attacks I test for changes constantly. I didn't want to ship a whole new version of the software every time I add one. So the attacks live in separate, versioned "content packs" the tool loads — and **every result records exactly which version of attacks it ran**. When the public sources update, a bot flags it and opens a request, but a human still writes the actual attack.

## Context
The red-team battery must stay current as the threat landscape moves, without shipping a new
engine release for every new scenario — and every assurance run must record *exactly which*
threat content it tested against, or the evidence object isn't reproducible. Hardcoding
scenarios in Python couples content churn to code releases and hides what version ran.

## Decision
We will treat threat content as **data, not code**: a versioned **content pack** (a manifest
+ scenarios file) that is content-addressed by a SHA-256 over its scenarios and optionally
Ed25519-signed. The engine *loads* packs; it does not embed them. The public pack ships in
the wheel; the human-editable authoring source regenerates it (guarded by a no-drift test).
Each run records the pack ref (`name@version#hash`) in the AAEO manifest. A CI job checks the
upstream public sources (OWASP-ASI, ATLAS, AIVSS, Anthropic research) for drift and opens a
**review PR** — automation surfaces drift; a human authors the red-team.

## Consequences
- **Positive:** Content refreshes without an engine release; every evidence object pins its
  exact threat-content version (reproducibility); freshness is transparent and review-gated,
  never auto-merged into a security tool.
- **Negative / trade-offs:** A second artifact (the pack) to version and distribute; the
  authoring-source ↔ pack sync must be enforced mechanically (it is, via a test).
- **Compliance impact:** The pack's `sources[]` provenance makes the OWASP/ATLAS/AIVSS
  crosswalk auditable to a specific upstream version.

## Alternatives considered
- **Hardcoded scenarios in the engine** — couples content to releases, hides the tested
  version, and can't carry provenance. Rejected.
- **Auto-generate scenarios from prose corpus at runtime** — non-deterministic and
  unreviewable; unsafe to feed a security tool unattended. Deferred to a future, explicitly-
  labeled path.
- **Fetch content live at run time** — breaks offline determinism and reproducibility.
  Rejected; freshness happens out-of-band via the review-PR flow instead.
