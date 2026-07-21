# ADR-0007: Contract-validation is the authority over SQL CHECK constraints

- **Status:** Accepted
- **Date:** 2026-07-20
- **Deciders:** Sanju Goswami (ForwardAI)
- **Standards:** defense-in-depth; fail-closed validation

## In plain English

A database will happily accept a row that looks fine but is actually broken when the real code tries to use it. So I made one rule: **a scenario only counts as "valid" if the actual code that runs it can load it** — not just because the database accepted it. The database's own checks are a cheap first filter. That way a broken entry can never sneak into a real test.

## Context
Proprietary scenarios are curated in a database (ADR-0005) and exported to the engine. A row
can be *structurally* plausible to the database yet still fail to load as a real scenario
(e.g. `requests: [{}]` satisfies a "non-empty array" CHECK but has no `task_id`/`prompt`;
`aivss: {"base": 0}` has the required key but a meaningless score). If a malformed row reached
export, it would silently weaken the battery or break a consumer's run.

## Decision
We will make the **Python contract (`scenario_from_dict`) the single source of truth** for
whether a scenario is valid: a row is marked `validated = true` **only if it loads cleanly
through that contract** — the exact code path the engine and exporter use. SQL CHECK
constraints remain as a cheap structural *floor* at insert time, but they are not the
authority. The export view exposes only `enabled AND validated` rows, so a CHECK-passing /
contract-failing row can never reach the exporter. This is defense-in-depth with a clear
owner, not two competing validators.

## Consequences
- **Positive:** Validation matches reality — a scenario is "valid" iff the consuming code can
  actually load it. Malformed curation is caught before export and is easy to test (drive the
  validator with a CHECK-passing/contract-failing row and assert it stays hidden).
- **Negative / trade-offs:** Validity now depends on importing the engine's contract in the
  curation tooling (a deliberate coupling — the DB layer references the real schema rather
  than re-encoding it in SQL and risking drift).
- **Compliance impact:** Fail-closed by construction; the export view is a least-exposure
  surface (only validated rows, only the contract columns).

## Alternatives considered
- **SQL CHECK constraints as the authority** — cannot express the real load contract
  (nested-field requirements, semantic ranges) and would drift from the code. Rejected as the
  authority; kept as a floor.
- **Validate only at export time** — leaves invalid rows silently marked usable in the base
  table until an export runs. Rejected in favor of validating on write + re-validating on
  refresh.
