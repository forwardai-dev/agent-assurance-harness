# Architecture Decision Records

Each ADR captures one load-bearing decision behind `aah` — the context, the choice, its
consequences, and (most importantly) the **alternatives we rejected and why**. They exist so
a reader can reconstruct the reasoning, not just the result.

| ADR | Decision |
|---|---|
| [0001](0001-offline-evidence-standard-not-a-harness.md) | Ship an offline-verifiable evidence **standard**, not a unified harness |
| [0002](0002-deterministic-gate-no-llm-in-money-path.md) | Deterministic policy gate — **no LLM judge in the money-path** |
| [0003](0003-ed25519-hash-chain-tamper-evidence.md) | Ed25519 signatures + hash-chained ledger for tamper-evidence |
| [0004](0004-threat-content-as-versioned-signed-packs.md) | Threat content as versioned, signed **data packs** (engine/content split) |
| [0005](0005-private-content-never-crosses-only-signed-packs.md) | Proprietary content stays private — **only signed packs cross** |
| [0006](0006-frozen-v1-attack-corpus-honestly-labeled.md) | Frozen v1 attack corpus, **honestly labeled** (adaptive = v2) |
| [0007](0007-contract-validation-authority-over-sql-checks.md) | Contract-validation is the authority over SQL CHECK constraints |

Format follows the standard ADR shape (Context / Decision / Consequences / Alternatives).
New decision → copy the shape, add the next number, link it here.
