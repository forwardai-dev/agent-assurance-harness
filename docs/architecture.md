# Architecture

```
 target agent (mock | http | subprocess | Arbiter)
        │  runs suites
        ▼
 aah.eval  ─┐   deterministic scorers + pass^k/CI/McNemar + leakage linter
 aah.attack ┤→  Finding[]  (ASI-tagged, AIVSS-scored, one common schema)
 aah.rerank ┘   IR metrics + reranker sweep
        │
        ▼
 aah.governance.gate   PURE deterministic policy evaluation  →  PASS / FAIL
        │
        ▼
 aah.core.evidence  →  AAEO payload (manifest + findings + scope + policy + gate)
        │
        ▼
 aah.audit  →  Ed25519-signed, hash-chained seal   →   evidence.json
        │                                              aah.report → dashboard.html
        ▼
 aah.verify  ←  auditor re-verifies OFFLINE from the artifact alone
```
Offline-first: `aah.target` and `aah.llm` default to deterministic mocks, so the full
suite and `aah run` execute with zero API keys. Real targets/judges/producers plug in
behind Protocols as optional extras.
