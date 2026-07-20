# The Agent Assurance Evidence Object (AAEO)

One portable, content-addressed, signed record per assurance run — the flagship artifact.

## Structure (a sealed bundle)
```
seal:
  payload:                       # the canonical, signed content
    schema_version: aeo-v1
    manifest:                    # the reproducibility pins
      sut_name, model_id, seed, harness_version, schema_version,
      policy_version, dataset_hash, tool_manifest[], created_at
    manifest_fingerprint         # sha256 over the manifest
    producers[]                  # which engines emitted findings (aah.eval, aah.attack, ...)
    scope:                       # MANDATORY honesty
      tested, not_tested, residual_risk, caveats[]
    policy:                      # the exact policy the gate ran (embedded for offline replay)
    findings[]:                  # the common Finding schema (below)
    gate:                        # the deterministic verdict
      verdict (PASS|FAIL), policy_name, policy_version, reasons[], stats{}
  prev_hash                      # links to the previous seal in the ledger
  timestamp
  public_key_hex                 # Ed25519 public key
  signature                      # Ed25519 over the canonical pre-seal bytes
  this_hash                      # sha256 over the canonical pre-seal bytes
```

## Finding schema (one shape for eval, security, governance)
`id · axis (eval|security|governance) · title · passed · severity · asi (ASI01-10) ·
aivss{base + amplification factors → score} · controls[] (informative framework refs) ·
metrics{} · transcript_ref · detail`

## Offline verification (`aah verify`)
1. **Integrity** — recompute the canonical pre-seal bytes; assert `this_hash` matches.
2. **Signature** — verify the Ed25519 signature against the recorded public key.
3. **Decision** — reconstruct findings + policy from the payload, re-run the deterministic
   gate, and assert the replayed verdict equals the recorded verdict.

Any mutation of any byte breaks (1); any attempt to forge the verdict breaks (1) and (3).
No network, no producer trust, no vendor.

## Design law
The gate is a **pure deterministic function** of (findings, policy): no LLM, no I/O, no
clock, no randomness. A judge score may appear in a finding's metrics as a *signal* a
policy reads — it is never the decider. This is what makes the AAEO reproducible and
independently re-verifiable.
