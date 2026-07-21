# ADR-0003: Ed25519 signatures + a hash-chained ledger for tamper-evidence

- **Status:** Accepted
- **Date:** 2026-07-19
- **Deciders:** Sanju Goswami (ForwardAI)
- **Standards:** in-toto / SLSA attestation; RFC 8032 (Ed25519); RFC 8785 (JCS, canonical JSON)

## In plain English

I wanted anyone to catch a faked result without having to phone home to me. So each result gets a cryptographic fingerprint and a signature. If someone edits the result to fake a "pass," the fingerprint stops matching and the signature breaks — **caught, offline, three different ways**. I used public-key signatures on purpose, so you don't need any secret from me to check it yourself.

## Context
Offline re-verification (ADR-0001) requires that a third party, holding only the artifact,
can detect any post-hoc mutation *and* confirm who produced it — with no shared secret and no
call home. The scheme must be deterministic over the object's canonical bytes so the same
logical evidence always hashes identically.

## Decision
We will content-address the evidence object with **SHA-256 over canonical JSON** (sorted
keys, tight separators — an RFC-8785-style subset) and sign that hash with **Ed25519**. Seals
are chained (each references the prior seal's hash) into an append-only ledger, so removal or
reordering is detectable, not just point mutation. Verification is three independent checks —
**integrity** (recompute the hash), **signature** (Ed25519 against the recorded public key),
and **decision replay** (ADR-0002) — any of which catches a forgery offline.

## Consequences
- **Positive:** A forged "pass" is caught three independent ways with no network and no trust
  in the producer — the headline demo. Public-key signatures mean the verifier needs no
  secret from us.
- **Negative / trade-offs:** Integrity ≠ third-party attestation — the chain proves *tamper-
  evidence*, not that a trusted notary witnessed it. This is stated as a mandatory scope
  caveat, not hidden. External timestamping (sigstore / RFC-3161) is named as v2.
- **Compliance impact:** Mirrors in-toto/SLSA provenance auditors already accept; the signer
  public key is the portable trust anchor distributed to consumers.

## Alternatives considered
- **HMAC / shared-secret MAC** — would force every verifier to hold the producer's secret,
  breaking "verify without trusting (or contacting) the producer." Rejected.
- **Trusted-notary / hosted timestamp authority in v1** — reintroduces a network dependency
  and a party to trust, contradicting offline verification. Deferred to v2 as an *optional*
  external timestamp, never the base guarantee.
- **Plain unsigned JSON + checksum** — detects accidental corruption but not authorship or
  deliberate re-signing. Rejected.
