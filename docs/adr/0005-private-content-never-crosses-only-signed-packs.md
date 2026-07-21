# ADR-0005: Proprietary content stays private — only signed packs cross the boundary

- **Status:** Accepted
- **Date:** 2026-07-20
- **Deciders:** Sanju Goswami (ForwardAI)
- **Standards:** OWASP-Agentic (ASI04 supply chain); least-privilege / data-boundary practice

## In plain English

If a client keeps their own private list of attacks in a database, I never want my public tool touching that database — that's a security and privacy nightmare. So **the only thing that ever leaves their walls is one signed file**. My tool checks the signature and runs; it never sees the database. And I'm upfront about one thing: signing proves the file wasn't tampered with — it does NOT hide the contents — so that file still only goes to people allowed to see it.

## Context
An operator may maintain a private, continually-updated corpus of proprietary threat
scenarios (in an internal database). The public engine must be able to run against that
content **without** the engine — or the public repo — ever gaining access to the private
store. A live database connection in the assessment path would both leak infrastructure into
a public tool and destroy offline determinism (ADR-0002).

## Decision
We will make the **signed content pack the only thing that crosses** the public/private
boundary. A private exporter (which lives outside the public repo) reads the internal source,
signs a pack with an Ed25519 key held only in the operator's infrastructure, and hands over
the portable signed pack. The public engine verifies the signature (and, with a trusted-key
allow-list, the signer) and runs — the database is never reachable from the engine. Crucially:
**a signed pack protects integrity, not confidentiality** (its scenarios are readable), so
distribution of the pack itself is the operator's call; the engine only guarantees it wasn't
tampered with and came from a trusted signer.

## Consequences
- **Positive:** Proprietary intel powers the public engine with zero infrastructure coupling;
  the offline-verify property is preserved because no live dependency enters the money-path.
- **Negative / trade-offs:** Signing ≠ encryption — operators must treat the pack as readable
  and distribute it only to authorized consumers; key hygiene (secret-manager storage,
  rotation) becomes the operator's responsibility.
- **Compliance impact:** Enforces a clean data boundary; the trust anchor (signer public key)
  is the only shared artifact, and it carries no secret.

## Alternatives considered
- **Engine connects to the private DB directly** — leaks credentials/topology into a public
  tool and breaks offline determinism. Rejected outright.
- **Encrypt the pack for confidentiality** — out of scope for v1 and orthogonal to the
  integrity guarantee; operators who need it can layer transport encryption on distribution.
  Deferred.
