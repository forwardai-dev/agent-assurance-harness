"""The forgery the harness could not catch, and the trust anchor that catches it.

THE DEFECT (found 2026-07-22 by a council rerun, confirmed in source):

    verifier.py:57
    signature_ok = Ed25519Verifier().verify(b, seal["signature"], seal["public_key_hex"])

The public key is read from the artifact being verified. There is no trust anchor, and
`aah verify` exposes no --trusted-key (that flag exists only for content packs). So an
attacker generates any keypair, builds a self-consistent PASS bundle, signs it, embeds
their own public key, and verification reports VERIFIED.

WHY demo.sh MISSES IT: the demo forges by MUTATING a real artifact, which breaks the
content hash and the recorded signature. That demonstrates TAMPER-EVIDENCE. It never
constructs a fresh artifact with a fresh key, which is what AUTHENTICITY requires.
Both properties are real; only one was implemented, and the README claimed both:

    "an auditor re-verifies the evidence air-gapped, from the artifact alone, with no
     network and without trusting the producer"

Signature-by-self-asserted-key cannot deliver "without trusting the producer".

THE FIX, in the fail-closed spirit of the rest of the standard: verification never
claims more than it can prove.
  - no trusted key supplied -> authenticity is UNVERIFIED, and the result must not
    read as a full verification, however intact the bytes are.
  - trusted key supplied     -> the seal's key must match, or verification FAILS.
"""

from __future__ import annotations

from aah.audit.signer import Ed25519Signer
from aah.core.canonical import canonical_bytes
from aah.core.hashing import sha256_hex
from aah.governance.policy import Policy
from aah.verify.verifier import verify_seal


def _seal_with(signer: Ed25519Signer, verdict: str = "PASS") -> dict:
    """Build a fully self-consistent seal signed by `signer`.

    Nothing here is mutated after signing, so integrity and decision replay both hold.
    This is a FORGERY, not a tampering: the attacker authors the artifact from scratch.
    """
    # A real policy is load-bearing: without one the verifier refuses the decision
    # replay, and the forgery fails for the WRONG reason. With an empty finding set the
    # default policy legitimately replays to PASS, so the artifact is internally sound
    # and only its AUTHORSHIP is in question — which is the actual attack.
    payload = {
        "gate": {"verdict": verdict},
        "findings": [],
        "policy": Policy.from_dict({}).to_dict(),
        "target": "totally-legit-agent",
    }
    presign = {
        "payload": payload,
        "prev_hash": "sha256:" + "0" * 64,
        "timestamp": "2026-07-22T00:00:00Z",
        "public_key_hex": signer.public_key_hex,
    }
    b = canonical_bytes(presign)
    seal = dict(presign)
    seal["signature"] = signer.sign(b)
    seal["this_hash"] = "sha256:" + sha256_hex(b)
    return seal


# ---------------------------------------------------------------------------
# the forgery
# ---------------------------------------------------------------------------


def test_a_forged_pass_signed_by_an_attacker_key_is_not_reported_as_verified():
    """The headline defect. An attacker's own key must not confer authenticity."""
    attacker = Ed25519Signer.generate(seed=999999)
    forged = _seal_with(attacker, verdict="PASS")

    res = verify_seal(forged)

    # Integrity legitimately holds — the attacker never mutated anything.
    assert res.integrity_ok, "the forgery is internally consistent by construction"
    # But with no trust anchor, authenticity is unproven and `ok` must not be True.
    assert not res.ok, (
        "a self-signed forgery reported as VERIFIED — the artifact proves only that "
        "whoever authored it also signed it"
    )


def test_authenticity_is_reported_as_unverified_without_a_trusted_key():
    signer = Ed25519Signer.generate(seed=1)
    seal = _seal_with(signer)
    res = verify_seal(seal)
    assert res.authenticity_ok is None, "no trust anchor means authenticity is unknown, not OK"
    assert any("trust anchor" in r.lower() or "trusted key" in r.lower() for r in res.reasons)


# ---------------------------------------------------------------------------
# the trust anchor
# ---------------------------------------------------------------------------


def test_matching_trusted_key_fully_verifies():
    # A REAL producer key (not the published seed=1 demo key) → full authorship.
    signer = Ed25519Signer.generate(seed=42)
    seal = _seal_with(signer)
    res = verify_seal(seal, trusted_keys=[signer.public_key_hex])
    assert res.authenticity_ok is True
    assert not res.demo_key
    assert res.ok, res.reasons


def test_pinning_the_published_demo_key_is_not_authorship():
    # Pinning the seed=1 demo key must NOT read as VERIFIED: anyone can regenerate it.
    demo = Ed25519Signer.generate(seed=1)
    seal = _seal_with(demo)
    res = verify_seal(seal, trusted_keys=[demo.public_key_hex])
    assert res.demo_key is True
    assert res.tamper_evident  # integrity + decision still hold
    assert not res.ok, "a published demo key proves reproducibility, not authorship"
    assert any("demo key" in r.lower() for r in res.reasons)


def test_forgery_is_rejected_when_the_real_key_is_pinned():
    """The attack, with the defence engaged."""
    real = Ed25519Signer.generate(seed=1)
    attacker = Ed25519Signer.generate(seed=999999)
    forged = _seal_with(attacker, verdict="PASS")

    res = verify_seal(forged, trusted_keys=[real.public_key_hex])

    assert res.authenticity_ok is False
    assert not res.ok
    assert any("untrusted" in r.lower() or "not in the trusted" in r.lower() for r in res.reasons)


def test_trusted_key_list_accepts_any_listed_signer():
    a = Ed25519Signer.generate(seed=1)
    b = Ed25519Signer.generate(seed=2)
    seal = _seal_with(b)
    res = verify_seal(seal, trusted_keys=[a.public_key_hex, b.public_key_hex])
    assert res.authenticity_ok is True and res.ok


def test_empty_trusted_key_list_is_not_treated_as_no_anchor():
    """An explicit empty allow-list trusts nobody. It must not silently mean 'skip'."""
    signer = Ed25519Signer.generate(seed=1)
    seal = _seal_with(signer)
    res = verify_seal(seal, trusted_keys=[])
    assert res.authenticity_ok is False
    assert not res.ok


# ---------------------------------------------------------------------------
# tamper-evidence must not regress
# ---------------------------------------------------------------------------


def test_mutation_after_sealing_still_breaks_integrity():
    signer = Ed25519Signer.generate(seed=1)
    seal = _seal_with(signer, verdict="FAIL")
    seal["payload"]["gate"]["verdict"] = "PASS"  # the demo.sh attack
    res = verify_seal(seal, trusted_keys=[signer.public_key_hex])
    assert not res.integrity_ok and not res.ok


def test_signature_by_a_different_key_than_recorded_still_fails():
    signer = Ed25519Signer.generate(seed=1)
    other = Ed25519Signer.generate(seed=2)
    seal = _seal_with(signer)
    seal["public_key_hex"] = other.public_key_hex  # claim a key that did not sign
    res = verify_seal(seal)
    assert not res.signature_ok


# ---------------------------------------------------------------------------
# the demo key must announce itself
# ---------------------------------------------------------------------------


def test_the_published_demo_key_is_flagged():
    """runner.py signs with Ed25519Signer.generate(seed=1) — a key published in the
    source. Anyone can produce a signature indistinguishable from the real producer's,
    so an artifact signed with it must say so rather than look authoritative."""
    demo = Ed25519Signer.generate(seed=1)
    seal = _seal_with(demo)
    res = verify_seal(seal, trusted_keys=[demo.public_key_hex])
    assert any("demo" in r.lower() or "published" in r.lower() for r in res.reasons), (
        "an artifact signed with the published demo key must be labelled as such"
    )
