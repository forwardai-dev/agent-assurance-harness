"""Offline, air-gapped verification — the whole point of the standard.

Given ONLY a sealed evidence artifact, re-verify it with no network and WITHOUT trusting
the producer's tooling:
  1. INTEGRITY  — recompute the content hash and verify the Ed25519 signature.
  2. DECISION   — re-run the deterministic gate over the recorded findings + embedded
                  policy, and confirm it matches the recorded verdict.
Any byte mutated in the payload breaks (1); any tampering with a finding to flip the
verdict breaks (2). Independence stops being a liability and becomes the guarantee.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..audit.signer import Ed25519Verifier
from ..core.canonical import canonical_bytes
from ..core.finding import Finding
from ..core.hashing import sha256_hex
from ..governance.gate import evaluate_gate
from ..governance.policy import Policy


@dataclass(frozen=True)
class VerifyResult:
    """Result of offline-verifying an evidence object."""

    integrity_ok: bool
    signature_ok: bool
    decision_ok: bool
    recorded_verdict: str
    replayed_verdict: str
    reasons: tuple[str, ...] = ()
    #: Tri-state on purpose. True = the seal was signed by a key the VERIFIER pinned.
    #: False = signed by a key outside the allow-list. None = no allow-list was given,
    #: so authorship is simply unknown. None is NOT a pass: a signature verified against
    #: a key carried inside the artifact proves only that whoever wrote it also signed it.
    authenticity_ok: bool | None = None
    #: True when the seal was signed by the PUBLISHED demo key (seed=1). Anyone can
    #: reproduce that key, so pinning it proves reproducibility, never authorship — it
    #: must not read as a full VERIFIED even when the verifier "pins" it.
    demo_key: bool = False

    @property
    def ok(self) -> bool:
        """True only when integrity, authorship and the decision replay all hold.

        `authenticity_ok is None` (no trust anchor supplied) deliberately fails this.
        The standard's claim is offline re-verification "without trusting the producer";
        self-asserted authorship cannot deliver that, so it must not read as VERIFIED.
        A signature under the published demo key (`demo_key`) also fails this: a key
        anyone can regenerate authenticates no one, so pinning it is not authorship.
        """
        return (
            self.integrity_ok
            and self.signature_ok
            and self.decision_ok
            and self.authenticity_ok is True
            and not self.demo_key
        )

    @property
    def tamper_evident(self) -> bool:
        """The weaker property that holds without a trust anchor: the bytes are intact
        and the recorded decision replays. Says nothing about WHO produced them."""
        return self.integrity_ok and self.signature_ok and self.decision_ok


#: The signing key `runner.py` uses by default is derived from seed=1, which is published
#: in this repository. Anyone can reproduce it, so a signature under it authenticates
#: nobody. Artifacts carrying it are labelled rather than silently trusted.
DEMO_KEY_SEED = 1


def _demo_public_key_hex() -> str:
    from ..audit.signer import Ed25519Signer

    return Ed25519Signer.generate(seed=DEMO_KEY_SEED).public_key_hex


def verify_seal(seal: dict, trusted_keys: list[str] | None = None) -> VerifyResult:
    """seal = Seal.to_dict() (payload + prev_hash + timestamp + public_key_hex + signature + this_hash)."""
    reasons: list[str] = []

    # This verifies UNTRUSTED input, so a malformed seal must fail cleanly, not raise.
    required = ("payload", "prev_hash", "timestamp", "public_key_hex", "signature", "this_hash")
    missing = [k for k in required if k not in seal]
    if missing:
        return VerifyResult(
            integrity_ok=False,
            signature_ok=False,
            decision_ok=False,
            recorded_verdict="UNKNOWN",
            replayed_verdict="UNKNOWN",
            reasons=(f"malformed seal: missing required field(s) {missing}",),
            authenticity_ok=None,
        )

    presign = {
        "payload": seal["payload"],
        "prev_hash": seal["prev_hash"],
        "timestamp": seal["timestamp"],
        "public_key_hex": seal["public_key_hex"],
    }
    b = canonical_bytes(presign)

    integrity_ok = seal.get("this_hash") == "sha256:" + sha256_hex(b)
    if not integrity_ok:
        reasons.append("content hash mismatch: the artifact was mutated after sealing")

    signature_ok = Ed25519Verifier().verify(b, seal.get("signature", ""), seal["public_key_hex"])
    if not signature_ok:
        reasons.append("signature invalid: not signed by the recorded key")

    payload = seal["payload"]
    recorded = (payload.get("gate") or {}).get("verdict", "UNKNOWN")
    decision_ok = True
    replayed = recorded
    if payload.get("policy") is not None:
        findings = [Finding.from_dict(f) for f in payload.get("findings", [])]
        policy = Policy.from_dict(payload["policy"])
        replayed = evaluate_gate(findings, policy).verdict
        decision_ok = replayed == recorded
        if not decision_ok:
            reasons.append(f"decision replay mismatch: recorded={recorded} replayed={replayed}")
    else:
        reasons.append("no embedded policy: decision could not be independently replayed")
        decision_ok = False

    # --- AUTHORSHIP -------------------------------------------------------------
    # Without an allow-list supplied by the VERIFIER, the only key available is the one
    # inside the artifact — which an author of a forgery controls completely.
    seal_key = (seal.get("public_key_hex") or "").lower()
    if trusted_keys is None:
        authenticity_ok = None
        reasons.append(
            "authorship UNVERIFIED: no trusted key supplied, so the signature was checked "
            "against a key carried inside the artifact. Pass --trusted-key <hex> to prove "
            "who produced it."
        )
    else:
        allow = {k.strip().lower() for k in trusted_keys if k and k.strip()}
        authenticity_ok = seal_key in allow
        if not authenticity_ok:
            reasons.append(
                "untrusted signer: the sealing key is not in the trusted-keys allow-list"
                if allow
                else "untrusted signer: an empty trusted-keys allow-list trusts no one"
            )

    used_demo_key = bool(seal_key) and seal_key == _demo_public_key_hex().lower()
    if used_demo_key:
        reasons.append(
            "signed with the PUBLISHED demo key (seed=1 in runner.py): reproducible by "
            "anyone, so it attests reproducibility, not authorship — pinning it does NOT "
            "prove who produced the artifact"
        )

    return VerifyResult(
        integrity_ok,
        signature_ok,
        decision_ok,
        recorded,
        replayed,
        tuple(reasons),
        authenticity_ok,
        demo_key=used_demo_key,
    )
