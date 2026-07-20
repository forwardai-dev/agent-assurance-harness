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

    @property
    def ok(self) -> bool:
        """True if signature and hash chain both verified."""
        return self.integrity_ok and self.signature_ok and self.decision_ok


def verify_seal(seal: dict) -> VerifyResult:
    """seal = Seal.to_dict() (payload + prev_hash + timestamp + public_key_hex + signature + this_hash)."""
    reasons: list[str] = []

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

    return VerifyResult(integrity_ok, signature_ok, decision_ok, recorded, replayed, tuple(reasons))
