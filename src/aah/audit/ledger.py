"""Hash-chained, append-only evidence ledger (generalized from Arbiter's audit trail).

Each sealed evidence entry links to the previous by hash, so any mutation of any past
entry breaks the chain — tamper-evidence, verifiable offline. The seal wraps an AAEO
payload with prev_hash, this_hash, an Ed25519 signature, and a timestamp.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.canonical import canonical_bytes
from ..core.evidence import AssuranceEvidenceObject
from ..core.hashing import sha256_hex
from .signer import Ed25519Signer, Ed25519Verifier

GENESIS = "sha256:GENESIS"


@dataclass
class Seal:
    """One hash-chained ledger entry sealing an evidence object."""

    payload: dict  # the AAEO payload (canonical, signed)
    prev_hash: str
    timestamp: str
    public_key_hex: str
    signature: str = ""  # Ed25519 over the pre-seal bytes
    this_hash: str = ""  # sha256 over the pre-seal bytes

    def _presign_dict(self) -> dict:
        return {
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "public_key_hex": self.public_key_hex,
        }

    def presign_bytes(self) -> bytes:
        """Return the canonical bytes signed for this seal (prev hash + content hash)."""
        return canonical_bytes(self._presign_dict())

    def to_dict(self) -> dict:
        """Return the seal as a JSON-serializable dict."""
        return {**self._presign_dict(), "signature": self.signature, "this_hash": self.this_hash}


def seal_evidence(
    aeo: AssuranceEvidenceObject,
    signer: Ed25519Signer,
    prev_hash: str = GENESIS,
    timestamp: str = "1970-01-01T00:00:00Z",
) -> Seal:
    """Seal an evidence object into a signed, hash-chained ledger entry."""
    seal = Seal(
        payload=aeo.payload(),
        prev_hash=prev_hash,
        timestamp=timestamp,
        public_key_hex=signer.public_key_hex,
    )
    b = seal.presign_bytes()
    seal.signature = signer.sign(b)
    seal.this_hash = "sha256:" + sha256_hex(b)
    return seal


@dataclass
class HashChainLedger:
    """Append-only, hash-chained ledger of evidence seals."""

    seals: list[Seal] = field(default_factory=list)

    def head(self) -> str:
        """Return the hash of the most recent seal, or the genesis value."""
        return self.seals[-1].this_hash if self.seals else GENESIS

    def append(
        self, aeo: AssuranceEvidenceObject, signer: Ed25519Signer, timestamp: str = "1970-01-01T00:00:00Z"
    ) -> Seal:
        """Append a seal for the evidence object and return it."""
        seal = seal_evidence(aeo, signer, prev_hash=self.head(), timestamp=timestamp)
        self.seals.append(seal)
        return seal

    def verify_chain(self) -> bool:
        """Re-walk the chain: every link's prev_hash, this_hash, and signature must hold."""
        v = Ed25519Verifier()
        prev = GENESIS
        for seal in self.seals:
            if seal.prev_hash != prev:
                return False
            b = seal.presign_bytes()
            if seal.this_hash != "sha256:" + sha256_hex(b):
                return False
            if not v.verify(b, seal.signature, seal.public_key_hex):
                return False
            prev = seal.this_hash
        return True
