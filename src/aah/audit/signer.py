"""Signing over canonical bytes. Ed25519 by default (offline, local keys).

A Signer/Verifier protocol keeps this pluggable; the default uses `cryptography`.
Signatures make the evidence re-verifiable without trusting the producer's tooling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class Signer(Protocol):
    def sign(self, data: bytes) -> str:
        """Sign the given bytes and return the signature."""
        ...

    @property
    def public_key_hex(self) -> str:
        """Return the signer's public key as hex."""
        ...


class Verifier(Protocol):
    def verify(self, data: bytes, signature_hex: str, public_key_hex: str) -> bool:
        """Return True if the signature is valid for the bytes and public key."""
        ...


@dataclass
class Ed25519Signer:
    """Ed25519 implementation of the signing protocol."""

    _private: Ed25519PrivateKey

    @classmethod
    def generate(cls, seed: int | None = None) -> Ed25519Signer:
        """Generate a new random Ed25519 signer."""
        if seed is not None:
            # deterministic key from a 32-byte seed (tests/reproducibility)
            raw = seed.to_bytes(32, "big", signed=False)
            return cls(Ed25519PrivateKey.from_private_bytes(raw))
        return cls(Ed25519PrivateKey.generate())

    def sign(self, data: bytes) -> str:
        """Sign the bytes with the Ed25519 private key."""
        return self._private.sign(data).hex()

    @property
    def public_key_hex(self) -> str:
        """Return the public key as hex."""
        from cryptography.hazmat.primitives import serialization

        raw = self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()


class Ed25519Verifier:
    """Ed25519 implementation of the verification protocol."""

    def verify(self, data: bytes, signature_hex: str, public_key_hex: str) -> bool:
        """Verify an Ed25519 signature against the public key."""
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            pub.verify(bytes.fromhex(signature_hex), data)
            return True
        except (InvalidSignature, ValueError):
            return False
