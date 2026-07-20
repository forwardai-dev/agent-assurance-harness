"""The Agent Assurance Evidence Object (AAEO) — the flagship artifact.

One portable, content-addressed record per assurance run. Its payload (manifest +
findings + scope + gate) is what gets hash-chained and signed by aah.audit. Honesty
is a required field: no AAEO may be emitted without a scope + residual-risk statement.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .. import SCHEMA_VERSION
from .finding import Finding
from .hashing import content_hash
from .manifest import RunManifest


@dataclass(frozen=True)
class ScopeStatement:
    """Mandatory honesty. Behavioral testing generates EVIDENCE, not a safety guarantee."""

    tested: str  # what WAS assessed
    not_tested: str  # what was NOT (the scope boundary)
    residual_risk: str  # plain-language residual risk
    caveats: tuple[str, ...] = (
        "Integrity != third-party attestation: the hash chain is tamper-evidence, not a trusted notary.",
        "Behavioral testing generates evidence; it does not verify the safety claims regulators demand.",
        "Frozen-corpus attack results measure robustness to a FROZEN attacker (adaptive attacks are out of scope in v1).",
    )

    def to_dict(self) -> dict:
        """Return the evidence object as a JSON-serializable dict."""
        d = asdict(self)
        d["caveats"] = list(self.caveats)
        return d


@dataclass
class AssuranceEvidenceObject:
    """The portable, signable Agent Assurance Evidence Object (AAEO)."""

    manifest: RunManifest
    findings: list[Finding]
    scope: ScopeStatement
    producers: list[str] = field(default_factory=list)  # which engines emitted findings
    gate: dict | None = None  # set by governance.gate (deterministic)
    policy: dict | None = None  # the policy dict the gate ran (embedded for offline replay)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.scope.tested or not self.scope.residual_risk:
            raise ValueError(
                "AAEO requires a non-empty scope + residual-risk statement (honesty is mandatory)."
            )

    def payload(self) -> dict:
        """The canonical, signable content (everything except the cryptographic seal)."""
        return {
            "schema_version": self.schema_version,
            "manifest": self.manifest.to_dict(),
            "manifest_fingerprint": self.manifest.fingerprint(),
            "producers": sorted(self.producers),
            "scope": self.scope.to_dict(),
            "policy": self.policy,
            "findings": [f.to_dict() for f in self.findings],
            "gate": self.gate,
        }

    def content_hash(self) -> str:
        """Return the SHA-256 hash of the object's canonical content."""
        return content_hash(self.payload())

    # ---- convenience aggregates (deterministic) ----
    def max_aivss(self) -> float:
        """Return the highest AIVSS score across all findings."""
        scores = [f.aivss.score for f in self.findings if f.aivss is not None]
        return max(scores) if scores else 0.0

    def open_findings(self) -> list[Finding]:
        """Return the findings that did not pass."""
        return [f for f in self.findings if not f.passed]

    def open_by_axis(self, axis) -> list[Finding]:
        """Return open (failing) findings on the given assurance axis."""
        return [f for f in self.open_findings() if f.axis == axis]
