"""The common Finding record — every producer (eval, security, governance) emits these.

One normalized schema so eval regressions, security findings, and control failures
are three views of one auditable object. Every finding is ASI-tagged, AIVSS-scored,
and ATLAS-mappable by construction.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Ordered severity levels for findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Integer rank for ordering severities (higher is worse)."""
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Axis(str, Enum):
    """The assurance axis a finding belongs to (eval, security, or governance)."""

    EVAL = "eval"  # correctness
    SECURITY = "security"  # adversarial
    GOVERNANCE = "governance"


@dataclass(frozen=True)
class ControlRef:
    """An informative mapping to a framework control (NOT certification)."""

    framework: str  # e.g. "OWASP-ASI-2026", "NIST-AI-RMF", "MITRE-ATLAS"
    control_id: str  # e.g. "ASI06", "MANAGE-2.1", "AML.T0051"
    note: str = ""


@dataclass(frozen=True)
class AIVSSScore:
    """Agentic AI Risk Score: CVSS-style base + agentic amplification factors."""

    base: float  # 0.0-10.0 CVSS-style base
    autonomy: float = 0.0  # amplification factors, each 0 / 0.5 / 1.0
    tool_use: float = 0.0
    memory: float = 0.0
    multi_agent: float = 0.0
    self_modification: float = 0.0
    non_determinism: float = 0.0

    @property
    def amplification(self) -> float:
        """Agentic amplification multiplier derived from the AIVSS factors."""
        return (
            self.autonomy
            + self.tool_use
            + self.memory
            + self.multi_agent
            + self.self_modification
            + self.non_determinism
        )

    @property
    def score(self) -> float:
        """Base scaled by agentic amplification, clamped to 10.0. Deterministic."""
        factor = 1.0 + 0.1 * self.amplification  # up to +60% for 6 maxed factors
        return round(min(10.0, self.base * factor), 2)


@dataclass(frozen=True)
class Finding:
    """A single normalized assurance finding."""

    id: str  # stable id, e.g. "sec.asi06.mem-poison.001"
    axis: Axis
    title: str
    passed: bool  # did this check PASS (True) or fail/vuln (False)
    severity: Severity = Severity.INFO
    asi: str | None = None  # OWASP Agentic ASI01-ASI10 tag
    aivss: AIVSSScore | None = None
    controls: tuple[ControlRef, ...] = ()
    metrics: dict[str, Any] = field(default_factory=dict)  # scores, rates, counts
    transcript_ref: str | None = None  # replayable trajectory id
    detail: str = ""

    def to_dict(self) -> dict:
        """Return the finding as a JSON-serializable dict."""
        d = asdict(self)
        d["axis"] = self.axis.value
        d["severity"] = self.severity.value
        if self.aivss is not None:
            d["aivss"] = {**asdict(self.aivss), "score": self.aivss.score}
        d["controls"] = [asdict(c) for c in self.controls]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        """Reconstruct a Finding from its dict form."""
        aivss = None
        if d.get("aivss") is not None:
            a = {k: v for k, v in d["aivss"].items() if k != "score"}
            aivss = AIVSSScore(**a)
        controls = tuple(ControlRef(**c) for c in d.get("controls", ()))
        return cls(
            id=d["id"],
            axis=Axis(d["axis"]),
            title=d["title"],
            passed=d["passed"],
            severity=Severity(d["severity"]),
            asi=d.get("asi"),
            aivss=aivss,
            controls=controls,
            metrics=d.get("metrics", {}),
            transcript_ref=d.get("transcript_ref"),
            detail=d.get("detail", ""),
        )
