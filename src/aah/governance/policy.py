"""Policy-as-code — declarative rules the deterministic gate evaluates over findings.

Encodes the RSP/ASL pattern: capability-threshold -> required-control -> evidence.
Loaded from YAML; versioned so the AAEO pins exactly which policy produced the verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..core.finding import Severity


@dataclass(frozen=True)
class RequiredControl:
    """If the SUT exhibits `capability`, then finding `control_id` must PASS to ship."""

    capability: str  # e.g. "tool_use", "memory", "multi_agent"
    control_id: str  # a finding id (or asi tag) that must be present AND passed
    reason: str = ""


@dataclass(frozen=True)
class Policy:
    """Declarative assurance policy (thresholds and per-axis rules)."""

    name: str = "default"
    version: str = "v1"
    max_aivss: float = 6.9  # any finding scoring above this fails the gate
    max_open_severity: Severity = Severity.MEDIUM  # open findings STRICTLY above this fail
    fail_on_open_axes: tuple[str, ...] = ("security",)  # any open finding in these axes fails
    min_eval_pass_rate: float = 0.0  # eval axis pass-rate floor (0 disables)
    required_controls: tuple[RequiredControl, ...] = ()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Policy:
        """Build a Policy from a plain dict."""
        return cls(
            name=d.get("name", "default"),
            version=d.get("version", "v1"),
            max_aivss=float(d.get("max_aivss", 6.9)),
            max_open_severity=Severity(d.get("max_open_severity", "medium")),
            fail_on_open_axes=tuple(d.get("fail_on_open_axes", ["security"])),
            min_eval_pass_rate=float(d.get("min_eval_pass_rate", 0.0)),
            required_controls=tuple(RequiredControl(**rc) for rc in d.get("required_controls", [])),
        )

    @classmethod
    def from_yaml(cls, path: str) -> Policy:
        """Load a Policy from a YAML file."""
        import yaml

        with open(path) as fh:
            return cls.from_dict(yaml.safe_load(fh) or {})

    def to_dict(self) -> dict:
        """Return the policy as a JSON-serializable dict."""
        return {
            "name": self.name,
            "version": self.version,
            "max_aivss": self.max_aivss,
            "max_open_severity": self.max_open_severity.value,
            "fail_on_open_axes": list(self.fail_on_open_axes),
            "min_eval_pass_rate": self.min_eval_pass_rate,
            "required_controls": [
                {"capability": rc.capability, "control_id": rc.control_id, "reason": rc.reason}
                for rc in self.required_controls
            ],
        }
