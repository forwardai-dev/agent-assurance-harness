"""RunManifest — the pins that make an assurance run reproducible.

Everything the deterministic gate needs to re-run to the identical decision:
model id + version, seed(s), harness version, dataset/fixture hash, policy version,
and the tool/MCP manifest of the system-under-test.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .. import SCHEMA_VERSION, __version__
from .hashing import content_hash


@dataclass(frozen=True)
class RunManifest:
    """Reproducibility manifest describing how a run was produced."""

    sut_name: str  # system-under-test name
    model_id: str  # e.g. "mock:scripted-v1" or "claude-opus-4-8"
    seed: int
    harness_version: str = __version__
    schema_version: str = SCHEMA_VERSION
    policy_version: str = "unset"
    dataset_hash: str = "sha256:0"  # hash of the fixtures/goldens used
    tool_manifest: tuple[str, ...] = ()  # tool/MCP ids exposed to the agent
    created_at: str = "1970-01-01T00:00:00Z"  # stamped by caller; fixed default keeps tests deterministic

    def to_dict(self) -> dict:
        """Return the manifest as a JSON-serializable dict."""
        d = asdict(self)
        d["tool_manifest"] = list(self.tool_manifest)
        return d

    def fingerprint(self) -> str:
        """Content hash of the manifest — the reproducibility key."""
        return content_hash(self.to_dict())
