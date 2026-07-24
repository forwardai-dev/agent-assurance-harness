"""Load, verify, sign, and (de)serialize threat-content packs.

A pack on disk is a directory:

    <pack>/
      manifest.json            # name, version, kind, sources[], content_hash, signature?
      scenarios/asi-battery.json   # {"scenarios": [ ... ]}

`content_hash` is a deterministic SHA-256 over the scenarios payload; loading always
recomputes it and rejects a mismatch. An optional `signature` block (Ed25519 over the whole
manifest minus the signature, bound to content_hash) lets a producer prove authorship — the mechanism by which a
PRIVATE pack, exported from internal infra, is trusted without exposing that infra.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import SCHEMA_VERSION
from ..attack.scenario import AttackScenario
from ..audit.signer import Ed25519Signer, Ed25519Verifier
from ..core.canonical import canonical_bytes
from ..core.finding import AIVSSScore, ControlRef
from ..core.hashing import content_hash
from ..target.base import AgentRequest

PACK_SCHEMA = "aah.content-pack/v1"
_AIVSS_FIELDS = (
    "base",
    "autonomy",
    "tool_use",
    "memory",
    "multi_agent",
    "self_modification",
    "non_determinism",
)


class ContentPackError(Exception):
    """Raised when a content pack is malformed, corrupt, or fails verification."""


@dataclass(frozen=True)
class Source:
    """Provenance for one authoritative source a pack derived content from."""

    id: str  # e.g. "owasp-asi", "mitre-atlas"
    name: str
    version: str  # the source's version/date the pack was built against
    url: str = ""
    retrieved: str = ""  # ISO date the source was last checked
    live: bool = False  # True if machine-readable + fetched; False if pinned by hand

    def to_dict(self) -> dict:
        """Return the source as a JSON-serializable dict."""
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "url": self.url,
            "retrieved": self.retrieved,
            "live": self.live,
        }


@dataclass(frozen=True)
class ContentPack:
    """A loaded, verified threat-content pack: scenarios plus signed provenance."""

    name: str
    version: str
    kind: str  # "public" | "private"
    sources: tuple[Source, ...]
    content_hash: str
    scenarios: tuple[AttackScenario, ...]
    description: str = ""
    signature: str | None = None  # hex Ed25519 signature, if signed
    signer_pubkey: str | None = None  # hex public key of the signer, if signed

    @property
    def signed(self) -> bool:
        """True if the pack carries a verified Ed25519 signature."""
        return self.signature is not None

    def provenance(self) -> dict:
        """Return a compact, JSON-serializable provenance record for the manifest/AAEO."""
        return {
            "name": self.name,
            "version": self.version,
            "kind": self.kind,
            "content_hash": self.content_hash,
            "signed": self.signed,
            "signer": self.signer_pubkey,
            "sources": [f"{s.id}@{s.version}" for s in self.sources],
        }

    def ref(self) -> str:
        """Return the short provenance reference: ``name@version#content_hash``."""
        return f"{self.name}@{self.version}#{self.content_hash}"


# ---------------------------------------------------------------------------
# (de)serialization — reused by the loader AND the private exporter
# ---------------------------------------------------------------------------
def scenario_to_dict(s: AttackScenario) -> dict:
    """Serialize an AttackScenario to a JSON-friendly dict (lossless)."""
    return {
        "id": s.id,
        "asi": s.asi,
        "title": s.title,
        "vector": s.vector,
        "requests": [
            {
                "task_id": r.task_id,
                "prompt": r.prompt,
                "context": dict(r.context),
                "allowed_tools": list(r.allowed_tools),
            }
            for r in s.requests
        ],
        "aivss": {f: getattr(s.aivss, f) for f in _AIVSS_FIELDS},
        "success_markers": list(s.success_markers),
        "benign_check": list(s.benign_check),
        "controls": [
            {"framework": c.framework, "control_id": c.control_id, "note": c.note} for c in s.controls
        ],
    }


def scenario_from_dict(d: dict) -> AttackScenario:
    """Reconstruct an AttackScenario from its dict form."""
    requests = tuple(
        AgentRequest(
            task_id=r["task_id"],
            prompt=r["prompt"],
            context=dict(r.get("context", {})),
            allowed_tools=tuple(r.get("allowed_tools", ())),
        )
        for r in d["requests"]
    )
    aivss = AIVSSScore(**{f: d["aivss"][f] for f in _AIVSS_FIELDS if f in d["aivss"]})
    controls = tuple(
        ControlRef(framework=c["framework"], control_id=c["control_id"], note=c.get("note", ""))
        for c in d.get("controls", ())
    )
    kwargs: dict[str, Any] = dict(
        id=d["id"],
        asi=d["asi"],
        title=d["title"],
        requests=requests,
        aivss=aivss,
        vector=d.get("vector", "prompt"),
        benign_check=tuple(d.get("benign_check", ())),
        controls=controls,
    )
    if "success_markers" in d:
        kwargs["success_markers"] = tuple(d["success_markers"])
    return AttackScenario(**kwargs)


def scenarios_content_hash(scenarios: list[dict]) -> str:
    """Deterministic content hash over a scenarios payload."""
    return content_hash(scenarios)


# ---------------------------------------------------------------------------
# signing
# ---------------------------------------------------------------------------
def _signable_bytes(manifest: dict, chash: str) -> bytes:
    """Canonical bytes an Ed25519 signature covers: the WHOLE manifest (minus the
    signature block) bound to the authoritative content hash — so ``kind``, ``sources``
    and ``description`` are signed too, not just name/version/content_hash. Signing only
    the identity+hash triple would let a signed *private* pack be re-labelled ``public``
    with forged ``sources`` and still verify, misattributing its provenance."""
    signable = {k: v for k, v in manifest.items() if k not in ("signature", "content_hash")}
    signable["content_hash"] = chash
    return canonical_bytes(signable)


def sign_manifest(manifest: dict, signer: Ed25519Signer) -> dict:
    """Attach an Ed25519 ``signature`` block to a manifest dict and return it."""
    sig = signer.sign(_signable_bytes(manifest, manifest["content_hash"]))
    manifest = dict(manifest)
    manifest["signature"] = {"algo": "ed25519", "public_key": signer.public_key_hex, "sig": sig}
    return manifest


def write_pack(
    dest: Any,
    *,
    name: str,
    version: str,
    kind: str,
    scenarios: list[AttackScenario],
    sources: tuple[Any, ...] = (),
    description: str = "",
    scenarios_file: str = "scenarios/asi-battery.json",
    signer: Ed25519Signer | None = None,
) -> Path:
    """Write a content pack to ``dest``, computing its hash and optionally signing it.

    This is the one place packs are produced — used by the regen script and by a private
    exporter to emit a signed pack from internal infra. Returns the pack directory.
    """
    dest = Path(dest)
    (dest / Path(scenarios_file).parent).mkdir(parents=True, exist_ok=True)
    scen = [scenario_to_dict(s) for s in scenarios]
    chash = scenarios_content_hash(scen)
    (dest / scenarios_file).write_text(
        json.dumps({"scenarios": scen}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    manifest = {
        "schema": PACK_SCHEMA,
        "name": name,
        "version": version,
        "kind": kind,
        "description": description,
        "sources": [s.to_dict() if isinstance(s, Source) else dict(s) for s in sources],
        "scenarios_file": scenarios_file,
        "content_hash": chash,
    }
    if signer is not None:
        manifest = sign_manifest(manifest, signer)
    (dest / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return dest


def discover_pack_paths(entry_points_fn: Any = None) -> list[Path]:
    """Resolve filesystem paths for packs registered under the ``aah.content_packs`` group.

    An installed private-pack package advertises its pack directory via a Python
    entry point; each entry point resolves to a path (or a callable returning one).
    ``entry_points_fn`` is injectable for testing.
    """
    if entry_points_fn is None:
        from importlib.metadata import entry_points

        def _default_entry_points() -> Any:
            return entry_points(group="aah.content_packs")

        entry_points_fn = _default_entry_points

    paths: list[Path] = []
    for ep in entry_points_fn():
        target = ep.load()
        paths.append(Path(str(target() if callable(target) else target)))
    return paths


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------
def _read_json(root: Any, name: str) -> dict:
    """Read and parse a JSON file from a pack root (Path or importlib Traversable)."""
    return json.loads((root / name).read_text(encoding="utf-8"))


def load_pack(
    path: Any,
    *,
    require_signature: bool = False,
    trusted_keys: list[str] | None = None,
) -> ContentPack:
    """Load a content pack from a directory, verifying its hash and (optional) signature.

    Args:
        path: pack directory (a ``pathlib.Path`` or importlib ``Traversable``).
        require_signature: if True, an unsigned pack is rejected.
        trusted_keys: if given, the signer's public key must be in this allow-list.

    Raises:
        ContentPackError: on a bad schema, hash mismatch, or failed signature check.
    """
    manifest = _read_json(path, "manifest.json")
    if manifest.get("schema") != PACK_SCHEMA:
        raise ContentPackError(f"unknown pack schema: {manifest.get('schema')!r}")

    payload = _read_json(path, manifest["scenarios_file"])
    scenario_dicts = payload["scenarios"]
    computed = scenarios_content_hash(scenario_dicts)
    if computed != manifest.get("content_hash"):
        raise ContentPackError(
            f"content hash mismatch: manifest={manifest.get('content_hash')} computed={computed}"
        )

    sig_block = manifest.get("signature")
    signature = signer_pubkey = None
    if sig_block:
        pub = sig_block["public_key"]
        ok = Ed25519Verifier().verify(
            _signable_bytes(manifest, computed),
            sig_block["sig"],
            pub,
        )
        if not ok:
            raise ContentPackError("invalid signature: pack does not verify against its public key")
        if trusted_keys is not None and pub not in trusted_keys:
            raise ContentPackError("untrusted signer: public key not in the trusted-keys allow-list")
        signature, signer_pubkey = sig_block["sig"], pub
    elif require_signature:
        raise ContentPackError("unsigned pack but a signature is required")

    return ContentPack(
        name=manifest["name"],
        version=manifest["version"],
        kind=manifest.get("kind", "public"),
        description=manifest.get("description", ""),
        sources=tuple(
            Source(
                id=s["id"],
                name=s["name"],
                version=s["version"],
                url=s.get("url", ""),
                retrieved=s.get("retrieved", ""),
                live=s.get("live", False),
            )
            for s in manifest.get("sources", ())
        ),
        content_hash=computed,
        scenarios=tuple(scenario_from_dict(d) for d in scenario_dicts),
        signature=signature,
        signer_pubkey=signer_pubkey,
    )


def bundled_public_root() -> Any:
    """Return the importlib path to the public pack shipped inside the wheel."""
    # nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2 -- requires-python >=3.11
    from importlib.resources import files

    return files("aah.content") / "packs" / "public"


def load_bundled_public() -> ContentPack:
    """Load the public threat-content pack that ships with this release."""
    return load_pack(bundled_public_root())


# Re-exported for callers that only need the schema string.
__all_schema__ = (PACK_SCHEMA, SCHEMA_VERSION)
