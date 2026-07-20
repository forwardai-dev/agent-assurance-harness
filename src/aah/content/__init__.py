"""Versioned, provenanced threat-content packs: the ASI battery as data, not code.

The engine is separate from the threat content it runs. A **content pack** is a
versioned bundle of attack scenarios + provenance (which public sources it derived
from, at which version), content-addressed by a SHA-256 over its scenarios and
optionally **Ed25519-signed**. The public pack ships in the wheel; private packs are
loaded by path or entry-point. Nothing here ever reaches a private database — a pack
is a portable, signed artifact, which is the only thing that should ever cross the
public/private boundary.
"""

from .pack import ContentPack, ContentPackError, Source, load_bundled_public, load_pack

__all__ = [
    "ContentPack",
    "ContentPackError",
    "Source",
    "load_pack",
    "load_bundled_public",
]
