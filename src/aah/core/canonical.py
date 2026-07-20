"""Deterministic canonical JSON bytes — the basis for content-addressing.

Production target is RFC 8785 (JCS). This reference uses a strict, stable
subset (sorted keys, tight separators, UTF-8, no NaN) that is sufficient for
reproducible hashing of the evidence object. It is deterministic: the same
logical object always serializes to the same bytes.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    """Serialize obj to canonical, deterministic UTF-8 bytes."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_str(obj: Any) -> str:
    """Serialize an object to canonical, deterministic JSON text."""
    return canonical_bytes(obj).decode("utf-8")
