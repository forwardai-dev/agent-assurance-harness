"""Deterministic secret detection on agent traces (trufflehog-style) — ASI04 surface.

Scans a trajectory for high-signal secret patterns. Reused conceptually from Sanju's
security tooling; here it is a small, dependency-free, deterministic detector.
"""

from __future__ import annotations

import re

_PATTERNS = {
    "openai_key": re.compile(r"sk-[A-Za-z0-9]{16,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "generic_password": re.compile(r"password\s*=\s*\S+", re.I),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "bearer_token": re.compile(r"bearer\s+[A-Za-z0-9._\-]{16,}", re.I),
}


def scan_secrets(text: str) -> list[dict]:
    """Scan text for exposed secrets and return the matched patterns."""
    hits = []
    for name, rx in _PATTERNS.items():
        for m in rx.finditer(text):
            hits.append({"type": name, "match": _redact(m.group(0))})
    return hits


def _redact(s: str) -> str:
    return s[:6] + "***" if len(s) > 6 else "***"
