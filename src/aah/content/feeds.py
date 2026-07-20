"""Freshness adapters for the PUBLIC authoritative sources the battery derives from.

Each adapter reports the current version of one source. Some sources are machine-readable
(``live=True``: MITRE ATLAS releases, the Anthropic research listing) and are fetched +
parsed; others are documents with no machine version (``live=False``: OWASP-ASI, AIVSS)
and are **pinned by hand**, surfaced for manual review. Everything degrades gracefully
offline — a fetch failure yields the pinned version with ``ok=False`` — so the updater and
its tests run without a network.

The updater NEVER rewrites scenarios. It surfaces *source drift* (a version bump) as a
signal for a human to author new threat content. Automation finds drift; humans write the
red-team.
"""

from __future__ import annotations

import json
import re
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256

Fetcher = Callable[[str], str]

# Pinned fallbacks — kept in step with the shipped public manifest.
PINNED = {
    "owasp-asi": "2026.01",
    "mitre-atlas": "2026.05",
    "aivss": "1.0",
    "anthropic-research": "2026-07-20",
}


@dataclass(frozen=True)
class FeedRecord:
    """The freshness reading for one source: its current version and how we got it."""

    id: str
    name: str
    version: str
    url: str
    live: bool  # machine-readable + fetched vs hand-pinned
    ok: bool  # True if the reading is fresh from the source (not a pinned fallback)
    retrieved: str = ""
    note: str = ""


def default_fetcher(url: str, timeout: float = 8.0) -> str:
    """Fetch an https URL's body as text (used in CI); raises on any network error."""
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL: {url!r}")  # no file:// / custom schemes
    req = urllib.request.Request(url, headers={"User-Agent": "aah-threat-content-updater"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - https-only, guarded above
        return resp.read().decode("utf-8", errors="replace")


def _pinned(id_: str, name: str, url: str, today: str, note: str, live: bool) -> FeedRecord:
    """Build a pinned-fallback record for a source we could not read live."""
    return FeedRecord(id_, name, PINNED[id_], url, live=live, ok=False, retrieved=today, note=note)


def check_owasp_asi(fetch: Fetcher, today: str = "") -> FeedRecord:
    """OWASP Agentic Security Initiative — ASI Top 10 (document; pinned, review manually)."""
    url = "https://genai.owasp.org/initiatives/agentic-security-initiative/"
    return FeedRecord(
        "owasp-asi",
        "OWASP Agentic Security Initiative — ASI Top 10",
        PINNED["owasp-asi"],
        url,
        live=False,
        ok=True,
        retrieved=today,
        note="pinned: no machine-readable version — review the ASI Top 10 doc manually",
    )


def check_aivss(fetch: Fetcher, today: str = "") -> FeedRecord:
    """AIVSS scoring spec (document; pinned, review manually)."""
    url = "https://aivss.org/"
    return FeedRecord(
        "aivss",
        "AIVSS — Agentic AI Vulnerability Scoring System",
        PINNED["aivss"],
        url,
        live=False,
        ok=True,
        retrieved=today,
        note="pinned: track the AIVSS spec version manually",
    )


def check_mitre_atlas(fetch: Fetcher, today: str = "") -> FeedRecord:
    """MITRE ATLAS — version from the atlas-data latest GitHub release (live)."""
    url = "https://api.github.com/repos/mitre-atlas/atlas-data/releases/latest"
    name = "MITRE ATLAS (adversarial technique IDs)"
    try:
        tag = json.loads(fetch(url)).get("tag_name")
        if not tag:
            raise ValueError("no tag_name")
        version = str(tag).lstrip("v")
        return FeedRecord("mitre-atlas", name, version, "https://atlas.mitre.org/", True, True, today)
    except Exception as e:  # offline / rate-limited / shape change -> pinned fallback
        return _pinned("mitre-atlas", name, "https://atlas.mitre.org/", today, f"fetch failed: {e}", True)


def check_anthropic_research(fetch: Fetcher, today: str = "") -> FeedRecord:
    """Anthropic research catalog — version = short hash of the published slug set (live)."""
    url = "https://www.anthropic.com/research"
    name = "Anthropic Research (safety/red-team catalog)"
    try:
        slugs = sorted(set(re.findall(r"/research/([a-z0-9][a-z0-9-]+)", fetch(url))))
        if not slugs:
            raise ValueError("no research slugs found")
        digest = sha256("\n".join(slugs).encode()).hexdigest()[:8]
        version = f"{len(slugs)}:{digest}"
        return FeedRecord("anthropic-research", name, version, url, True, True, today)
    except Exception as e:
        return _pinned("anthropic-research", name, url, today, f"fetch failed: {e}", True)


ADAPTERS = (check_owasp_asi, check_aivss, check_mitre_atlas, check_anthropic_research)


def check_all(fetch: Fetcher | None = None, today: str = "") -> list[FeedRecord]:
    """Run every feed adapter and return their freshness records."""
    fetch = fetch or default_fetcher
    return [adapter(fetch, today) for adapter in ADAPTERS]


def diff_sources(manifest_sources: list[dict], records: list[FeedRecord]) -> list[dict]:
    """Return drift entries where a source's live version differs from the manifest."""
    by_id = {r.id: r for r in records}
    drift = []
    for src in manifest_sources:
        rec = by_id.get(src["id"])
        if rec is None or not rec.live:
            continue  # pinned sources never auto-drift; they are reviewed by hand
        if rec.ok and rec.version != src.get("version"):
            drift.append({"id": src["id"], "old": src.get("version"), "new": rec.version})
    return drift
