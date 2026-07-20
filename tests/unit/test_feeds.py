"""Threat-content freshness adapters: live parsing, offline fallback, drift detection."""

import json

import pytest

from aah.content.feeds import (
    PINNED,
    check_all,
    check_anthropic_research,
    check_mitre_atlas,
    default_fetcher,
    diff_sources,
)


def test_default_fetcher_rejects_non_https():
    with pytest.raises(ValueError, match="non-https"):
        default_fetcher("file:///etc/passwd")


def _raise(url):
    raise OSError("offline")


def test_mitre_atlas_parses_release_tag_when_live():
    fetch = lambda url: json.dumps({"tag_name": "v5.1.0"})  # noqa: E731
    rec = check_mitre_atlas(fetch, today="2026-07-20")
    assert rec.version == "5.1.0"
    assert rec.live and rec.ok
    assert rec.retrieved == "2026-07-20"


def test_mitre_atlas_falls_back_to_pinned_offline():
    rec = check_mitre_atlas(_raise, today="2026-07-20")
    assert rec.version == PINNED["mitre-atlas"]
    assert rec.live is True and rec.ok is False
    assert "fetch failed" in rec.note


def test_anthropic_research_hashes_slug_set():
    html = '<a href="/research/petri">x</a> <a href="/research/shade-arena">y</a>'
    rec = check_anthropic_research(lambda url: html, today="2026-07-20")
    assert rec.ok and rec.live
    assert rec.version.startswith("2:")  # two distinct slugs


def test_anthropic_research_falls_back_offline():
    rec = check_anthropic_research(_raise, today="2026-07-20")
    assert rec.ok is False and rec.version == PINNED["anthropic-research"]


def test_check_all_offline_returns_all_sources_pinned_for_live_ones():
    recs = check_all(fetch=_raise, today="2026-07-20")
    ids = {r.id for r in recs}
    assert ids == {"owasp-asi", "aivss", "mitre-atlas", "anthropic-research"}
    # live sources report FALLBACK offline; pinned docs still report ok
    by_id = {r.id: r for r in recs}
    assert by_id["mitre-atlas"].ok is False
    assert by_id["owasp-asi"].ok is True and by_id["owasp-asi"].live is False


def test_diff_detects_live_version_change_only():
    sources = [
        {"id": "mitre-atlas", "version": "2026.05"},
        {"id": "owasp-asi", "version": "2026.01"},
    ]
    records = check_all(
        fetch=lambda url: json.dumps({"tag_name": "9.9.9"}) if "atlas-data" in url else "",
        today="2026-07-20",
    )
    drift = diff_sources(sources, records)
    ids = {d["id"] for d in drift}
    assert "mitre-atlas" in ids  # live version changed 2026.05 -> 9.9.9
    assert "owasp-asi" not in ids  # pinned doc never auto-drifts
