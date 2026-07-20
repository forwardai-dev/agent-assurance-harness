#!/usr/bin/env python3
"""Check the public threat-content sources for drift; optionally update the manifest.

Run by CI on a schedule. It reads the shipped public pack manifest, queries each source's
current version (live sources over the network, pinned sources by hand), and reports drift.
With ``--write`` it bumps the changed *source versions + retrieved dates* in the manifest —
never the scenarios. A source-version bump is a signal for a human to review whether new
red-team scenarios are needed; the CI job opens a PR so that review happens in the open.

Usage:
    python scripts/update_threat_content.py --today 2026-07-20            # report only
    python scripts/update_threat_content.py --today 2026-07-20 --write    # update manifest
    python scripts/update_threat_content.py --offline --today 2026-07-20  # no network (pinned)

Exit code 0 = clean, 20 = drift detected (so CI can branch on it).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aah.content.feeds import check_all, diff_sources  # noqa: E402

MANIFEST = ROOT / "src" / "aah" / "content" / "packs" / "public" / "manifest.json"


def _offline_fetch(url: str) -> str:
    """A fetcher that always fails — forces every live source to its pinned fallback."""
    raise OSError("offline mode")


def main() -> int:
    """Report threat-content source drift and, with --write, update the manifest."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true", help="apply version/retrieved bumps to the manifest")
    ap.add_argument("--offline", action="store_true", help="skip the network (all sources pinned)")
    ap.add_argument("--today", default="", help="ISO date to stamp as 'retrieved' (deterministic)")
    args = ap.parse_args()

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    records = check_all(fetch=_offline_fetch if args.offline else None, today=args.today)

    print("Threat-content source freshness:")
    for r in records:
        tag = "live" if r.live else "pinned"
        state = "ok" if r.ok else "FALLBACK"
        print(f"  [{tag:6} {state:8}] {r.id:20} {r.version:16} {r.note}")

    drift = diff_sources(manifest.get("sources", []), records)
    if not drift:
        print("\nNo drift. Threat-content sources are current.")
        return 0

    print("\nDRIFT DETECTED:")
    for d in drift:
        print(f"  {d['id']}: {d['old']} -> {d['new']}")

    if args.write:
        by_id = {r.id: r for r in records}
        for src in manifest["sources"]:
            rec = by_id.get(src["id"])
            if rec and rec.live and rec.ok:
                src["version"] = rec.version
                if args.today:
                    src["retrieved"] = args.today
        MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print("\nManifest updated. Review whether new scenarios are warranted before merging.")

    return 20


if __name__ == "__main__":
    raise SystemExit(main())
