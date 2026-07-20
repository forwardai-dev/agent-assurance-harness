#!/usr/bin/env python3
"""Regenerate the bundled public content pack from the authoring battery.

Run this after editing scenarios in ``aah/attack/generators/battery.py``. It rewrites
``aah/content/packs/public/scenarios/asi-battery.json`` and updates the manifest's
``content_hash`` (and, unless ``--keep-version``, bumps the version to today's date,
which you pass in — this script takes no wall-clock so runs stay reproducible).

Usage:
    python scripts/regen_public_pack.py --version 2026.07.20
    python scripts/regen_public_pack.py --keep-version
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aah.attack.generators.battery import authoring_battery  # noqa: E402
from aah.content.pack import scenario_to_dict, scenarios_content_hash  # noqa: E402

PACK = ROOT / "src" / "aah" / "content" / "packs" / "public"


def main() -> int:
    """Rebuild the public pack scenarios file and refresh the manifest content hash."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--version", help="new pack version (e.g. 2026.07.20)")
    ap.add_argument("--keep-version", action="store_true", help="do not change the version")
    args = ap.parse_args()

    scen = [scenario_to_dict(s) for s in authoring_battery()]
    chash = scenarios_content_hash(scen)
    (PACK / "scenarios" / "asi-battery.json").write_text(
        json.dumps({"scenarios": scen}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    manifest = json.loads((PACK / "manifest.json").read_text(encoding="utf-8"))
    manifest["content_hash"] = chash
    if args.version and not args.keep_version:
        manifest["version"] = args.version
    manifest.pop("signature", None)  # regenerating invalidates any prior signature
    (PACK / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"regenerated public pack: {len(scen)} scenarios, {chash}, version {manifest['version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
