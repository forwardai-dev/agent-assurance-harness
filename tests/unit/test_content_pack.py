"""Threat content lives in a versioned, hash-verified pack, not in code."""

import json

import pytest

from aah.attack.generators.battery import authoring_battery, default_battery
from aah.content.pack import (
    ContentPackError,
    load_bundled_public,
    load_pack,
    scenario_to_dict,
)


def test_bundled_public_pack_loads_and_is_provenanced():
    pack = load_bundled_public()
    assert pack.name == "aah-public"
    assert pack.kind == "public"
    assert pack.content_hash.startswith("sha256:")
    assert len(pack.scenarios) == 5
    assert {s.id for s in pack.sources} == {"owasp-asi", "mitre-atlas", "aivss", "anthropic-research"}
    assert pack.ref() == f"{pack.name}@{pack.version}#{pack.content_hash}"
    assert pack.signed is False  # the public pack ships unsigned


def test_default_battery_matches_authoring_source():
    # The runtime pack (JSON) must never drift from the human-editable authoring battery.
    # If this fails, run scripts/regen_public_pack.py.
    from_pack = [scenario_to_dict(s) for s in default_battery()]
    from_code = [scenario_to_dict(s) for s in authoring_battery()]
    assert from_pack == from_code


def test_corrupt_content_hash_is_rejected(tmp_path):
    # copy the bundled pack, then tamper with a scenario without fixing the hash
    pack = load_bundled_public()
    scen = [scenario_to_dict(s) for s in pack.scenarios]
    scen[0]["title"] = "tampered"
    (tmp_path / "scenarios").mkdir()
    (tmp_path / "scenarios" / "asi-battery.json").write_text(json.dumps({"scenarios": scen}))
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "aah.content-pack/v1",
                "name": "aah-public",
                "version": pack.version,
                "kind": "public",
                "sources": [],
                "scenarios_file": "scenarios/asi-battery.json",
                "content_hash": pack.content_hash,  # stale: does not match tampered scenarios
            }
        )
    )
    with pytest.raises(ContentPackError, match="content hash mismatch"):
        load_pack(tmp_path)


def test_unknown_schema_is_rejected(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({"schema": "bogus/v9"}))
    with pytest.raises(ContentPackError, match="unknown pack schema"):
        load_pack(tmp_path)


def test_run_records_content_pack_provenance_in_manifest():
    # a run tags its evidence with exactly which content version it tested against
    from aah.governance.policy import Policy
    from aah.runner import run_assurance
    from aah.target.mock_agent import MockTargetAgent

    pack = load_bundled_public()
    r = run_assurance(
        target=MockTargetAgent(profile="safe"),
        eval_tasks=[],
        attack_scenarios=list(pack.scenarios),
        policy=Policy(),
        content_packs=(pack.ref(),),
    )
    assert pack.ref() in r.aeo.manifest.to_dict()["content_packs"]
