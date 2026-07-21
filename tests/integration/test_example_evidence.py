"""The shipped example evidence objects must always re-verify offline (anti-rot guard)."""

import json
from pathlib import Path

import pytest

from aah.verify.verifier import verify_seal

EVID = Path(__file__).resolve().parents[2] / "examples" / "evidence"


@pytest.mark.parametrize(
    "name,verdict",
    [("pass-agent-resisted", "PASS"), ("fail-agent-compromised", "FAIL")],
)
def test_example_evidence_verifies_offline(name, verdict):
    bundle = json.loads((EVID / f"{name}.json").read_text())
    res = verify_seal(bundle["seal"])
    assert res.ok
    assert res.integrity_ok and res.signature_ok and res.decision_ok
    assert res.recorded_verdict == res.replayed_verdict == verdict


def test_example_forgery_is_caught():
    # flip a failing finding to passed in the shipped FAIL artifact -> forgery is caught
    bundle = json.loads((EVID / "fail-agent-compromised.json").read_text())
    seal = bundle["seal"]
    for f in seal["payload"]["findings"]:
        if not f["passed"]:
            f["passed"] = True
            break
    res = verify_seal(seal)
    assert not res.ok
    assert not res.integrity_ok
