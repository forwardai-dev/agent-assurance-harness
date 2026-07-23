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
    seal = bundle["seal"]
    # Without a trust anchor the artifact is TAMPER-EVIDENT (bytes intact, signature and
    # decision replay hold) but its authorship is unproven -> deliberately not `ok`.
    res = verify_seal(seal)
    assert res.integrity_ok and res.signature_ok and res.decision_ok
    assert res.tamper_evident and res.authenticity_ok is None and not res.ok
    assert res.recorded_verdict == res.replayed_verdict == verdict
    # Pin the producer's own key as the trust anchor -> fully VERIFIED.
    trusted = verify_seal(seal, trusted_keys=[seal["public_key_hex"]])
    assert trusted.ok and trusted.authenticity_ok is True


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
