"""End-to-end: run assurance offline, verify the seal, prove tamper + decision-replay."""

from aah.attack.generators.battery import default_battery
from aah.audit.signer import Ed25519Signer
from aah.eval.engine import EvalTask
from aah.governance.policy import Policy
from aah.runner import run_assurance
from aah.target.mock_agent import MockTargetAgent
from aah.verify.verifier import verify_seal

EVAL = [
    EvalTask("q1", "Return the answer.", expected="42", scorer="exact_match"),
    EvalTask("q2", "Say hello.", expected="hello", scorer="contains"),
]


def _run(profile):
    return run_assurance(
        target=MockTargetAgent(profile=profile),
        eval_tasks=EVAL,
        attack_scenarios=default_battery(),
        policy=Policy(),
    )


def test_safe_run_passes_and_is_offline_reproducible():
    r1 = _run("safe")
    r2 = _run("safe")
    assert r1.gate.verdict == "PASS"
    # fully deterministic: identical content hash across runs (no API keys, no clock, no rng)
    assert r1.aeo.content_hash() == r2.aeo.content_hash()


def test_vulnerable_run_fails_the_gate():
    r = _run("vulnerable")
    assert r.gate.verdict == "FAIL"
    assert any("security" in reason or "AIVSS" in reason for reason in r.gate.reasons)


def test_verify_roundtrip_offline():
    r = _run("safe")
    # `ok` means integrity AND authorship AND decision replay. These artifacts are
    # produced in-test by the default demo signer (published seed=1), so pinning that
    # key proves reproducibility, not authorship: flagged (demo_key), not a full
    # VERIFIED. Integrity + decision replay still hold (tamper-evident).
    res = verify_seal(r.seal.to_dict(), trusted_keys=[Ed25519Signer.generate(seed=1).public_key_hex])
    assert res.demo_key is True and res.tamper_evident and not res.ok
    assert res.integrity_ok and res.signature_ok and res.decision_ok
    assert res.replayed_verdict == res.recorded_verdict == "PASS"


def test_tamper_breaks_verification():
    r = _run("vulnerable")
    seal = r.seal.to_dict()
    # flip a failing finding to 'passed' to try to forge a PASS -> integrity + decision both catch it
    seal["payload"]["findings"][-1]["passed"] = True
    res = verify_seal(seal)
    assert not res.ok
    assert not res.integrity_ok  # content hash no longer matches the signed bytes


def test_decision_replay_independent_of_producer_claim():
    # even if the producer LIES about the verdict, replay recomputes the truth
    r = _run("vulnerable")
    seal = r.seal.to_dict()
    original_hash = seal["this_hash"]
    seal["payload"]["gate"]["verdict"] = "PASS"  # forged verdict
    res = verify_seal(seal)
    assert not res.ok
    # hash breaks (payload mutated) so integrity catches the forgery
    assert not res.integrity_ok
    assert seal["this_hash"] == original_hash  # producer didn't re-seal (can't, no key)
