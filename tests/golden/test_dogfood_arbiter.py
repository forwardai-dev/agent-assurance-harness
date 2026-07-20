"""Dogfood: run the whole harness against the governed subrogation-intake agent."""

from aah.attack.generators.battery import default_battery
from aah.eval.engine import EvalTask
from aah.governance.policy import Policy
from aah.runner import run_assurance
from aah.target.arbiter_agent import ArbiterSubrogationAgent
from aah.verify.verifier import verify_seal


def _run(profile):
    return run_assurance(
        target=ArbiterSubrogationAgent(profile=profile),
        eval_tasks=[
            EvalTask(
                "extract-coverage",
                "Extract coverage.",
                expected="collision",
                scorer="contains",
                context={"tool_output": "coverage=collision"},
            )
        ],
        attack_scenarios=default_battery(),
        policy=Policy(),
    )


def test_arbiter_safe_passes_and_verifies():
    r = _run("safe")
    assert r.gate.verdict == "PASS"
    assert verify_seal(r.seal.to_dict()).ok


def test_arbiter_vulnerable_fails_on_pii_exfil():
    r = _run("vulnerable")
    assert r.gate.verdict == "FAIL"
    open_sec = [f for f in r.aeo.findings if f.axis.value == "security" and not f.passed]
    assert open_sec, "vulnerable subrogation agent should have open security findings"
    # the SUT identity is pinned in the evidence manifest
    assert r.aeo.manifest.model_id == "arbiter:subrogation-intake-v1"
