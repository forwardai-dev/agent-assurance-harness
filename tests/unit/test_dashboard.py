"""The HTML dashboard renders a self-contained report for an evidence object."""

from aah.attack.generators.battery import default_battery
from aah.eval.engine import EvalTask
from aah.governance.policy import Policy
from aah.report.dashboard import render
from aah.runner import run_assurance
from aah.target.mock_agent import MockTargetAgent
from aah.verify.verifier import verify_seal

EVAL = [EvalTask("q1", "Return the answer.", expected="42", scorer="exact_match")]


def _run(profile):
    return run_assurance(
        target=MockTargetAgent(profile=profile),
        eval_tasks=EVAL,
        attack_scenarios=default_battery(),
        policy=Policy(),
    )


def test_render_produces_self_contained_html_for_passing_run():
    r = _run("safe")
    html = render(r.aeo, None, r.aeo.content_hash())
    assert html.lstrip().lower().startswith("<!doctype html")
    assert "PASS" in html
    # self-contained: no external network dependencies
    assert "http://" not in html and "https://" not in html
    assert "cdn" not in html.lower()


def test_render_reflects_failing_gate_and_verify_result():
    r = _run("vulnerable")
    verify = verify_seal(r.seal.to_dict())
    html = render(r.aeo, verify, r.aeo.content_hash())
    assert "FAIL" in html
    # every axis label is present in the report
    for axis in ("Eval", "Security", "Governance"):
        assert axis.lower() in html.lower()
