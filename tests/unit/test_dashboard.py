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


def test_verify_badge_is_tristate_never_false_failed():
    # The dashboard is rendered WITHOUT a pinned key, so an honest artifact has
    # tamper_evident=True but ok=False. That must read TAMPER-EVIDENT ONLY (amber), never a
    # red "FAILED" — the historical bug that stamped every honest run as forged.
    r = _run("safe")
    verify = verify_seal(r.seal.to_dict())  # no trusted_keys
    assert verify.tamper_evident and not verify.ok  # the exact state that used to render FAILED
    html = render(r.aeo, verify, r.aeo.content_hash())
    assert "TAMPER-EVIDENT ONLY" in html
    assert "verify re-checked offline: FAILED" not in html

    # A genuinely broken artifact (mutated verdict → integrity breaks) still shows FAILED.
    forged = r.seal.to_dict()
    forged["payload"]["gate"]["verdict"] = "FAIL"
    broken = verify_seal(forged)
    assert not broken.tamper_evident
    assert "VERIFICATION FAILED" in render(r.aeo, broken, r.aeo.content_hash())
