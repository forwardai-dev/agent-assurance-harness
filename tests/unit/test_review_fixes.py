"""Smaller fixes from the multi-reviewer code audit: leakage threshold is honored,
and the verifier fails cleanly (no traceback) on a malformed seal."""

from aah.eval.leakage_linter import LeakReport, lint_golden
from aah.verify.verifier import verify_seal


def test_leak_threshold_is_honored():
    # Same overlap, different threshold -> different verdict. Previously hardcoded > 0.5.
    loose = LeakReport("x", overlap=0.3, has_canary=False, has_provenance=True, threshold=0.5)
    strict = LeakReport("x", overlap=0.3, has_canary=False, has_provenance=True, threshold=0.2)
    assert not loose.leaked  # 0.3 <= 0.5
    assert strict.leaked  # 0.3 > 0.2


def test_lint_golden_threads_threshold_into_reports():
    items = [{"id": "a", "text": "hello world", "provenance": "src"}]
    assert lint_golden(items, [], threshold=0.2)[0].threshold == 0.2


def test_verify_seal_fails_cleanly_on_a_malformed_seal():
    res = verify_seal({"payload": {}})  # missing prev_hash/signature/this_hash/...
    assert not res.ok and not res.tamper_evident
    assert res.authenticity_ok is None
    assert any("malformed" in r for r in res.reasons)
    # and it must not raise on a completely empty seal
    assert not verify_seal({}).ok
