"""Unit tests for the docs-vs-repo sync check (scripts/check_docs_sync.py)."""

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "check_docs_sync",
    Path(__file__).resolve().parents[2] / "scripts" / "check_docs_sync.py",
)
assert _SPEC and _SPEC.loader
docs_sync = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(docs_sync)


def test_parse_badge_test_count():
    assert docs_sync.parse_badge_test_count("...tests-76%20passing...") == 76
    assert docs_sync.parse_badge_test_count("no badge here") is None


def test_parse_prose_test_counts():
    # catches a stale Status line even when the badge is right (audit v2 #1)
    assert docs_sync.parse_prose_test_counts("`pytest`: **80 passed**, fully offline") == [80]
    assert docs_sync.parse_prose_test_counts("no counts here") == []


def test_parse_readme_asi_set_expands_shorthand():
    # the exact shorthand the README uses
    assert docs_sync.parse_readme_asi_set("GATE: FAIL (ASI01/02/04/06/07)") == {
        "ASI01",
        "ASI02",
        "ASI04",
        "ASI06",
        "ASI07",
    }
    # standalone mentions union in
    assert docs_sync.parse_readme_asi_set("covers ASI04 and ASI06") == {"ASI04", "ASI06"}


def test_battery_asi_set_reads_real_source():
    # the real battery must implement exactly the coverage the docs advertise
    attack_dir = Path(__file__).resolve().parents[2] / "src" / "aah" / "attack"
    assert docs_sync.battery_asi_set(attack_dir) == {"ASI01", "ASI02", "ASI04", "ASI06", "ASI07"}


def test_repo_is_actually_in_sync():
    # end-to-end: the committed README + battery pass every check (real count included)
    assert docs_sync.main() == 0
