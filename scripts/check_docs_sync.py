#!/usr/bin/env python3
"""Fail CI when documented facts drift from repo reality.

This guards against the "badge says 30, suite actually has 76" class of bug — a
claim in the docs that quietly stopped matching the code. It checks facts that are
cheap to recompute from the repo and easy to let rot:

  1. README tests badge  ==  the real collected test count (`pytest --collect-only`).
  2. Every OWASP-ASI id the README advertises is actually implemented in the attack
     battery (no over-claiming coverage the code doesn't have).

Run it directly (`python scripts/check_docs_sync.py`) or in CI. Exit 0 = all synced;
exit 1 = drift, with a specific diff so the fix is obvious.

The parsing helpers are pure (text in, value out) so they are unit-tested without
running pytest; only `real_test_count()` shells out.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def parse_badge_test_count(readme: str) -> int | None:
    """Return N from the shields.io badge `tests-N%20passing`, or None if absent."""
    m = re.search(r"tests-(\d+)%20passing", readme)
    return int(m.group(1)) if m else None


def parse_prose_test_counts(readme: str) -> list[int]:
    """Every test count stated in README prose, e.g. `pytest`: **80 passed**.

    The badge is not the only place a count rots — a stale `**30 passed**` in the
    Status line is exactly what audit v2 caught. Guard those too.
    """
    return [int(m.group(1)) for m in re.finditer(r"\*\*(\d+) passed\*\*", readme)]


def parse_readme_asi_set(readme: str) -> set[str]:
    """Expand every `ASI01` / `ASI01/02/04` shorthand in the README into a set of ids.

    `ASI01/02/04/06/07` -> {ASI01, ASI02, ASI04, ASI06, ASI07}.
    """
    ids: set[str] = set()
    for m in re.finditer(r"ASI(\d{2}(?:/\d{2})*)", readme):
        for num in m.group(1).split("/"):
            ids.add(f"ASI{num}")
    return ids


def battery_asi_set(attack_dir: Path) -> set[str]:
    """Collect the ASI ids the attack battery actually implements (from `asiNN` tokens)."""
    ids: set[str] = set()
    for path in attack_dir.rglob("*.py"):
        for m in re.finditer(r"asi(\d{2})", path.read_text()):
            ids.add(f"ASI{m.group(1)}")
    return ids


def real_test_count() -> int:
    """Ask pytest how many tests it collects (offline, no execution)."""
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "pytest", "tests", "--collect-only", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    blob = out.stdout + out.stderr
    m = re.search(r"(\d+) tests? collected", blob)
    if not m:
        sys.stderr.write(blob)
        raise SystemExit("check_docs_sync: could not read test count from pytest --collect-only")
    return int(m.group(1))


def main() -> int:
    """Run every sync check; print a line per check; return 0 if all pass, else 1."""
    readme = (ROOT / "README.md").read_text()
    failures: list[str] = []

    # 1. test-count badge vs reality
    badge = parse_badge_test_count(readme)
    real = real_test_count()
    if badge is None:
        failures.append("README has no `tests-N%20passing` badge to verify")
    elif badge != real:
        failures.append(
            f"test-count drift: README badge says {badge}, pytest collects {real} "
            f"— update the badge to `tests-{real}%20passing`"
        )
    else:
        print(f"OK  test count: badge {badge} == collected {real}")

    # 1b. any test count stated in README prose (e.g. the Status line) must also match
    for prose in parse_prose_test_counts(readme):
        if prose != real:
            failures.append(
                f"test-count drift in README prose: `**{prose} passed**` but pytest "
                f"collects {real} — update it to `**{real} passed**`"
            )
    if parse_prose_test_counts(readme):
        print(f"OK  prose test counts {parse_prose_test_counts(readme)} all == {real}")

    # 2. README must not advertise ASI coverage the battery doesn't implement
    advertised = parse_readme_asi_set(readme)
    implemented = battery_asi_set(ROOT / "src" / "aah" / "attack")
    overclaimed = advertised - implemented
    if overclaimed:
        failures.append(
            f"README advertises ASI ids not in the battery: {sorted(overclaimed)} "
            f"(implemented: {sorted(implemented)})"
        )
    else:
        print(f"OK  ASI coverage: README {sorted(advertised)} ⊆ battery {sorted(implemented)}")

    if failures:
        print("\nDOCS-SYNC FAILED:")
        for f in failures:
            print(f"  ✗ {f}")
        return 1
    print("\nDOCS-SYNC OK — docs match the repo.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
