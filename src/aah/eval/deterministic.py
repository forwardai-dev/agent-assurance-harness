"""Deterministic scorers — the eval money-path. Free of judge bias, fully reproducible.

Each scorer returns (passed: bool, metrics: dict). An LLM judge (aah.eval.judge) may add
a SIGNAL to metrics, but only these deterministic scorers gate the build in v1.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

Scorer = Callable[..., tuple[bool, dict]]


def exact_match(output: str, expected: str) -> tuple[bool, dict]:
    """Scorer: output exactly equals the expected string."""
    ok = output.strip() == expected.strip()
    return ok, {"scorer": "exact_match", "match": ok}


def contains(output: str, expected: str) -> tuple[bool, dict]:
    """Scorer: output contains the expected substring."""
    ok = expected.strip().lower() in output.lower()
    return ok, {"scorer": "contains", "match": ok}


def regex_match(output: str, pattern: str) -> tuple[bool, dict]:
    """Scorer: output matches the expected regular expression."""
    ok = re.search(pattern, output) is not None
    return ok, {"scorer": "regex_match", "pattern": pattern, "match": ok}


def json_valid(output: str, required_keys: tuple[str, ...] = ()) -> tuple[bool, dict]:
    """Scorer: output parses as valid JSON."""
    try:
        obj = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return False, {"scorer": "json_valid", "parsed": False}
    missing = [k for k in required_keys if k not in obj] if isinstance(obj, dict) else list(required_keys)
    return (not missing), {"scorer": "json_valid", "parsed": True, "missing_keys": missing}


def tool_call_arg_equivalence(actual: dict, expected: dict) -> tuple[bool, dict]:
    """Functional equivalence of a tool call's arguments (order-insensitive, BFCL-style)."""
    ok = _norm(actual) == _norm(expected)
    return ok, {"scorer": "tool_call_arg_equivalence", "match": ok}


def _norm(o: Any) -> Any:
    if isinstance(o, dict):
        return {k: _norm(v) for k, v in sorted(o.items())}
    if isinstance(o, list):
        return [_norm(x) for x in o]
    if isinstance(o, str):
        return o.strip().lower()
    return o


SCORERS: dict[str, Scorer] = {
    "exact_match": exact_match,
    "contains": contains,
    "regex_match": regex_match,
    "json_valid": json_valid,
}
