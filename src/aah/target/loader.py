"""Load a user-supplied TargetAgent by ``module:Attribute`` spec.

Lets ``aah run --target-module mypkg.adapters:MyAgent --target-arg url=...`` plug any
adapter into the CLI without editing aah. The attribute may be a class or a factory; it is
called with the parsed ``--target-arg`` keyword arguments.
"""

from __future__ import annotations

import importlib
from typing import Any


def load_target(spec: str, **kwargs: Any) -> Any:
    """Import ``module:Attribute`` and instantiate it, validating the TargetAgent shape.

    Raises:
        ValueError: if the spec is not ``module:Attribute``.
        TypeError: if the loaded object is not a TargetAgent (missing ``.run`` / ``.name``).
    """
    mod_name, sep, attr = spec.partition(":")
    if not sep or not attr:
        raise ValueError(f"target spec must be 'module:Attribute', got {spec!r}")
    obj = getattr(importlib.import_module(mod_name), attr)
    target = obj(**kwargs) if callable(obj) else obj
    if not hasattr(target, "run") or not hasattr(target, "name"):
        raise TypeError(f"{spec} is not a TargetAgent (needs a .run(request) method and a .name)")
    return target


def parse_target_args(pairs: list[str]) -> dict[str, str]:
    """Parse ``key=value`` CLI args into a kwargs dict for the adapter factory."""
    out: dict[str, str] = {}
    for p in pairs or []:
        k, sep, v = p.partition("=")
        if not sep:
            raise ValueError(f"--target-arg must be key=value, got {p!r}")
        out[k.strip()] = v
    return out
