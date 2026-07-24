"""The real-producer-key example must actually reach a full VERIFIED (guards against drift)."""

import importlib.util
from pathlib import Path

_PATH = Path(__file__).resolve().parents[2] / "examples" / "real_producer_key.py"


def test_real_producer_key_example_fully_verifies():
    spec = importlib.util.spec_from_file_location("real_producer_key", _PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # main() asserts res.ok and not res.demo_key internally, and returns 0 on success
    assert mod.main() == 0
