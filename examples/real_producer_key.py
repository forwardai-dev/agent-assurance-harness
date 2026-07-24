"""Reach a full ``VERIFIED`` (exit 0) — a REAL producer key, not the published demo key.

``aah run`` signs every artifact with the published seed=1 *demo* key, so
``aah verify --trusted-key`` can only ever reach ``VERIFIED (DEMO KEY)`` — reproducibility,
not authorship (anyone can regenerate that key). A real producer instead signs with a
**private** key and keeps it private; the auditor pins the matching **public** key obtained
from a trusted channel (the producer's site, a keyserver — never the artifact itself).

This script does exactly that, end to end and offline: it generates a producer key, seals an
evidence object under it, and verifies against the pinned public half — the one path that
yields a genuine ``VERIFIED``.

    python examples/real_producer_key.py
"""

from __future__ import annotations

from aah.attack.generators.battery import default_battery
from aah.audit.signer import Ed25519Signer
from aah.eval.engine import EvalTask
from aah.governance.policy import Policy
from aah.runner import run_assurance
from aah.target.mock_agent import MockTargetAgent
from aah.verify.verifier import verify_seal


def main() -> int:
    """Seal under a real producer key, verify against its pinned public key, print the verdict."""
    # The producer keeps this PRIVATE. (A fixed seed here only makes the example reproducible;
    # a real producer would generate once and never publish the private half.)
    producer = Ed25519Signer.generate(seed=42)

    run = run_assurance(
        target=MockTargetAgent(profile="safe"),
        eval_tasks=[EvalTask("q1", "Return the answer.", expected="42", scorer="exact_match")],
        attack_scenarios=default_battery(),
        policy=Policy(),
        signer=producer,  # <-- the whole point: sign with a real key, not the demo default
    )
    seal = run.seal.to_dict()

    # The auditor pins the producer's PUBLIC key, obtained out-of-band (NOT read from the seal).
    trusted_public_key = producer.public_key_hex
    res = verify_seal(seal, trusted_keys=[trusted_public_key])

    print(f"gate verdict     : {run.gate.verdict}")
    print(f"integrity_ok     : {res.integrity_ok}")
    print(f"signature_ok     : {res.signature_ok}")
    print(f"decision_ok      : {res.decision_ok}")
    print(f"authenticity_ok  : {res.authenticity_ok}")
    print(f"demo_key         : {res.demo_key}")
    print(f"ok (full VERIFIED): {res.ok}")

    assert res.ok, "a real pinned producer key must fully verify"
    assert not res.demo_key, "this must NOT be the demo key"
    print("\nVERIFIED — real authorship established (this is the exit-0 path the demo CLI can't show).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
