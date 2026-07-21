"""aah CLI — one command surface.

  aah run    [--vulnerable] [--out DIR] [--seed N]   # run the offline battery -> signed AAEO + dashboard
  aah verify <evidence.json>                          # offline re-verify (no network, no producer trust)
  aah gate   <evidence.json>                          # exit non-zero if the recorded verdict is FAIL

stdlib argparse (no third-party CLI dep). Fully offline; mock target + no API keys.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from ..content.pack import ContentPackError, load_bundled_public, load_pack
from ..eval.engine import EvalTask
from ..governance.policy import Policy
from ..report.dashboard import render
from ..rerank_eval.evaluate import RerankCase, sweep
from ..rerank_eval.rerankers import IdentityReranker, OracleMockReranker
from ..runner import run_assurance
from ..target.arbiter_agent import ArbiterSubrogationAgent
from ..target.mock_agent import MockTargetAgent
from ..verify.verifier import verify_seal


def _demo_eval(target: str) -> list[EvalTask]:
    if target == "arbiter":
        # domain eval: a governed subrogation-intake agent extracting claim fields correctly
        return [
            EvalTask(
                "extract-coverage",
                "Extract the coverage type from the claim.",
                expected="collision",
                scorer="contains",
                context={"tool_output": "claim packet: coverage=collision, loss_state=CO"},
            ),
            EvalTask(
                "extract-amount",
                "Return total company-paid damages.",
                expected="8420",
                scorer="contains",
                context={"tool_output": "features: repair 6180, rental 1240, tow 300, storage 700"},
            ),
            EvalTask(
                "intake-valid",
                "Validate the intake and confirm.",
                expected="intake:intake-valid:validated",
                scorer="contains",
            ),
        ]
    return [
        EvalTask("answer-42", "Return the answer to the question.", expected="42", scorer="exact_match"),
        EvalTask("greet", "Greet the user.", expected="hello", scorer="contains"),
        EvalTask("json-out", "Emit JSON with key status.", expected='{"status":"ok"}', scorer="contains"),
    ]


def _make_target(name: str, vulnerable: bool):
    profile = "vulnerable" if vulnerable else "safe"
    if name == "arbiter":
        return ArbiterSubrogationAgent(profile=profile)
    return MockTargetAgent(profile=profile)


def _resolve_target(args):
    """Pick the system-under-test: a loaded module, the interactive relay, or a built-in."""
    if getattr(args, "target_module", ""):
        from ..target.loader import load_target, parse_target_args

        return load_target(args.target_module, **parse_target_args(args.target_arg))
    if args.target == "interactive":
        from ..target.interactive import InteractiveAgent

        return InteractiveAgent()
    return _make_target(args.target, args.vulnerable)


def _demo_rerank_findings():
    cases = [
        RerankCase("q1", ["d3", "d4", "d1", "d2"], {"d1", "d2"}),
        RerankCase("q2", ["b2", "b3", "b1"], {"b1"}),
    ]
    rel = {"q1": {"d1", "d2"}, "q2": {"b1"}}
    res = sweep(
        cases,
        {
            "identity": IdentityReranker(),
            "mock-oracle": OracleMockReranker(relevant_by_query=rel, strength=1.0),
        },
        metric="ndcg",
        k=10,
    )
    return res.to_findings(k=10)


def _load_content_pack(args):
    """Load the requested content pack (or the bundled public one) for a run."""
    if args.content_pack:
        trusted = [args.trusted_key] if args.trusted_key else None
        return load_pack(
            Path(args.content_pack),
            require_signature=args.require_signature,
            trusted_keys=trusted,
        )
    return load_bundled_public()


def cmd_run(args) -> int:
    """``aah run``: execute an assurance run and write the evidence object."""
    profile = "vulnerable" if args.vulnerable else "safe"
    try:
        target = _resolve_target(args)
    except (ValueError, TypeError, ImportError, AttributeError) as e:
        print(f"target error: {e}", file=sys.stderr)
        return 4
    try:
        pack = _load_content_pack(args)
    except ContentPackError as e:
        print(f"content-pack error: {e}", file=sys.stderr)
        return 3
    run = run_assurance(
        target=target,
        eval_tasks=_demo_eval(args.target),
        attack_scenarios=list(pack.scenarios),
        policy=Policy(),
        seed=args.seed,
        extra_findings=_demo_rerank_findings(),
        content_packs=(pack.ref(),),
    )
    os.makedirs(args.out, exist_ok=True)
    ev_path = os.path.join(args.out, "evidence.json")
    with open(ev_path, "w") as fh:
        json.dump(run.evidence_bundle(), fh, indent=2)
    vres = verify_seal(run.seal.to_dict())
    dash = render(run.aeo, vres, run.seal.this_hash)
    dash_path = os.path.join(args.out, "dashboard.html")
    with open(dash_path, "w") as fh:
        fh.write(dash)
    print(f"GATE: {run.gate.verdict}  (profile={profile})")
    print(f"  content-pack : {pack.ref()}  ({'signed' if pack.signed else 'unsigned'}, kind={pack.kind})")
    print(f"  content-hash : {run.seal.this_hash}")
    print(
        f"  verify       : {'OK' if vres.ok else 'FAILED'} (integrity={vres.integrity_ok} sig={vres.signature_ok} decision={vres.decision_ok})"
    )
    print(f"  evidence     : {ev_path}")
    print(f"  dashboard    : {dash_path}")
    if run.gate.reasons:
        print("  reasons:")
        for r in run.gate.reasons:
            print(f"    - {r}")
    return 0


def cmd_verify(args) -> int:
    """``aah verify``: offline-verify an evidence object's signature and hash chain."""
    with open(args.evidence) as fh:
        bundle = json.load(fh)
    res = verify_seal(bundle["seal"])
    print(f"integrity : {'OK' if res.integrity_ok else 'FAIL'}")
    print(f"signature : {'OK' if res.signature_ok else 'FAIL'}")
    print(
        f"decision  : {'OK' if res.decision_ok else 'FAIL'} (recorded={res.recorded_verdict} replayed={res.replayed_verdict})"
    )
    for r in res.reasons:
        print(f"  - {r}")
    print("VERIFIED" if res.ok else "VERIFICATION FAILED")
    return 0 if res.ok else 2


def cmd_gate(args) -> int:
    """``aah gate``: apply a policy to an evidence object and print the gate decision."""
    with open(args.evidence) as fh:
        bundle = json.load(fh)
    verdict = (bundle["seal"]["payload"].get("gate") or {}).get("verdict", "UNKNOWN")
    print(f"GATE: {verdict}")
    return 0 if verdict == "PASS" else 1


def cmd_pack(args) -> int:
    """``aah pack``: load + verify a content pack offline and print its provenance."""
    trusted = [args.trusted_key] if args.trusted_key else None
    try:
        pack = load_pack(Path(args.path), require_signature=args.require_signature, trusted_keys=trusted)
    except ContentPackError as e:
        print(f"content-pack INVALID: {e}", file=sys.stderr)
        return 3
    print(f"pack        : {pack.name}@{pack.version} (kind={pack.kind})")
    print(f"content-hash: {pack.content_hash}")
    print(f"scenarios   : {len(pack.scenarios)}")
    print(f"signature   : {f'signed by {pack.signer_pubkey}' if pack.signed else 'unsigned'}")
    print(f"sources     : {', '.join(s.id + '@' + s.version for s in pack.sources)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argparse command-line parser."""
    p = argparse.ArgumentParser(
        prog="aah", description="Agent Assurance Harness — offline-verifiable evidence + gate"
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the offline assurance battery")
    r.add_argument(
        "--target",
        choices=["mock", "arbiter", "interactive"],
        default="mock",
        help="system-under-test: 'mock' / 'arbiter' (built-in, offline) or "
        "'interactive' (relay a REAL agent by pasting its responses)",
    )
    r.add_argument(
        "--target-module",
        default="",
        help="load a custom adapter: 'module.path:ClassOrFactory' (overrides --target)",
    )
    r.add_argument(
        "--target-arg",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="keyword arg passed to the --target-module factory (repeatable)",
    )
    r.add_argument(
        "--vulnerable", action="store_true", help="use the vulnerable SUT profile (produces a FAIL)"
    )
    r.add_argument("--out", default="./out", help="output directory")
    r.add_argument("--seed", type=int, default=0)
    r.add_argument(
        "--content-pack",
        default="",
        help="path to a threat-content pack dir (default: the bundled public pack)",
    )
    r.add_argument(
        "--require-signature",
        action="store_true",
        help="reject an unsigned content pack (for trusted private packs)",
    )
    r.add_argument(
        "--trusted-key",
        default="",
        help="hex Ed25519 public key the content pack must be signed by",
    )
    r.set_defaults(func=cmd_run)
    pk = sub.add_parser("pack", help="inspect + verify a content pack offline")
    pk.add_argument("path")
    pk.add_argument("--require-signature", action="store_true")
    pk.add_argument("--trusted-key", default="")
    pk.set_defaults(func=cmd_pack)
    v = sub.add_parser("verify", help="offline re-verify an evidence bundle")
    v.add_argument("evidence")
    v.set_defaults(func=cmd_verify)
    g = sub.add_parser("gate", help="exit non-zero if the recorded verdict is FAIL")
    g.add_argument("evidence")
    g.set_defaults(func=cmd_gate)
    return p


def main(argv=None) -> int:
    """CLI entry point: parse arguments and dispatch to the sub-command."""
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
