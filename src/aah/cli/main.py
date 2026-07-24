"""aah CLI — one command surface.

  aah run    [--vulnerable] [--out DIR] [--seed N]   # run the offline battery -> signed AAEO + dashboard
  aah verify <evidence.json>                          # offline re-verify; integrity+decision need no anchor, authorship needs --trusted-key
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
    # Inline verify uses no trust anchor, so a sound artifact is "tamper-evident"
    # (bytes intact, decision replays) rather than fully "OK" — reserve OK/FAILED for
    # the real states and don't cry "FAILED" on an artifact that is merely unattributed.
    if vres.ok:
        vtxt = "OK"
    elif vres.tamper_evident and vres.authenticity_ok is None:
        vtxt = "tamper-evident (author unproven — run 'aah verify --trusted-key' to attest)"
    else:
        vtxt = "FAILED"
    print(
        f"  verify       : {vtxt} (integrity={vres.integrity_ok} sig={vres.signature_ok} decision={vres.decision_ok})"
    )
    print(f"  evidence     : {ev_path}")
    print(f"  dashboard    : {dash_path}")
    if run.gate.reasons:
        print("  reasons:")
        for r in run.gate.reasons:
            print(f"    - {r}")
    print(f"\n  ▶ Open the plain-English report in a browser:  {os.path.abspath(dash_path)}")
    return 0


def cmd_verify(args) -> int:
    """``aah verify``: offline-verify an evidence object's signature and hash chain."""
    with open(args.evidence) as fh:
        bundle = json.load(fh)
    trusted = [args.trusted_key] if getattr(args, "trusted_key", "") else None
    res = verify_seal(bundle["seal"], trusted_keys=trusted)
    print(f"integrity : {'OK' if res.integrity_ok else 'FAIL'}")
    print(f"signature : {'OK' if res.signature_ok else 'FAIL'}")
    if res.demo_key:
        authorship = "DEMO KEY (reproducibility, not authorship)"
    else:
        authorship = {True: "OK", False: "FAIL", None: "UNVERIFIED (no --trusted-key)"}[res.authenticity_ok]
    print(f"authorship: {authorship}")
    print(
        f"decision  : {'OK' if res.decision_ok else 'FAIL'} (recorded={res.recorded_verdict} replayed={res.replayed_verdict})"
    )
    for r in res.reasons:
        print(f"  - {r}")
    if res.ok:
        print("VERIFIED")
        return 0
    if res.demo_key and res.tamper_evident and res.authenticity_ok is True:
        # The verifier pinned the published demo key. Integrity + decision replay hold,
        # but authorship does NOT — anyone can regenerate that key. Distinct verdict and
        # exit code so a naive "I pinned a key, it says VERIFIED" can't overstate trust.
        print("VERIFIED (DEMO KEY) — reproducibility only; pin a real producer key to prove authorship")
        return 4
    if res.tamper_evident and res.authenticity_ok is None:
        # Distinguish "intact but unattributed" from "broken". Collapsing them would
        # either overstate an unsigned-for artifact or cry wolf on a sound one.
        print("TAMPER-EVIDENT ONLY — bytes intact and decision replays, author unproven")
        return 3
    print("VERIFICATION FAILED")
    return 2


def cmd_gate(args) -> int:
    """``aah gate``: re-verify the evidence, then gate on the REPLAYED decision.

    The gate must never trust the self-declared verdict field — that would let a one-byte
    edit (flip ``payload.gate.verdict`` to PASS) sail through CI. So it runs the full
    offline verification (content hash, signature, and a fresh policy replay over the
    embedded findings) and fails closed unless the artifact is tamper-evident; then it
    gates on the verdict the policy actually replays to, not the stored one.
    """
    with open(args.evidence) as fh:
        bundle = json.load(fh)
    res = verify_seal(bundle["seal"])
    if not res.tamper_evident:
        print("GATE: FAIL  (evidence failed verification — not tamper-evident)")
        for r in res.reasons:
            print(f"  - {r}")
        return 1
    print(f"GATE: {res.replayed_verdict}")
    return 0 if res.replayed_verdict == "PASS" else 1


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
    v.add_argument(
        "--trusted-key",
        default="",
        help="hex public key the artifact MUST be sealed with. Without it authorship "
        "cannot be established, because the only key available is the one inside the "
        "artifact — which a forger controls.",
    )
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
