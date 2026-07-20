"""Orchestrator — one assurance run: eval + security -> findings -> gate -> sealed AAEO.

Deterministic given (target, suites, policy, seed). Produces the signed evidence object
and its seal. This is what `aah run` calls.
"""

from __future__ import annotations

from dataclasses import dataclass

from .attack.engine import run_attacks
from .attack.scenario import AttackScenario
from .audit.ledger import Seal, seal_evidence
from .audit.signer import Ed25519Signer
from .core.evidence import AssuranceEvidenceObject, ScopeStatement
from .core.finding import Finding
from .core.hashing import content_hash
from .core.manifest import RunManifest
from .eval.engine import EvalTask, run_eval
from .governance.gate import GateResult, evaluate_gate
from .governance.policy import Policy
from .target.base import TargetAgent

DEFAULT_TS = "2026-07-19T00:00:00Z"


@dataclass
class AssuranceRun:
    """Result of an assurance run: the evidence object and its ledger seal."""

    aeo: AssuranceEvidenceObject
    gate: GateResult
    seal: Seal

    def evidence_bundle(self) -> dict:
        """Return the evidence bundle (evidence object plus seal) as a dict."""
        return {"seal": self.seal.to_dict()}


def run_assurance(
    target: TargetAgent,
    eval_tasks: list[EvalTask],
    attack_scenarios: list[AttackScenario],
    policy: Policy,
    signer: Ed25519Signer | None = None,
    scope: ScopeStatement | None = None,
    seed: int = 0,
    k: int = 1,
    timestamp: str = DEFAULT_TS,
    extra_findings: list[Finding] | None = None,
    content_packs: tuple[str, ...] = (),
) -> AssuranceRun:
    """Run eval, attack, and rerank stages, then seal the evidence object."""
    signer = signer or Ed25519Signer.generate(seed=1)  # deterministic key for reproducible demo
    findings: list[Finding] = []
    producers: list[str] = []
    if eval_tasks:
        findings += run_eval(eval_tasks, target, k=k, seed=seed)
        producers.append("aah.eval")
    if attack_scenarios:
        findings += run_attacks(attack_scenarios, target)
        producers.append("aah.attack")
    if extra_findings:
        findings += extra_findings
        producers.append("aah.rerank_eval")

    gate = evaluate_gate(findings, policy)

    dataset_hash = content_hash(
        {
            "eval": [t.task_id for t in eval_tasks],
            "attack": [s.id for s in attack_scenarios],
        }
    )
    tools = sorted({t for s in attack_scenarios for t in s.requests[0].allowed_tools})
    manifest = RunManifest(
        sut_name=getattr(target, "name", "unknown"),
        model_id=getattr(target, "name", "unknown"),
        seed=seed,
        policy_version=policy.version,
        dataset_hash=dataset_hash,
        tool_manifest=tuple(tools),
        content_packs=tuple(content_packs),
        created_at=timestamp,
    )
    scope = scope or ScopeStatement(
        tested=(
            "Deterministic correctness eval + a frozen OWASP-Agentic red-team battery "
            "(ASI01/02/04/06/07) against the system-under-test, scored offline."
        ),
        not_tested=(
            "Adaptive/feedback-guided attacks, LLM-judged correctness, live model behavior "
            "under real deployment, and supply-chain CVE scanning (all v2 roadmap)."
        ),
        residual_risk=(
            "A PASS means the agent resisted a FIXED attacker on the tested surface; "
            "it is evidence, not a safety guarantee. Unknown/adaptive attacks remain."
        ),
    )
    aeo = AssuranceEvidenceObject(
        manifest=manifest,
        findings=findings,
        scope=scope,
        producers=producers,
        gate=gate.to_dict(),
        policy=policy.to_dict(),
    )
    seal = seal_evidence(aeo, signer, timestamp=timestamp)
    return AssuranceRun(aeo=aeo, gate=gate, seal=seal)
