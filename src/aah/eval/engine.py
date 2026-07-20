"""Eval engine — runs correctness tasks against the target, emits Findings.

Deterministic-first: a task passes only if it passes on all k trials (pass^k). Every
finding carries its trajectory reference so verdicts are transcript-linked, not
final-answer-only.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.finding import Axis, ControlRef, Finding, Severity
from ..target.base import AgentRequest, TargetAgent
from . import deterministic as det
from .statistics import bootstrap_ci, pass_hat_k


@dataclass(frozen=True)
class EvalTask:
    """A single eval task: input, expected output, and scorer."""

    task_id: str
    prompt: str
    expected: str = ""
    scorer: str = "exact_match"
    scorer_args: tuple = ()
    context: dict = field(default_factory=dict)


def _score(task: EvalTask, output: str) -> tuple[bool, dict]:
    fn = det.SCORERS.get(task.scorer, det.exact_match)
    if task.scorer in ("exact_match", "contains"):
        return fn(output, task.expected)
    if task.scorer == "regex_match":
        return fn(output, task.scorer_args[0] if task.scorer_args else task.expected)
    if task.scorer == "json_valid":
        return fn(output, tuple(task.scorer_args))
    return fn(output, task.expected)


def run_eval(tasks: list[EvalTask], target: TargetAgent, k: int = 1, seed: int = 0) -> list[Finding]:
    """Run eval tasks with deterministic scorers and return Findings."""
    findings: list[Finding] = []
    all_trials: list[list[bool]] = []
    for task in tasks:
        ctx = dict(task.context)
        ctx.setdefault("expected", task.expected)
        trials: list[bool] = []
        for _ in range(max(1, k)):
            resp = target.run(AgentRequest(task_id=task.task_id, prompt=task.prompt, context=ctx))
            ok, _m = _score(task, resp.output)
            trials.append(ok)
        all_trials.append(trials)
        passed = all(trials)
        findings.append(
            Finding(
                id=f"eval.{task.task_id}",
                axis=Axis.EVAL,
                title=f"Correctness: {task.task_id}",
                passed=passed,
                severity=Severity.INFO if passed else Severity.HIGH,
                controls=(ControlRef("NIST-AI-RMF", "MEASURE-2.3", "measure agent performance"),),
                metrics={"scorer": task.scorer, "k": k, "trial_passes": sum(trials)},
                transcript_ref=f"eval.{task.task_id}.traj",
            )
        )
    # aggregate stat finding
    flat = [t for trials in all_trials for t in trials]
    point, lo, hi = bootstrap_ci(flat, seed=seed)
    findings.append(
        Finding(
            id="eval.aggregate",
            axis=Axis.EVAL,
            title="Eval aggregate (pass^k + bootstrap CI)",
            passed=all(all(t) for t in all_trials),
            severity=Severity.INFO,
            metrics={
                "pass_hat_k": pass_hat_k(all_trials),
                "trial_pass_rate": point,
                "ci_lo": lo,
                "ci_hi": hi,
                "n_tasks": len(tasks),
                "k": k,
            },
        )
    )
    return findings
