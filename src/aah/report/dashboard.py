"""Static, self-contained HTML dashboard rendering an Assurance Evidence Object.

No external calls, no JS frameworks — a single offline file an auditor can open. Panels:
gate verdict hero + offline-verify badge, three-axis scorecard, ASI coverage heatmap,
findings table, and the mandatory residual-risk statement.
"""

from __future__ import annotations

import html

from ..core.evidence import AssuranceEvidenceObject
from ..core.finding import Axis
from ..verify.verifier import VerifyResult

ASI_NAMES = {
    "ASI01": "Goal Hijack",
    "ASI02": "Tool Misuse",
    "ASI03": "Identity/Privilege",
    "ASI04": "Supply Chain",
    "ASI05": "Code Execution",
    "ASI06": "Memory Poisoning",
    "ASI07": "Inter-Agent Comms",
    "ASI08": "Cascading Failures",
    "ASI09": "Human Trust",
    "ASI10": "Rogue Agents",
}
_SEV_COLOR = {
    "info": "#e8dfd0",
    "low": "#dcfce7",
    "medium": "#fef3c7",
    "high": "#fed7aa",
    "critical": "#fee2e2",
}


def render(aeo: AssuranceEvidenceObject, verify: VerifyResult | None, this_hash: str) -> str:
    """Render the evidence object to a self-contained HTML dashboard."""
    g = aeo.gate or {}
    verdict = g.get("verdict", "UNKNOWN")
    vcolor = "#0f7a52" if verdict == "PASS" else "#b91c1c"
    m = aeo.manifest

    # three axes
    def axis_stats(ax):
        """Aggregate pass/fail counts per assurance axis."""
        fs = [f for f in aeo.findings if f.axis == ax]
        openf = [f for f in fs if not f.passed]
        return len(fs), len(openf)

    e_n, e_open = axis_stats(Axis.EVAL)
    s_n, s_open = axis_stats(Axis.SECURITY)
    gv_n, gv_open = axis_stats(Axis.GOVERNANCE)
    max_aivss = aeo.max_aivss()

    # ASI heatmap
    worst: dict[str, str] = {}
    for f in aeo.findings:
        if f.asi:
            sev = f.severity.value if not f.passed else "info"
            if ASI_NAMES.get(f.asi) and (_rank(sev) > _rank(worst.get(f.asi, "info"))):
                worst[f.asi] = sev
    heat = ""
    for asi in [f"ASI{str(i).zfill(2)}" for i in range(1, 11)]:
        tested = asi in worst or any(f.asi == asi for f in aeo.findings)
        sev = worst.get(asi, "info" if tested else "untested")
        color = _SEV_COLOR.get(sev, "#f3f4f6")
        label = "tested" if tested else "not tested"
        heat += (
            f'<div class="cell" style="background:{color}">'
            f"<b>{asi}</b><span>{html.escape(ASI_NAMES[asi])}</span>"
            f"<em>{label}</em></div>"
        )

    # findings rows
    rows = ""
    for f in sorted(aeo.findings, key=lambda x: (x.passed, -(x.aivss.score if x.aivss else 0))):
        av = f.aivss.score if f.aivss else ""
        st = "PASS" if f.passed else "OPEN"
        stc = "#0f7a52" if f.passed else "#b91c1c"
        joint = f.metrics.get("joint_risk_success_and_missed")
        jointtxt = " · <b style='color:#b91c1c'>joint-risk</b>" if joint else ""
        rows += (
            f"<tr><td>{html.escape(f.asi or '-')}</td><td>{html.escape(f.axis.value)}</td>"
            f"<td>{html.escape(f.title)}</td><td>{html.escape(f.severity.value)}</td>"
            f"<td>{av}</td><td style='color:{stc};font-weight:700'>{st}{jointtxt}</td></tr>"
        )

    vbadge = ""
    if verify is not None:
        ok = verify.ok
        vbadge = (
            f'<span class="vb" style="background:{"#dcfce7" if ok else "#fee2e2"};'
            f'color:{"#0f5a2c" if ok else "#8f1b1b"}">verify re-checked offline: '
            f"{'OK' if ok else 'FAILED'}</span>"
        )

    scope = aeo.scope
    caveats = "".join(f"<li>{html.escape(c)}</li>" for c in scope.caveats)

    # Plain-English interpretation of the verdict, for readers who won't read a findings table.
    tested_asi = sum(1 for asi in ASI_NAMES if any(f.asi == asi for f in aeo.findings))
    n_checks = len(aeo.findings)
    if verdict == "PASS":
        plain = (
            f"<b>In plain English:</b> this agent was run through {n_checks} checks — correctness "
            f"tasks plus {tested_asi} known agentic-AI attacks — and it held: nothing dangerous got "
            f"through, so the gate <b>passed</b>. Everything below is a signed receipt anyone can "
            f"re-verify offline, with no need to trust the producer. A PASS means the agent resisted "
            f"<i>these specific</i> tests — not a guarantee against every possible attack (see "
            f"<b>Scope &amp; residual risk</b> at the bottom)."
        )
        pcolor, pbg = "#0f7a52", "#eafaf1"
    else:
        plain = (
            f"<b>In plain English:</b> this agent <b>failed</b> at least one check, so the gate "
            f"<b>blocked</b> it from shipping. <b>Gate reasons</b> below says exactly why, and the "
            f"<b>Findings</b> table shows which of the {tested_asi} attacks got through. Fix those, "
            f"re-run, and the gate flips to PASS."
        )
        pcolor, pbg = "#b91c1c", "#fdecec"

    return _TEMPLATE.format(
        plain=plain,
        pcolor=pcolor,
        pbg=pbg,
        verdict=verdict,
        vcolor=vcolor,
        vbadge=vbadge,
        this_hash=html.escape(this_hash),
        model=html.escape(m.model_id),
        seed=m.seed,
        hv=html.escape(m.harness_version),
        pv=html.escape(m.policy_version),
        dh=html.escape(m.dataset_hash[:19]),
        ts=html.escape(m.created_at),
        reasons=("".join(f"<li>{html.escape(r)}</li>" for r in g.get("reasons", [])) or "<li>none</li>"),
        e_n=e_n,
        e_open=e_open,
        s_n=s_n,
        s_open=s_open,
        gv_n=gv_n,
        gv_open=gv_open,
        max_aivss=max_aivss,
        heat=heat,
        rows=rows,
        tested=html.escape(scope.tested),
        not_tested=html.escape(scope.not_tested),
        residual=html.escape(scope.residual_risk),
        caveats=caveats,
        producers=", ".join(html.escape(p) for p in aeo.producers),
    )


def _rank(sev: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, -1)


_TEMPLATE = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Agent Assurance Evidence</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:Inter,system-ui,sans-serif;background:#f7f8fa;color:#18212f;line-height:1.5;font-size:14px;padding:1.2rem}}
.wrap{{max-width:1000px;margin:0 auto}}
.hero{{background:{vcolor};color:#fff;border-radius:12px;padding:1.4rem 1.6rem;margin-bottom:1rem}}
.hero .v{{font-size:2.2rem;font-weight:800;letter-spacing:.02em}}
.hero .sub{{font-family:ui-monospace,monospace;font-size:.72rem;opacity:.92;margin-top:.4rem;word-break:break-all}}
.vb{{display:inline-block;font-size:.7rem;font-weight:700;padding:.2rem .6rem;border-radius:20px;margin-top:.5rem}}
.pins{{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:.6rem;font-size:.72rem;font-family:ui-monospace,monospace;opacity:.95}}
.pins span{{background:rgba(255,255,255,.15);padding:.15rem .5rem;border-radius:5px}}
.grid3{{display:grid;grid-template-columns:repeat(3,1fr);gap:.8rem;margin-bottom:1rem}}
.tile{{background:#fff;border:1px solid #e2e6ec;border-radius:10px;padding:.9rem 1.1rem}}
.tile .k{{font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;color:#5b6675;font-weight:700}}
.tile .n{{font-size:1.7rem;font-weight:800;color:#123c69}}
.card{{background:#fff;border:1px solid #e2e6ec;border-radius:10px;padding:1rem 1.2rem;margin-bottom:1rem}}
h2{{font-size:1rem;color:#123c69;margin-bottom:.6rem;font-family:Georgia,serif}}
.heat{{display:grid;grid-template-columns:repeat(5,1fr);gap:.4rem}}
.cell{{border:1px solid #e2e6ec;border-radius:8px;padding:.5rem;text-align:center;font-size:.7rem}}
.cell b{{display:block;color:#123c69}}.cell span{{display:block;color:#5b6675;font-size:.66rem}}.cell em{{font-size:.6rem;color:#5b6675}}
table{{width:100%;border-collapse:collapse;font-size:.82rem}}
th{{text-align:left;background:#111d35;color:#fff;padding:.45rem .6rem;font-size:.66rem;text-transform:uppercase}}
td{{padding:.45rem .6rem;border-bottom:1px solid #eee;vertical-align:top}}
.warn{{background:#fef3c7;border:1px solid #f0d48a;border-radius:8px;padding:.9rem 1.1rem;font-size:.85rem}}
.warn h2{{color:#a16207}} ul{{margin:.3rem 0 0 1.1rem}} .foot{{color:#5b6675;font-size:.72rem;text-align:center;margin-top:1rem}}
.plain{{background:{pbg};border-left:4px solid {pcolor};border-radius:8px;padding:.8rem 1rem;margin-bottom:1rem;font-size:.9rem}}
.hint{{font-size:.75rem;color:#5b6675;margin:-.35rem 0 .7rem;font-weight:400;line-height:1.45}}
.cap{{font-size:.66rem;color:#5b6675;margin-top:.3rem;line-height:1.35}}
.terms{{font-size:.72rem;color:#5b6675;margin-bottom:1rem;line-height:1.55}}
</style></head><body><div class="wrap">
<div class="hero"><div style="font-size:.7rem;letter-spacing:.1em;text-transform:uppercase;opacity:.85">Agent Assurance Evidence Object</div>
<div class="v">GATE: {verdict}</div>{vbadge}
<div class="pins"><span>model={model}</span><span>seed={seed}</span><span>harness={hv}</span><span>policy={pv}</span><span>dataset={dh}</span><span>ts={ts}</span></div>
<div class="sub">content-hash {this_hash}</div></div>
<div class="plain">{plain}</div>
<div class="grid3">
<div class="tile"><div class="k">Eval (correctness)</div><div class="n">{e_open}<span style="font-size:.9rem;color:#5b6675"> open / {e_n}</span></div><div class="cap">correctness checks the agent got wrong / total run</div></div>
<div class="tile"><div class="k">Security (max AIVSS)</div><div class="n">{max_aivss}<span style="font-size:.9rem;color:#5b6675"> · {s_open} open / {s_n}</span></div><div class="cap">worst attack severity (0&#8211;10) &middot; attacks not stopped / total</div></div>
<div class="tile"><div class="k">Governance</div><div class="n">{gv_n}<span style="font-size:.9rem;color:#5b6675"> controls</span></div><div class="cap">policy controls required to pass</div></div>
</div>
<p class="terms"><b>Key terms &#8212;</b> <b>AAEO</b>: this signed evidence file (the "receipt"). <b>ASI</b>: an OWASP category of agentic-AI attack. <b>AIVSS</b>: a 0&#8211;10 attack-severity score. <b>Gate</b>: the ship/block decision, computed deterministically from the results &#8212; no AI in the decision itself.</p>
<div class="card"><h2>Gate reasons</h2><p class="hint">Why the gate reached its verdict &#8212; empty means nothing blocked it.</p><ul>{reasons}</ul><p style="font-size:.72rem;color:#5b6675;margin-top:.4rem">Producers: {producers}. Decision is a pure deterministic function of the pinned inputs — no LLM in the money-path.</p></div>
<div class="card"><h2>OWASP-Agentic ASI coverage</h2><p class="hint">The 10 ways an agentic AI can be attacked (OWASP Agentic Top-10). "tested" = we ran that attack against this agent; the outcome is in Findings below.</p><div class="heat">{heat}</div></div>
<div class="card"><h2>Findings</h2><p class="hint">One row per check. <b>PASS</b> = the agent handled it safely. Severity rises info &#8594; low &#8594; medium &#8594; high &#8594; critical: an active data leak (a tool call to an attacker) scores high/critical, while merely repeating a secret <i>while refusing</i> scores low.</p><table><thead><tr><th>ASI</th><th>Axis</th><th>Title</th><th>Severity</th><th>AIVSS</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="warn"><h2>Scope &amp; residual risk (mandatory)</h2>
<p><b>Tested:</b> {tested}</p><p><b>NOT tested:</b> {not_tested}</p><p><b>Residual risk:</b> {residual}</p>
<ul>{caveats}</ul></div>
<div class="foot">Informative control mapping, NOT certification. Integrity != third-party attestation. Behavioral testing generates evidence, not a safety guarantee.</div>
</div></body></html>"""
