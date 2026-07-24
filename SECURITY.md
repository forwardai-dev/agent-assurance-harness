# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security Advisories
(**Security → Report a vulnerability**) on this repository, rather than opening a public
issue. We aim to acknowledge within a few business days.

## Scope and threat model

`aah` is an offline, deterministic reference implementation. Its security-relevant guarantees
and their limits are stated in the evidence object's residual-risk statement and in the README
"Honest by design" section. In short:

- **Tamper-evidence** holds from the artifact alone (hash chain + Ed25519 signature + decision
  replay). **Authorship** requires a trust anchor the verifier pins (`aah verify --trusted-key`);
  without one, verification reports `TAMPER-EVIDENT ONLY`.
- The security battery's result is only as faithful as the adapter you wire in — it scores the
  tool calls your adapter reports.

## Synthetic secrets in fixtures

This repo is a red-team harness: fixtures under `tests/`,
`src/aah/content/packs/*/scenarios/`, and `src/aah/attack/generators/battery.py` deliberately
contain **synthetic** secrets (e.g. `sk-ABCD…`) that attack scenarios attempt to exfiltrate.
These are not real credentials; `.gitleaks.toml` allowlists those surfaces so secret scans stay
signal-only.

## Static analysis

CI runs Ruff, mypy, and Bandit. Semgrep and gitleaks pass clean; a small number of audit-level
Semgrep findings are triaged inline with `# nosemgrep:` and a justification (an https-guarded
`urlopen`, an intentional operator-supplied adapter import, and a Python-3.7 compat rule that
does not apply to this `requires-python >= 3.11` project).
