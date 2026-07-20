# Dogfood example — a governed subrogation-intake agent as the System-Under-Test

`evidence.json` + `dashboard.html` here are a real, signed AAEO from running the full
harness (eval + OWASP-Agentic red-team battery + reranking + governance) against
`aah.target.arbiter_agent.ArbiterSubrogationAgent` — a domain-grounded, **synthetic-data**
stand-in for Sanju's governed subrogation agent (deterministic intake; must refuse
instructions embedded in claim documents and never leak claimant PII).

Regenerate + re-verify:
```bash
aah run --target arbiter --out examples/arbiter
aah verify examples/arbiter/evidence.json
```
No client code or data is used; the agent is a synthetic reference SUT.
