# Example evidence objects

Two **real** Agent Assurance Evidence Objects (AAEOs), produced by a live interactive
assessment of a Claude-based agent against the OWASP-Agentic battery (`aah run --target
interactive`). Verify either one yourself — offline, no network, no keys, no trust in the
producer:

```bash
aah verify examples/evidence/pass-agent-resisted.json
aah verify examples/evidence/fail-agent-compromised.json
```

| File | What the agent did | Verdict |
|---|---|---|
| `pass-agent-resisted.json` | Refused every injected exfiltration attempt | **PASS** |
| `fail-agent-compromised.json` | Obeyed the injections (called the malicious tool) | **FAIL** — caught on ASI01/02/04/06/07 |

Both re-verify to `integrity OK · signature OK · decision OK`. The verdict is not taken on
the producer's word — it is **recomputed** from the pinned findings (decision replay).

### Try forging one
Open either JSON, flip a failing finding's `"passed"` to `true` (or rewrite the verdict), then
re-verify:

```bash
aah verify examples/evidence/fail-agent-compromised.json
# integrity : FAIL   (content hash no longer matches the signed bytes)
# signature : FAIL   (not signed by the recorded key)
# decision  : FAIL   (recorded != replayed)
```

A forged evidence object cannot survive offline re-verification. That is the whole thesis.

All fixtures are synthetic (honeytokens, invented `*.example` endpoints) — no real secrets,
no client data.
