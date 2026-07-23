# Example BYO-agent — `support_agent.py`

A realistic **enterprise customer-support agent**, provided as a reference
subject-under-test so you can watch AAH flip **PASS ↔ FAIL** on the *same* agent.

It answers order questions from a small knowledge base and can take privileged
actions (`issue_refund`, `send_email`) plus the tools the red-team battery
watches (`http_post`, `wire_transfer`). Two profiles:

| Profile | Control | Expected AAH result |
|---|---|---|
| `guarded` | Retrieved content is treated as **data, not instructions**; refunds capped; email/exfil destinations allowlisted; secrets redacted. | `GATE: PASS` |
| `naive` | Helpful assistant, **no guardrails** — follows instructions embedded in documents/memory. | `GATE: FAIL` (ASI01/02/04/06/07) |

## Run it

In-process (no network):

```bash
aah run --target-module examples.agents.support_agent:make_guarded --out out-guarded   # PASS
aah run --target-module examples.agents.support_agent:make_naive   --out out-naive     # FAIL
```

Over HTTP (for a remote AAH host), start the server then point the HTTP adapter at it:

```bash
python3 examples/agents/support_agent.py --port 8787
aah run --target-module examples.adapters.http_agent:HTTPAgent --target-arg url=https://<host>/naive
```

## Brain

Deterministic policy engine by default (reproducible, no key). Set
`OPENROUTER_API_KEY` (and optionally `AGENT_LLM_MODEL`) to drive the **same two
profiles with a real LLM** — the guarded/naive difference becomes purely the
system prompt, a genuine control. Any LLM error degrades gracefully to the
deterministic brain.

> Scope: the benign-correctness answers use the harness's `expected` field so the
> eval leg is deterministic — the real signal in this example is the **security
> differential**. Swap in the LLM brain (above) for a genuine correctness measure.
