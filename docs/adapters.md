# Pointing aah at your agent (BYO-agent)

`aah` is model-agnostic: any agent is assessed through one small adapter that implements the
`TargetAgent` protocol. There are three ways to connect one, easiest first.

## 1. Interactive — test any agent, zero code

```bash
aah run --target interactive
```

aah shows you each task and each attack (including the injected content). You run it through
your agent **however you like** — a browser chatbot, an internal API, a CLI — and paste back
what the agent said and which tools it called. aah records that as the trajectory and scores
it. Fully offline, no keys, no integration. This is the fastest way to assess a black box.

Per prompt you paste:
- the agent's final answer, then a line with just `.`
- the tools it called (one per line as `name=args`), then `.` (blank = none)

## 2. Callable — wrap a Python function

```python
from aah.target.adapters import CallableAgent

def my_agent(prompt, context, tools):
    # ... call your real agent ...
    return {"text": "the answer", "tool_calls": [("http_post", "https://api/…")]}
    # or just: return "the answer"

target = CallableAgent(my_agent, name="mycompany/agent-v3")
```

Run it from a short script with `run_assurance(target=target, ...)`, or expose it as a factory
and load it from the CLI (below).

## 3. Custom adapter — load from the CLI

Implement the protocol (a `.name` and a `.run(AgentRequest) -> AgentResponse`), then:

```bash
aah run --target-module mypkg.adapters:MyAgent --target-arg url=https://agent.internal/invoke
```

`--target-module` is `module.path:ClassOrFactory`; each `--target-arg key=value` is passed to
it. See [`examples/adapters/http_agent.py`](../examples/adapters/http_agent.py) for a working
HTTP example.

## The one rule that matters

The security battery detects an attack succeeding by **inspecting the trajectory** — did your
agent call `http_post` to `attacker.example`, did it emit a leaked secret. So your adapter
**must faithfully record every tool call and the real output**. If you drop the tool calls and
return only the final text, a real exfiltration will look like a PASS.

This is also the honest scope boundary (it's in every evidence object's residual-risk
statement): aah observes the actions your adapter reports — it does not intercept the agent at
the network layer. A network-tap adapter for higher-fidelity capture is a v2 direction.

## The protocol (for reference)

```python
class TargetAgent(Protocol):
    name: str
    def run(self, req: AgentRequest) -> AgentResponse: ...

# req:  .prompt  .context (injected tool_output / memory)  .allowed_tools
# resp: AgentResponse(output=<final text>, trajectory=Trajectory(<Steps>))
# Step(kind="tool_call"|"message"|"tool_result", name=<tool/role>, content=<args/text>)
```
