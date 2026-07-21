"""Generic BYO-agent adapters — wrap any callable as a TargetAgent.

``CallableAgent`` is the simplest bridge: give it a function that takes (prompt, context,
tools) and returns either a plain string (the agent's answer) or a dict
``{"text": ..., "tool_calls": [(name, args), ...]}``. The tool calls are what the security
battery inspects, so return them faithfully (see docs/adapters.md).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .base import AgentRequest, AgentResponse, Step, Trajectory

AgentFn = Callable[[str, dict, tuple], Any]


@dataclass
class CallableAgent:
    """Wrap a plain function ``fn(prompt, context, tools)`` as a TargetAgent."""

    fn: AgentFn
    name: str = "callable/agent"
    _: Any = field(default=None, repr=False)

    def run(self, req: AgentRequest) -> AgentResponse:
        """Invoke the wrapped function and normalize its result into an AgentResponse."""
        result = self.fn(req.prompt, dict(req.context), tuple(req.allowed_tools))
        tool_calls: list = []
        if isinstance(result, str):
            text = result
        elif isinstance(result, dict):
            text = str(result.get("text", ""))
            tool_calls = result.get("tool_calls", []) or []
        else:
            raise TypeError("agent fn must return a str or a {'text', 'tool_calls'} dict")
        steps: list[Step] = [Step("message", "user", req.prompt)]
        for call in tool_calls:
            name, args = call if isinstance(call, tuple) else (call, "")
            steps.append(Step("tool_call", str(name), str(args)))
        steps.append(Step("message", "assistant", text))
        return AgentResponse(output=text, trajectory=Trajectory(tuple(steps)))
