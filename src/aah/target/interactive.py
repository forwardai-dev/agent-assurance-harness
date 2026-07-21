"""Interactive human-relay target — assess ANY agent with zero integration code.

``aah run --target interactive`` shows you each task and each attack (with the injected
content), you run it through your agent however you like — a browser chatbot, an internal
API, a CLI — and paste back what the agent said and which tools it called. aah records that
as the trajectory and scores it exactly as it would a wired adapter. Fully offline, no keys.

The human is the bridge to the agent, so you can test a black box you can't import.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .base import AgentRequest, AgentResponse, Step, Trajectory

_TERM = "."  # a line containing only this ends a paste block


@dataclass
class InteractiveAgent:
    """Prompt an operator to relay a real agent's responses (human-in-the-loop)."""

    name: str = "interactive:human-relay"
    readline: Callable[[], str] = field(default=input)
    write: Callable[[str], None] = field(default=print)

    def run(self, req: AgentRequest) -> AgentResponse:
        """Show the task + injected content, then capture the relayed answer and tool calls."""
        w = self.write
        w("")
        w(f"── [{req.task_id}] ─────────────────────────────────────────")
        w(f"PROMPT: {req.prompt}")
        for k in ("tool_output", "memory"):
            if req.context.get(k):
                w(f"  ({k}): {req.context[k]}")
        if req.allowed_tools:
            w(f"  allowed tools: {', '.join(req.allowed_tools)}")
        w(f"Run this through YOUR agent, then paste its final answer. End with a line: '{_TERM}'")
        text = "\n".join(self._read_block())
        w(f"Tools your agent CALLED (one per line as name=args), then '{_TERM}' (blank = none):")
        tool_lines = self._read_block()

        steps: list[Step] = [Step("message", "user", req.prompt)]
        for line in tool_lines:
            if not line.strip():
                continue
            name, _, args = line.partition("=")
            steps.append(Step("tool_call", name.strip(), args.strip()))
        steps.append(Step("message", "assistant", text))
        return AgentResponse(output=text, trajectory=Trajectory(tuple(steps)))

    def _read_block(self) -> list[str]:
        """Read lines until a lone terminator line or EOF."""
        lines: list[str] = []
        while True:
            try:
                line = self.readline()
            except EOFError:
                break
            if line.strip() == _TERM:
                break
            lines.append(line)
        return lines
