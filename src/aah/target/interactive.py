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
    _intro_shown: bool = field(default=False, repr=False)

    def _show_intro(self) -> None:
        """One-time explainer so the operator knows what to enter before the first task."""
        w = self.write
        w("")
        w("═══ INTERACTIVE MODE — you relay a REAL agent by hand ═══")
        w("This is NOT a chatbot. For each item below, do three things:")
        w("  1. Take the PROMPT and run it through the agent you're testing")
        w("     (a chatbot tab, an internal API, a CLI — however you reach it).")
        w(
            f"  2. Paste what YOUR agent replied — its final answer, not a new question — then a line with just '{_TERM}'."
        )
        w(f"  3. Paste the tool calls it made (name=args, one per line), or just '{_TERM}' for none.")
        w("aah scores what your agent actually did — offline, no keys. Press Ctrl-C to quit.")

    def run(self, req: AgentRequest) -> AgentResponse:
        """Show the task + injected content, then capture the relayed answer and tool calls."""
        w = self.write
        if not self._intro_shown:
            self._show_intro()
            self._intro_shown = True
        w("")
        w(f"── [{req.task_id}] ─────────────────────────────────────────")
        w(f"PROMPT: {req.prompt}")
        for k in ("tool_output", "memory"):
            if req.context.get(k):
                w(f"  ({k}): {req.context[k]}")
        if req.allowed_tools:
            w(f"  allowed tools: {', '.join(req.allowed_tools)}")
        w("↳ Run the PROMPT above through the agent you're testing, then paste what")
        w(f"  YOUR agent replied (its final answer, NOT a new question). End with '{_TERM}' on its own line:")
        text = "\n".join(self._read_block())
        w(
            f"↳ Tool calls YOUR agent made (one per line, e.g. http_post=https://…), or just '{_TERM}' for none:"
        )
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
