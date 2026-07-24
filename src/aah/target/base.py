"""The plug-in target-agent interface — the System-Under-Test (SUT) seam.

Any agent (mock, HTTP/OpenAI-compatible, interactive, Arbiter) is assessed through this
one Protocol, so the harness is model-agnostic and BYO-agent. Offline-first: the default
registry target is a deterministic scripted mock.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class Step:
    """One step in an agent trajectory (a tool call or text output)."""

    kind: str  # "message" | "tool_call" | "tool_result"
    name: str  # tool name or role
    content: str


@dataclass(frozen=True)
class Trajectory:
    """An ordered sequence of agent steps."""

    steps: tuple[Step, ...] = ()

    def tool_calls(self) -> list[Step]:
        """Return the names of tools called in this trajectory."""
        return [s for s in self.steps if s.kind == "tool_call"]

    def text(self) -> str:
        """Return the concatenated text outputs of this trajectory."""
        return "\n".join(f"{s.kind}:{s.name}:{s.content}" for s in self.steps)


@dataclass(frozen=True)
class AgentRequest:
    """A request handed to a target agent."""

    task_id: str
    prompt: str
    context: dict = field(default_factory=dict)  # tool outputs, memory, injected content
    allowed_tools: tuple[str, ...] = ()


@dataclass(frozen=True)
class AgentResponse:
    """A target agent's response: its trajectory and final answer."""

    output: str
    trajectory: Trajectory = Trajectory()

    def called(self, tool: str) -> bool:
        """True if the named tool was called in the response trajectory."""
        return any(s.name == tool for s in self.trajectory.tool_calls())


class TargetAgent(Protocol):
    """Protocol every target agent adapter implements."""

    name: str

    def run(self, req: AgentRequest) -> AgentResponse:
        """Run the agent on a request and return its response."""
        ...
