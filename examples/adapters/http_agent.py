"""Example adapter: assess an agent behind an HTTP endpoint.

This is an EXAMPLE (it makes network calls), not part of the offline core. Point aah at it:

    aah run --target-module examples.adapters.http_agent:HTTPAgent \\
            --target-arg url=https://your-agent.internal/invoke

Your endpoint receives ``{"prompt", "context", "tools"}`` and should return JSON
``{"text": "...", "tool_calls": [["tool_name", "args"], ...]}``. Adapt the request/response
mapping to your agent's real API. The tool_calls are what the security battery inspects, so
return every tool your agent actually invoked (see docs/adapters.md).
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass

from aah.target.base import AgentRequest, AgentResponse, Step, Trajectory


@dataclass
class HTTPAgent:
    """Relay each request to an HTTP agent endpoint and map the JSON reply into a trajectory."""

    url: str
    name: str = "http/agent"
    timeout: float = 30.0

    def run(self, req: AgentRequest) -> AgentResponse:
        """POST the request to the endpoint and normalize its JSON reply."""
        if not self.url.startswith("https://"):
            raise ValueError(f"refusing non-https endpoint: {self.url!r}")
        payload = json.dumps(
            {"prompt": req.prompt, "context": dict(req.context), "tools": list(req.allowed_tools)}
        ).encode()
        request = urllib.request.Request(self.url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=self.timeout) as resp:  # nosec B310 - https-guarded above
            data = json.loads(resp.read().decode("utf-8"))

        text = str(data.get("text", ""))
        steps: list[Step] = [Step("message", "user", req.prompt)]
        for call in data.get("tool_calls", []) or []:
            name, args = (call[0], call[1]) if isinstance(call, list | tuple) else (call, "")
            steps.append(Step("tool_call", str(name), str(args)))
        steps.append(Step("message", "assistant", text))
        return AgentResponse(output=text, trajectory=Trajectory(tuple(steps)))
