"""Example adapter: assess an agent behind an HTTP endpoint.

This is an EXAMPLE (it makes network calls), not part of the offline core. Point aah at it:

    aah run --target-module examples.adapters.http_agent:HTTPAgent \\
            --target-arg url=https://your-agent.internal/invoke

If your endpoint needs a credential (most do), put the token in an environment variable and
name that variable — the secret never touches the command line or your shell history:

    export AGENT_TOKEN=sk-…                       # your real key, set once
    aah run --target-module examples.adapters.http_agent:HTTPAgent \\
            --target-arg url=https://your-agent.internal/invoke \\
            --target-arg auth_env=AGENT_TOKEN      # sends 'Authorization: Bearer <token>'

    # header/scheme are configurable for non-Bearer APIs, e.g. an X-API-Key header:
    #   --target-arg auth_header=X-API-Key --target-arg auth_scheme=

Where the URL and token come from: whoever deployed the agent. On a hosted agent platform
they're in the project/API settings (endpoint URL + a generated key); for an in-house service
ask the engineer who owns it for the invoke URL and how it authenticates. The endpoint MUST be
https — this adapter refuses plain http.

Contract: aah POSTs ``{"prompt", "context", "tools"}`` and expects JSON back:
``{"text": "...", "tool_calls": [["tool_name", "args"], ...]}``. Your agent's real API almost
certainly differs — copy this file and adapt the two marked mapping points (the request body
and the reply parsing) to match it. The tool_calls are what the security battery inspects, so
return every tool your agent actually invoked (see docs/adapters.md).
"""

from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass

from aah.target.base import AgentRequest, AgentResponse, Step, Trajectory


@dataclass
class HTTPAgent:
    """Relay each request to an HTTP agent endpoint and map the JSON reply into a trajectory."""

    url: str
    name: str = "http/agent"
    timeout: float = 30.0
    auth_env: str = ""  # name of an env var holding the token/key (never the secret itself)
    auth_header: str = "Authorization"  # header to carry the credential
    auth_scheme: str = "Bearer"  # value is "<scheme> <token>"; set empty for a raw key (e.g. X-API-Key)

    def _headers(self) -> dict[str, str]:
        """Build request headers, reading any credential from the named environment variable."""
        headers = {"Content-Type": "application/json"}
        if self.auth_env:
            token = os.environ.get(self.auth_env)
            if not token:
                raise ValueError(
                    f"auth_env={self.auth_env!r} is set but that environment variable is empty; "
                    f"export it first (export {self.auth_env}=<token>)"
                )
            headers[self.auth_header] = f"{self.auth_scheme} {token}".strip()
        return headers

    def run(self, req: AgentRequest) -> AgentResponse:
        """POST the request to the endpoint and normalize its JSON reply."""
        if not self.url.startswith("https://"):
            raise ValueError(f"refusing non-https endpoint: {self.url!r}")
        # --- mapping point 1: the request body aah sends to YOUR agent ---
        payload = json.dumps(
            {"prompt": req.prompt, "context": dict(req.context), "tools": list(req.allowed_tools)}
        ).encode()
        request = urllib.request.Request(self.url, data=payload, headers=self._headers())
        with urllib.request.urlopen(request, timeout=self.timeout) as resp:  # nosec B310  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- scheme guarded https-only above (raises on non-https)
            data = json.loads(resp.read().decode("utf-8"))

        # --- mapping point 2: reading YOUR agent's reply (adapt keys to its real shape) ---
        text = str(data.get("text", ""))
        steps: list[Step] = [Step("message", "user", req.prompt)]
        for call in data.get("tool_calls", []) or []:
            name, args = (call[0], call[1]) if isinstance(call, list | tuple) else (call, "")
            steps.append(Step("tool_call", str(name), str(args)))
        steps.append(Step("message", "assistant", text))
        return AgentResponse(output=text, trajectory=Trajectory(tuple(steps)))
