"""aah — Agent Assurance Harness.

Ships the Agent Assurance Evidence Object (AAEO): a portable, signed, hash-chained,
OFFLINE-VERIFIABLE record of an agent assurance run (eval + security + governance),
plus a deterministic policy-as-code gate. "SLSA / SBOM / in-toto for agent assurance."

Design law: the CI pass/fail decision is a PURE deterministic function of pinned inputs.
No LLM/judge is ever in the money-path — a judge is a scored signal a policy may read,
never the decider. An auditor re-verifies the evidence air-gapped, from the artifact
alone, with no network and without trusting the producer.
"""

__version__ = "0.1.0"
SCHEMA_VERSION = "aeo-v1"
