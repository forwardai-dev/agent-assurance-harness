# Threat-content packs

The **engine** (how a run is scored, sealed, and verified) is deliberately separate from
the **threat content** it runs (the red-team scenarios). Content is data, not code: a
versioned, provenanced, content-addressed **pack**.

This is what makes "keep the security checks up to date" a solved problem *without* ever
coupling the tool to a private database. Freshness comes from public feeds and portable
signed packs — never from a live connection to internal infra.

## Pack format

A pack is a directory:

```
<pack>/
  manifest.json              # identity + provenance + content_hash + optional signature
  scenarios/asi-battery.json # {"scenarios": [ ... ]}
```

`manifest.json`:

```json
{
  "schema": "aah.content-pack/v1",
  "name": "aah-public",
  "version": "2026.07.20",
  "kind": "public",
  "sources": [{"id": "mitre-atlas", "version": "2026.05", "live": true, "...": "..."}],
  "scenarios_file": "scenarios/asi-battery.json",
  "content_hash": "sha256:…",
  "signature": {"algo": "ed25519", "public_key": "…", "sig": "…"}   // optional
}
```

`content_hash` is a deterministic SHA-256 over the scenarios payload. **Loading always
recomputes it and rejects a mismatch** — a pack cannot be tampered with silently. Every
assurance run records the pack `name@version#hash` in its manifest, so an AAEO pins exactly
which threat content it was tested against (reproducibility).

## The public pack

`aah/content/packs/public/` ships in the wheel and is the default for `aah run`. Edit
scenarios in `aah/attack/generators/battery.py` (the human-editable source), then:

```bash
python scripts/regen_public_pack.py --version 2026.08.01
```

A test (`test_default_battery_matches_authoring_source`) fails if the code and the pack
ever drift.

## Keeping the public checks fresh (feeds + CI)

`aah/content/feeds.py` reads the current version of each **public authoritative source**:

| Source | Live? | How |
|---|---|---|
| MITRE ATLAS | yes | latest `atlas-data` GitHub release tag |
| Anthropic research | yes | hash of the published research slug set |
| OWASP-ASI Top 10 | no | pinned; reviewed by hand (no machine version) |
| AIVSS spec | no | pinned; reviewed by hand |

`scripts/update_threat_content.py` reports drift; `--write` bumps changed source
versions in the manifest (**never** scenarios). The
`.github/workflows/threat-content-update.yml` cron runs weekly and, on drift, **opens a
review PR** — it never auto-merges. Automation surfaces drift; a human authors any new
red-team scenarios. Everything degrades gracefully offline.

## Private / proprietary content — signed packs, never a DB connection

If you maintain continually-updated proprietary threat intel, **do not** give the harness
access to your database. Instead, export a **signed pack** and load it:

```
┌─ your infra (private) ─────────────┐        ┌─ the harness (public engine) ─┐
│ internal DB / intel                │ signed │ load_pack(path,               │
│   → exporter → write_pack(signer)  │  pack  │   require_signature=True,     │
│   (Ed25519 private key, in env)    │ ─────▶ │   trusted_keys=[pubkey])      │
└────────────────────────────────────┘        └───────────────────────────────┘
```

Only the **signed pack** crosses the boundary. The engine verifies the Ed25519 signature
(over `name + version + content_hash`) and, with `trusted_keys`, that it was signed by a
key you trust:

```bash
aah run --content-pack ./acme-private --require-signature --trusted-key <pubkey-hex>
aah pack ./acme-private --trusted-key <pubkey-hex>   # inspect + verify offline
```

A private pack that is tampered with (hash mismatch), unsigned (when a signature is
required), forged (signature doesn't verify), or signed by an untrusted key is **rejected**
— all offline, no network, no trust in the producer.

### Producing a signed pack

`aah.content.write_pack(dest, name=…, version=…, kind="private", scenarios=[…], signer=…)`
is the one supported way to emit a pack. The signing **private key lives only in your
infra** (an env var / secret), never in a repo. A reference exporter that reads an internal
source and emits a signed pack lives outside this public repo, in your own tooling.

### Auto-discovery via entry points

An installed private-pack *package* can advertise its pack directory under the
`aah.content_packs` entry-point group; `aah.content.discover_pack_paths()` resolves them.
This lets authorized users `pip install acme-aah-packs` and have the harness find them —
still just signed data, still no infra coupling.
