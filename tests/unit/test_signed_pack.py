"""A private pack is trusted via an Ed25519 signature — never by touching private infra."""

import json

import pytest

from aah.audit.signer import Ed25519Signer
from aah.content.pack import (
    ContentPackError,
    discover_pack_paths,
    load_bundled_public,
    load_pack,
    write_pack,
)


def _scenarios():
    return list(load_bundled_public().scenarios)


def test_signed_pack_roundtrips_and_verifies(tmp_path):
    signer = Ed25519Signer.generate(seed=7)
    write_pack(
        tmp_path,
        name="acme-private",
        version="2026.07.20",
        kind="private",
        scenarios=_scenarios(),
        signer=signer,
    )
    pack = load_pack(tmp_path)
    assert pack.signed
    assert pack.signer_pubkey == signer.public_key_hex
    assert pack.kind == "private"


def test_require_signature_rejects_unsigned(tmp_path):
    write_pack(tmp_path, name="p", version="1", kind="private", scenarios=_scenarios())
    with pytest.raises(ContentPackError, match="signature is required"):
        load_pack(tmp_path, require_signature=True)


def test_untrusted_signer_is_rejected(tmp_path):
    signer = Ed25519Signer.generate(seed=7)
    write_pack(tmp_path, name="p", version="1", kind="private", scenarios=_scenarios(), signer=signer)
    other = Ed25519Signer.generate(seed=99).public_key_hex
    with pytest.raises(ContentPackError, match="untrusted signer"):
        load_pack(tmp_path, trusted_keys=[other])
    # the real key passes
    assert load_pack(tmp_path, trusted_keys=[signer.public_key_hex]).signed


def test_tampered_signed_pack_is_rejected(tmp_path):
    signer = Ed25519Signer.generate(seed=7)
    write_pack(tmp_path, name="p", version="1", kind="private", scenarios=_scenarios(), signer=signer)
    # mutate a scenario but keep the (now-stale) content_hash + signature
    sfile = tmp_path / "scenarios" / "asi-battery.json"
    payload = json.loads(sfile.read_text())
    payload["scenarios"][0]["title"] = "tampered"
    sfile.write_text(json.dumps(payload))
    with pytest.raises(ContentPackError, match="content hash mismatch"):
        load_pack(tmp_path)


def test_forged_signature_is_rejected(tmp_path):
    # sign, then swap the public key to a different one: signature no longer verifies
    signer = Ed25519Signer.generate(seed=7)
    write_pack(tmp_path, name="p", version="1", kind="private", scenarios=_scenarios(), signer=signer)
    mpath = tmp_path / "manifest.json"
    m = json.loads(mpath.read_text())
    m["signature"]["public_key"] = Ed25519Signer.generate(seed=42).public_key_hex
    mpath.write_text(json.dumps(m))
    with pytest.raises(ContentPackError, match="invalid signature"):
        load_pack(tmp_path)


def test_discover_pack_paths_reads_entry_points(tmp_path):
    class _EP:
        def load(self_inner):
            return str(tmp_path)

    paths = discover_pack_paths(entry_points_fn=lambda: [_EP()])
    assert paths == [tmp_path]
