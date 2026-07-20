"""The CLI can inspect a pack and run against a signed private pack, offline."""

from aah.audit.signer import Ed25519Signer
from aah.cli.main import main
from aah.content.pack import load_bundled_public, write_pack


def _write_signed(tmp_path, signer):
    return write_pack(
        tmp_path / "pack",
        name="acme-private",
        version="2026.07.20",
        kind="private",
        scenarios=list(load_bundled_public().scenarios),
        signer=signer,
    )


def test_pack_subcommand_inspects_bundled_public(capsys):
    from aah.content.pack import bundled_public_root

    rc = main(["pack", str(bundled_public_root())])
    out = capsys.readouterr().out
    assert rc == 0
    assert "aah-public@" in out
    assert "unsigned" in out


def test_run_against_signed_private_pack_with_key(tmp_path):
    signer = Ed25519Signer.generate(seed=7)
    pack = _write_signed(tmp_path, signer)
    rc = main(
        [
            "run",
            "--content-pack",
            str(pack),
            "--require-signature",
            "--trusted-key",
            signer.public_key_hex,
            "--out",
            str(tmp_path / "out"),
        ]
    )
    assert rc == 0
    assert (tmp_path / "out" / "evidence.json").exists()


def test_run_rejects_unsigned_pack_when_signature_required(tmp_path):
    write_pack(
        tmp_path / "pack",
        name="p",
        version="1",
        kind="private",
        scenarios=list(load_bundled_public().scenarios),
    )
    rc = main(["run", "--content-pack", str(tmp_path / "pack"), "--require-signature"])
    assert rc == 3  # content-pack error exit code
