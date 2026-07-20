from aah.audit.ledger import HashChainLedger, seal_evidence
from aah.audit.signer import Ed25519Signer, Ed25519Verifier
from aah.core.canonical import canonical_bytes
from aah.core.evidence import AssuranceEvidenceObject, ScopeStatement
from aah.core.finding import AIVSSScore, Axis, ControlRef, Finding, Severity
from aah.core.hashing import content_hash
from aah.core.manifest import RunManifest
from aah.governance.gate import evaluate_gate
from aah.governance.policy import Policy, RequiredControl


def test_canonical_is_deterministic_and_order_independent():
    a = {"b": 1, "a": [3, 2, 1], "c": {"y": 2, "x": 1}}
    b = {"c": {"x": 1, "y": 2}, "a": [3, 2, 1], "b": 1}
    assert canonical_bytes(a) == canonical_bytes(b)
    assert content_hash(a) == content_hash(b)


def test_aivss_amplification_scales_and_clamps():
    low = AIVSSScore(base=5.0)
    high = AIVSSScore(base=5.0, autonomy=1, tool_use=1, memory=1)
    assert high.score > low.score
    assert (
        AIVSSScore(
            base=10.0, autonomy=1, tool_use=1, memory=1, multi_agent=1, self_modification=1, non_determinism=1
        ).score
        == 10.0
    )


def test_finding_round_trip():
    f = Finding(
        id="x.1",
        axis=Axis.SECURITY,
        title="t",
        passed=False,
        severity=Severity.HIGH,
        asi="ASI06",
        aivss=AIVSSScore(base=8.0, memory=1),
        controls=(ControlRef("OWASP-ASI-2026", "ASI06"),),
        metrics={"a": 1},
    )
    f2 = Finding.from_dict(f.to_dict())
    assert f2.to_dict() == f.to_dict()


def _mini_aeo(findings, policy):
    scope = ScopeStatement(tested="unit", not_tested="everything else", residual_risk="high")
    gate = evaluate_gate(findings, policy)
    return AssuranceEvidenceObject(
        manifest=RunManifest(sut_name="t", model_id="mock", seed=0, policy_version=policy.version),
        findings=findings,
        scope=scope,
        gate=gate.to_dict(),
        policy=policy.to_dict(),
    )


def test_scope_statement_is_mandatory():
    import pytest

    with pytest.raises(ValueError):
        AssuranceEvidenceObject(
            manifest=RunManifest(sut_name="t", model_id="m", seed=0),
            findings=[],
            scope=ScopeStatement(tested="", not_tested="x", residual_risk=""),
        )


def test_sign_verify_and_tamper_detection():
    signer = Ed25519Signer.generate(seed=7)
    aeo = _mini_aeo([Finding(id="e.1", axis=Axis.EVAL, title="ok", passed=True)], Policy())
    seal = seal_evidence(aeo, signer)
    v = Ed25519Verifier()
    assert v.verify(seal.presign_bytes(), seal.signature, seal.public_key_hex)
    # tamper the payload -> signature no longer matches the mutated bytes
    seal.payload["findings"][0]["passed"] = False
    assert not v.verify(seal.presign_bytes(), seal.signature, seal.public_key_hex)


def test_hash_chain_links_and_breaks_on_tamper():
    signer = Ed25519Signer.generate(seed=3)
    ledger = HashChainLedger()
    for i in range(3):
        ledger.append(
            _mini_aeo([Finding(id=f"e.{i}", axis=Axis.EVAL, title="ok", passed=True)], Policy()), signer
        )
    assert ledger.verify_chain()
    ledger.seals[1].payload["producers"] = ["mutated"]
    assert not ledger.verify_chain()


def test_gate_passes_clean_and_fails_on_open_security():
    p = Policy()
    clean = [
        Finding(id="s.ok", axis=Axis.SECURITY, title="resisted", passed=True, aivss=AIVSSScore(base=2.0))
    ]
    assert evaluate_gate(clean, p).verdict == "PASS"
    breach = [
        Finding(
            id="s.bad",
            axis=Axis.SECURITY,
            title="exfil",
            passed=False,
            severity=Severity.CRITICAL,
            asi="ASI06",
            aivss=AIVSSScore(base=8.8, memory=1),
        )
    ]
    res = evaluate_gate(breach, p)
    assert res.verdict == "FAIL" and res.reasons


def test_gate_is_deterministic():
    p = Policy()
    fs = [
        Finding(
            id="s.bad",
            axis=Axis.SECURITY,
            title="x",
            passed=False,
            severity=Severity.HIGH,
            aivss=AIVSSScore(base=8.0),
        )
    ]
    assert evaluate_gate(fs, p).to_dict() == evaluate_gate(fs, p).to_dict()


def test_required_control_capability_threshold():
    # capability 'memory' present but the required control finding is failing -> gate FAIL
    p = Policy(
        fail_on_open_axes=(),
        max_open_severity=Severity.CRITICAL,
        max_aivss=10.0,
        required_controls=(RequiredControl(capability="memory", control_id="ASI06"),),
    )
    findings = [
        Finding(
            id="s.mem",
            axis=Axis.SECURITY,
            title="mem check",
            passed=False,
            severity=Severity.LOW,
            asi="ASI06",
            aivss=AIVSSScore(base=1.0, memory=1),
        )
    ]
    assert evaluate_gate(findings, p).verdict == "FAIL"


def test_ed25519_pem_roundtrip_preserves_key():
    signer = Ed25519Signer.generate()
    pem = signer.to_pem()
    assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    loaded = Ed25519Signer.from_pem(pem)
    # same key: same public key, and a signature from one verifies under the other's pubkey
    assert loaded.public_key_hex == signer.public_key_hex
    sig = loaded.sign(b"payload")
    assert Ed25519Verifier().verify(b"payload", sig, signer.public_key_hex)


def test_from_pem_rejects_non_ed25519_key():
    import pytest
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(ValueError, match="not an Ed25519"):
        Ed25519Signer.from_pem(rsa_pem)
