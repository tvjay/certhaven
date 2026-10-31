from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509

from certmgr.crypto import bundle, certs, keys
from certmgr.crypto.vault import Vault


def test_parse_sans_detects_types():
    names = certs.parse_sans("www.example.test, 10.0.0.1\nDNS:*.apps.example.test\nadmin@example.test\n"
                             "https://example.test/x\nIP:::1\nwww.example.test")
    assert names == [
        x509.DNSName("www.example.test"),
        x509.IPAddress(__import__("ipaddress").ip_address("10.0.0.1")),
        x509.DNSName("*.apps.example.test"),
        x509.RFC822Name("admin@example.test"),
        x509.UniformResourceIdentifier("https://example.test/x"),
        x509.IPAddress(__import__("ipaddress").ip_address("::1")),
    ]


@pytest.mark.parametrize("bad", ["exa mple.test", "-bad.test", "DNS:foo..bar", "IP:300.1.1.1"])
def test_parse_sans_rejects_invalid(bad):
    with pytest.raises(ValueError):
        certs.parse_sans(bad)


def test_build_name_validates_country():
    with pytest.raises(ValueError):
        certs.build_name({"C": "USA"})
    assert certs.build_name({"C": "us", "CN": "x"}).rfc4514_string() == "CN=x,C=US"


@pytest.mark.parametrize("algo", list(keys.ALGORITHMS))
def test_self_signed_for_every_algorithm(algo):
    key = keys.generate(algo)
    now = datetime.now(timezone.utc)
    profile = certs.Profile(is_ca=True, key_usage=["keyCertSign", "cRLSign"])
    subject = certs.build_name({"CN": f"root {algo}"})
    cert = certs.issue(subject=subject, public_key=key.public_key(), signer_key=key, issuer_cert=None,
                       profile=profile, sans=[], not_before=now, not_after=now + timedelta(days=1))
    cert.verify_directly_issued_by(cert)
    assert certs.profile_from_cert(cert)[0].is_ca


def test_key_encipherment_dropped_for_ec():
    key = keys.generate("ec256")
    now = datetime.now(timezone.utc)
    profile = certs.Profile(key_usage=["digitalSignature", "keyEncipherment"])
    cert = certs.issue(subject=certs.build_name({"CN": "x"}), public_key=key.public_key(), signer_key=key,
                       issuer_cert=None, profile=profile, sans=[], not_before=now,
                       not_after=now + timedelta(days=1))
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature and not ku.key_encipherment


def test_vault_roundtrip_and_wrong_password(monkeypatch):
    v = Vault()
    params = v.initialize("pw-one-123456")
    blob = v.encrypt(b"secret")
    v.lock()
    assert Vault.unwrap(params, "wrong password") is None
    v.load(Vault.unwrap(params, "pw-one-123456"))
    assert v.decrypt(blob) == b"secret"
    new_params = v.rewrap("pw-two-123456")
    v.lock()
    v.load(Vault.unwrap(new_params, "pw-two-123456"))
    assert v.decrypt(blob) == b"secret"


def test_encrypted_key_import_needs_password():
    key = keys.generate("ec256")
    pem = keys.to_pem(key, "hunter2hunter2")
    with pytest.raises(ValueError):
        keys.load_private(pem)
    with pytest.raises(ValueError):
        keys.load_private(pem, "wrong")
    assert keys.fingerprint(keys.load_private(pem, "hunter2hunter2")) == keys.fingerprint(key)


def test_bundle_parses_mixed_pem_and_pkcs12():
    key = keys.generate("rsa2048")
    now = datetime.now(timezone.utc)
    cert = certs.issue(subject=certs.build_name({"CN": "x"}), public_key=key.public_key(), signer_key=key,
                       issuer_cert=None, profile=certs.Profile(), sans=[], not_before=now,
                       not_after=now + timedelta(days=1))
    from cryptography.hazmat.primitives import serialization
    pem = keys.to_pem(key) + cert.public_bytes(serialization.Encoding.PEM)
    k, c, r = bundle.parse(pem)
    assert len(k) == 1 and len(c) == 1 and not r

    p12 = bundle.pkcs12_bytes("x", key, cert, [], "pw")
    k, c, r = bundle.parse(p12, "pw")
    assert len(k) == 1 and c == [cert]
    with pytest.raises(ValueError):
        bundle.parse(p12, "wrong")
