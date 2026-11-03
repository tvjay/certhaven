import sqlite3
from datetime import datetime, timezone

import pytest
import sqlalchemy
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.verification import PolicyBuilder, Store

import certhaven
from certhaven import create_app
from certhaven.crypto import csr as csrlib
from certhaven.crypto import certs as certlib
from certhaven.crypto import keys as keylib
from certhaven.models import CRL, Certificate, Key, db
from certhaven.views import main as main_views

from .conftest import PASSWORD, Client


def _hierarchy(client):
    root = client.issue(None, "Root CA", "Test Root", algo="ec384")
    inter = client.issue(root, "Intermediate CA", "Test Issuing CA", algo="ec256")
    leaf = client.issue(inter, "TLS Server", "www.example.test",
                        sans="www.example.test\n10.0.0.5", algo="rsa2048")
    return root, inter, leaf


def test_requires_setup_then_login(client):
    r = client.get("/certs")
    assert r.status_code == 302 and "/setup" in r.headers["Location"]
    client.setup()
    assert client.get("/certs").status_code == 200

    client.post("/logout")
    r = client.get("/certs")
    assert r.status_code == 302 and "/login" in r.headers["Location"]

    r = client.post("/login", {"username": "admin", "password": "nope"})
    assert b"Incorrect username or password" in r.data
    r = client.post("/login", {"username": "admin", "password": PASSWORD, "next": "/certs"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/certs")


def test_csrf_required(client):
    client.setup()
    r = client.http.post("/keys/new", data={"algo": "ec256"})
    assert r.status_code == 400


def test_login_rate_limited(client):
    client.setup()
    client.post("/logout")
    for _ in range(5):
        client.post("/login", {"username": "admin", "password": "nope"})
    r = client.post("/login", {"username": "admin", "password": PASSWORD})
    assert r.status_code == 429


def test_chain_verifies_as_tls_server(client):
    client.setup()
    root, inter, leaf = _hierarchy(client)
    root_c, inter_c, leaf_c = client.cert(root), client.cert(inter), client.cert(leaf)

    verifier = (PolicyBuilder().store(Store([root_c])).time(datetime.now(timezone.utc))
                .build_server_verifier(x509.DNSName("www.example.test")))
    chain = verifier.verify(leaf_c, [inter_c])
    assert chain == [leaf_c, inter_c, root_c]

    cdp = leaf_c.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    assert cdp[0].full_name[0].value == f"http://pki.example.test/crl/{inter}.crl"
    bc = inter_c.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca and bc.path_length == 0

    # Path length 0 blocks a sub-CA under the intermediate.
    r = client.post("/certs/new", {"issuer": inter, "template": client.template_id("Intermediate CA"),
                                   "subj_CN": "too deep", "key": "new", "key_algo": "ec256"})
    assert b"path length 0" in r.data


def test_revoke_updates_public_crl(client):
    client.setup()
    root, inter, leaf = _hierarchy(client)
    client.post(f"/certs/{leaf}/revoke", {"reason": "keyCompromise"})
    client.post("/logout")

    r = client.get(f"/crl/{inter}.crl")  # public, works while locked
    assert r.status_code == 200 and r.mimetype == "application/pkix-crl"
    crl = x509.load_der_x509_crl(r.data)
    assert crl.is_signature_valid(client.cert(inter).public_key())
    entry = crl.get_revoked_certificate_by_serial_number(client.cert(leaf).serial_number)
    assert entry is not None
    assert entry.extensions.get_extension_for_class(x509.CRLReason).value.reason == x509.ReasonFlags.key_compromise

    r = client.get(f"/ca/{inter}.crt")
    assert x509.load_der_x509_certificate(r.data) == client.cert(inter)


def test_pkcs12_and_chain_export(client):
    client.setup()
    root, inter, leaf = _hierarchy(client)
    r = client.post(f"/certs/{leaf}/pkcs12", {"password": "export-pw", "confirm": "export-pw", "chain": "1"})
    assert r.status_code == 200
    p12 = pkcs12.load_pkcs12(r.data, b"export-pw")
    assert p12.cert.certificate == client.cert(leaf)
    assert {c.certificate for c in p12.additional_certs} == {client.cert(inter), client.cert(root)}

    r = client.get(f"/certs/{leaf}/download/chain")
    assert r.data.count(b"BEGIN CERTIFICATE") == 3


def test_sign_external_csr(client):
    client.setup()
    root, inter, _ = _hierarchy(client)
    key = keylib.generate("ec256")
    req = csrlib.build(certlib.build_name({"CN": "api.example.test"}), key,
                       certlib.parse_sans("api.example.test"))
    r = client.post("/csrs/import", {"text": csrlib.to_pem(req)})
    csr_id = int(r.headers["Location"].rsplit("/", 1)[1])
    r = client.post(f"/csrs/{csr_id}/sign", {"issuer": inter, "template": client.template_id("TLS Server"),
                                              "sans": "api.example.test\napi2.example.test"})
    cert_id = int(r.headers["Location"].rsplit("/", 1)[1])
    cert = client.cert(cert_id)
    assert keylib.fingerprint(cert.public_key()) == keylib.fingerprint(key)
    assert [n.value for n in certlib.get_sans(cert)] == ["api.example.test", "api2.example.test"]
    with client.app.app_context():
        assert db.session.get(Certificate, cert_id).key_id is None  # key stays with the requester


def test_renew_keeps_key_and_subject(client):
    client.setup()
    _, _, leaf = _hierarchy(client)
    r = client.post(f"/certs/{leaf}/renew")
    new_id = int(r.headers["Location"].rsplit("/", 1)[1])
    assert new_id != leaf
    old, new = client.cert(leaf), client.cert(new_id)
    assert old.subject == new.subject and old.serial_number != new.serial_number
    assert keylib.fingerprint(old.public_key()) == keylib.fingerprint(new.public_key())
    assert certlib.get_sans(old) == certlib.get_sans(new)


def test_import_into_fresh_instance_links_everything(client, tmp_path):
    client.setup()
    root, inter, leaf = _hierarchy(client)
    with client.app.app_context():
        pems = {i: db.session.get(Certificate, i).pem for i in (root, inter, leaf)}
        inter_key_id = db.session.get(Certificate, inter).key_id
    key_pem = client.post(f"/keys/{inter_key_id}/export", {"password": "kpw", "confirm": "kpw"}).data
    assert b"ENCRYPTED PRIVATE KEY" in key_pem

    other = Client(create_app({"DATA_DIR": str(tmp_path / "other"), "TESTING": True,
                               "SESSION_COOKIE_SECURE": False}))
    other.setup()
    # Child first, then parents, to exercise orphan adoption.
    other.post("/import", {"text": pems[leaf]})
    other.post("/import", {"text": pems[inter] + key_pem.decode(), "password": "kpw"})
    other.post("/import", {"text": pems[root]})
    with other.app.app_context():
        rows = {c.subject: c for c in db.session.scalars(db.select(Certificate))}
        r, i, l = rows["CN=Test Root"], rows["CN=Test Issuing CA"], rows["CN=www.example.test"]
        assert r.self_signed and i.issuer_id == r.id and l.issuer_id == i.id
        assert i.key_id is not None and r.key_id is None
        assert db.session.scalar(db.select(db.func.count(Key.id))) == 1
    # The imported CA with its key can issue.
    other.issue(i.id, "TLS Client", "client1")


def test_pages_render(client):
    client.setup()
    root, inter, leaf = _hierarchy(client)
    client.post("/csrs/new", {"subj_CN": "csr.example.test", "key": "new", "key_algo": "ec256"})
    for url in ["/", "/cas", "/certs", "/certs?kind=ca", f"/certs/{root}", f"/certs/{inter}", f"/certs/{leaf}",
                "/certs/new", "/certs/new?issuer=", f"/certs/{leaf}/pkcs12", "/csrs", "/csrs/new", "/csrs/1",
                "/keys", "/templates", "/templates/new", "/templates/1/edit", "/import", "/audit", "/settings",
                f"/certs/{inter}/crl.pem", f"/certs/{root}/download/der"]:
        r = client.get(url)
        assert r.status_code == 200, url
    assert client.get("/settings/backup").data.startswith(b"SQLite format 3")


def test_key_list_filters(client):
    client.setup()
    root = client.issue(None, "Root CA", "Root", algo="ec384")
    client.issue(root, "TLS Server", "web.example.test", sans="web.example.test")
    client.post("/keys/new", {"name": "spare", "algo": "ec256"})
    with client.app.app_context():
        root_fp = db.session.get(Certificate, root).key.fingerprint

    def names(query):
        page = client.get(f"/keys?{query}").data.decode()
        return [n for n in ("Root", "web.example.test", "spare") if f'value="{n}"' in page]

    assert names("") == ["Root", "web.example.test", "spare"]
    assert names("q=WEB") == ["web.example.test"]
    assert names(f"q={root_fp[:12].upper()}") == ["Root"]
    assert names("algo=EC+P-384") == ["Root"]
    assert names("usage=unused") == ["spare"]
    assert names("usage=used") == ["Root", "web.example.test"]
    assert b"No keys match." in client.get("/keys?q=nothing-like-this").data


def test_lists_sorted_by_name(client):
    client.setup()
    root = client.issue(None, "Root CA", "Root")
    for cn in ["zeta.example.test", "Alpha.example.test", "mike.example.test"]:
        client.issue(root, "TLS Server", cn, sans=cn)
    expected = ["Alpha.example.test", "mike.example.test", "zeta.example.test"]
    for url in ["/certs?kind=ee", f"/certs/{root}"]:
        page = client.get(url).data.decode()
        positions = [page.index(f">{name}</a>") for name in expected]
        assert positions == sorted(positions), url


def test_delete_rules(client):
    client.setup()
    root, inter, leaf = _hierarchy(client)
    client.post(f"/certs/{inter}/delete")
    with client.app.app_context():
        assert db.session.get(Certificate, inter) is not None  # has children
        key_id = db.session.get(Certificate, leaf).key_id
    client.post(f"/keys/{key_id}/delete")
    with client.app.app_context():
        assert db.session.get(Key, key_id) is not None  # in use
    client.post(f"/certs/{leaf}/delete")
    client.post(f"/keys/{key_id}/delete")
    with client.app.app_context():
        assert db.session.get(Certificate, leaf) is None
        assert db.session.get(Key, key_id) is None
        assert db.session.scalar(db.select(db.func.count(CRL.id)).filter_by(ca_id=inter)) >= 1


def test_email_attribute_shown_as_e(client):
    client.setup()
    root = client.issue(None, "Root CA", "Root")
    leaf = client.issue(root, "TLS Client", "jdoe", subj_E="jdoe@example.test")
    page = client.get("/certs").data.decode()
    assert "E=jdoe@example.test" in page and "1.2.840.113549" not in page
    with client.app.app_context():
        assert db.session.get(Certificate, leaf).subject == "E=jdoe@example.test,CN=jdoe"


def test_validity_is_capped(client):
    client.setup()
    root = client.issue(None, "Root CA", "Root")
    r = client.post("/certs/new", {"issuer": root, "template": client.template_id("TLS Server"),
                                   "subj_CN": "x.example.test", "key": "new", "key_algo": "ec256",
                                   "days": "99999999999"})
    assert r.status_code == 200 and b"Validity must be between" in r.data


def test_password_change_logs_out_other_sessions(client):
    client.setup()
    other = Client(client.app)
    other.post("/login", {"username": "admin", "password": PASSWORD})
    assert other.get("/certs").status_code == 200
    client.post("/account/password", {"current": PASSWORD, "new": "another long password",
                                       "confirm": "another long password"})
    assert client.get("/certs").status_code == 200  # the session that changed it stays in
    r = other.get("/certs")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_forwarded_host_not_trusted(app):
    proxy = app.wsgi_app
    assert (proxy.x_for, proxy.x_proto, proxy.x_host) == (1, 1, 0)


def test_password_change_keeps_keys_usable(client):
    client.setup()
    root = client.issue(None, "Root CA", "Root")
    client.post("/account/password", {"current": PASSWORD, "new": "another long password", "confirm": "another long password"})
    client.post("/logout")
    assert b"Incorrect" in client.post("/login", {"username": "admin", "password": PASSWORD}).data
    client.post("/login", {"username": "admin", "password": "another long password"})
    client.issue(root, "TLS Server", "after-change.example.test", sans="after-change.example.test")


def test_unencrypted_exports_need_confirmation(client):
    client.setup()
    root, inter, leaf = _hierarchy(client)
    with client.app.app_context():
        key_id = db.session.get(Certificate, leaf).key_id
    r = client.post(f"/keys/{key_id}/export", {"password": "", "confirm": ""})
    assert r.status_code == 302 and b"PRIVATE KEY" not in r.data
    r = client.post(f"/keys/{key_id}/export", {"password": "", "confirm": "", "unencrypted": "1"})
    assert b"-----BEGIN PRIVATE KEY-----" in r.data
    r = client.post(f"/certs/{leaf}/pkcs12", {"password": "", "confirm": ""})
    assert r.status_code == 200 and b"Export without a password" in r.data and r.mimetype == "text/html"
    r = client.post(f"/certs/{leaf}/pkcs12", {"password": "", "confirm": "", "unencrypted": "1"})
    assert r.mimetype == "application/x-pkcs12"
    assert pkcs12.load_pkcs12(r.data, None).cert.certificate == client.cert(leaf)


def test_crl_numbers_are_unique_per_ca(client):
    client.setup()
    root = client.issue(None, "Root CA", "Root")
    with client.app.app_context():
        crl = db.session.scalar(db.select(CRL).filter_by(ca_id=root))
        db.session.add(CRL(ca_id=root, number=crl.number, this_update=crl.this_update,
                           next_update=crl.next_update, pem=crl.pem))
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            db.session.commit()


def test_key_imported_after_its_certificate_is_linked(client):
    client.setup()
    root, inter, leaf = _hierarchy(client)
    with client.app.app_context():
        row = db.session.get(Certificate, leaf)
        pem, key_id = row.pem, row.key_id
    key_pem = client.post(f"/keys/{key_id}/export", {"password": "kpw", "confirm": "kpw"}).data

    other = Client(create_app({"DATA_DIR": str(client.app.config["DATA_DIR"]) + "-other", "TESTING": True,
                               "SESSION_COOKIE_SECURE": False}))
    other.setup()
    other.post("/import", {"text": pem})
    other.post("/import", {"text": key_pem.decode(), "password": "kpw"})
    with other.app.app_context():
        cert = db.session.scalar(db.select(Certificate).filter_by(subject="CN=www.example.test"))
        assert cert.key_id is not None and cert.pubkey_fp == cert.key.fingerprint


def test_upgrade_adds_and_fills_public_key_fingerprints(client):
    client.setup()
    root, inter, leaf = _hierarchy(client)
    data_dir = client.app.config["DATA_DIR"]
    with client.app.app_context():
        db.engine.dispose()
    con = sqlite3.connect(f"{data_dir}/certhaven.db")
    con.executescript("DROP INDEX ix_certificates_pubkey_fp; ALTER TABLE certificates DROP COLUMN pubkey_fp;")
    con.close()
    upgraded = create_app({"DATA_DIR": data_dir, "TESTING": True, "SESSION_COOKIE_SECURE": False})
    with upgraded.app_context():
        for cert in db.session.scalars(db.select(Certificate)):
            assert cert.pubkey_fp == keylib.fingerprint(cert.x509.public_key())


def test_ca_list_counts_issued_certificates(client):
    client.setup()
    root, inter, leaf = _hierarchy(client)
    client.issue(inter, "TLS Client", "jdoe")
    page = client.get("/cas").data.decode()
    assert f'href="/certs?issuer={root}">1<' in page and f'href="/certs?issuer={inter}">2<' in page
    assert page.index("Test Root") < page.index("Test Issuing CA")


def test_settings_about_shows_version_and_build_date(client, monkeypatch, tmp_path):
    client.setup()
    page = client.get("/settings").data.decode()
    assert f"certhaven {certhaven.__version__}" in page and "development build" in page

    (tmp_path / "BUILD_DATE").write_text("2026-10-31T03:00:00Z\n")
    monkeypatch.setattr(certhaven, "__file__", str(tmp_path / "__init__.py"))
    assert certhaven.build_date() == datetime(2026, 10, 31, 3, 0)
    monkeypatch.setattr(main_views, "build_date", certhaven.build_date)
    page = client.get("/settings").data.decode()
    assert '<time datetime="2026-10-31T03:00:00Z" data-kind="datetime">2026-10-31 03:00 UTC</time>' in page
    assert "development build" not in page


def test_every_page_links_to_the_source(client):
    # AGPL section 13: users interacting with the app over a network are offered its source.
    login = client.get("/login", follow_redirects=True).data.decode()
    assert f'<a href="{certhaven.SOURCE_URL}" rel="noopener">Source code</a>' in login
    assert certhaven.LICENSE_NAME in login
    client.setup()
    for url in ("/", "/certs", "/account"):
        assert f'href="{certhaven.SOURCE_URL}"' in client.get(url).data.decode(), url
    about = client.get("/settings").data.decode()
    assert f"<dt>License</dt><dd>{certhaven.LICENSE_NAME}</dd>" in about
