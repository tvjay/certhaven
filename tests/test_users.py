import json
import re
import sqlite3

import pytest

from certhaven import accounts, create_app, security
from certhaven.crypto.vault import Vault
from certhaven.models import AuditLog, Certificate, User, db

from .conftest import PASSWORD, TEMP, Client

NEW = "my own long password"


def _user(app, username):
    with app.app_context():
        return db.session.scalar(db.select(User).filter_by(username=username))


def _as(app, username, password=TEMP, change_to=NEW):
    """A client logged in as `username`, past the forced password change."""
    c = Client(app)
    r = c.login(username, password)
    assert r.status_code == 302 and r.headers["Location"].endswith("/account"), r.data
    r = c.post("/account/password", {"current": password, "new": change_to, "confirm": change_to})
    assert r.status_code == 302 and not r.headers["Location"].endswith("/account")
    return c


@pytest.fixture
def ca(client):
    client.setup()
    root = client.issue(None, "Root CA", "Root")
    leaf = client.issue(root, "TLS Server", "web.example.test", sans="web.example.test")
    return root, leaf


def test_new_user_must_change_temporary_password(client, app, ca):
    client.add_user("olivia", "operator")
    c = Client(app)
    r = c.login("olivia", TEMP)
    assert r.headers["Location"].endswith("/account")
    r = c.get("/certs")
    assert r.status_code == 302 and r.headers["Location"].endswith("/account")
    r = c.post("/account/password", {"current": TEMP, "new": NEW, "confirm": NEW})
    assert r.status_code == 302
    assert c.get("/certs").status_code == 200
    assert not _user(app, "olivia").must_change_password


def test_auditor_is_read_only(client, app, ca):
    root, leaf = ca
    client.add_user("ann", "auditor")
    a = _as(app, "ann")
    for url in ["/", "/cas", "/certs", f"/certs/{root}", f"/certs/{leaf}", "/csrs", "/keys", "/templates",
                "/audit", f"/certs/{leaf}/download/pem", f"/crl/{root}.crl", "/account"]:
        assert a.get(url).status_code == 200, url
    for url in ["/settings", "/users", "/import", "/certs/new", f"/certs/{leaf}/pkcs12", "/settings/backup",
                "/templates/new", "/csrs/new"]:
        assert a.get(url).status_code == 403, url
    for url, data in [(f"/certs/{leaf}/revoke", {"reason": "superseded"}), (f"/certs/{leaf}/renew", {}),
                      ("/keys/new", {"algo": "ec256"}), (f"/certs/{root}/crl", {}), ("/lock", {}),
                      (f"/certs/{leaf}/delete", {}), ("/unlock", {"password": PASSWORD})]:
        assert a.post(url, data).status_code == 403, url
    page = a.get(f"/certs/{leaf}").data.decode()
    for action in ("/revoke", "/renew", "/pkcs12", "/delete", "/lock"):
        assert action not in page, action
    # An auditor's password cannot decrypt anything: no wrapped key is stored for them.
    assert _user(app, "ann").wrapped_key is None


def test_operator_issues_leaf_but_not_ca(client, app, ca):
    root, leaf = ca
    client.add_user("olivia", "operator")
    o = _as(app, "olivia")
    tls = client.template_id("TLS Server")
    r = o.post("/certs/new", {"issuer": root, "template": tls, "subj_CN": "api.example.test",
                              "sans": "api.example.test", "key": "new", "key_algo": "ec256"})
    assert r.status_code == 302 and "/certs/" in r.headers["Location"]
    # A CA template, or a self-signed certificate, is refused outright (never silently swapped).
    r = o.post("/certs/new", {"issuer": root, "template": client.template_id("Intermediate CA"),
                              "subj_CN": "sub", "key": "new", "key_algo": "ec256"})
    assert r.status_code == 403
    r = o.post("/certs/new", {"issuer": "", "template": tls, "subj_CN": "x", "key": "new", "key_algo": "ec256"})
    assert r.status_code == 403
    assert o.post(f"/certs/{root}/revoke", {"reason": "superseded"}).status_code == 403
    assert o.post(f"/certs/{leaf}/revoke", {"reason": "superseded"}).status_code == 302
    page = o.get("/certs/new").data.decode()
    assert "Self-signed" not in page and "Root CA" not in page


def test_operator_cannot_export_keys_or_administer(client, app, ca):
    root, leaf = ca
    client.add_user("olivia", "operator")
    o = _as(app, "olivia")
    with app.app_context():
        key_id = db.session.get(Certificate, leaf).key_id
    assert o.post(f"/keys/{key_id}/export", {"password": "", "confirm": ""}).status_code == 403
    assert o.get(f"/certs/{leaf}/pkcs12").status_code == 403
    assert o.post(f"/certs/{leaf}/delete").status_code == 403
    assert o.get("/users").status_code == 403
    assert o.post("/users/new", {"username": "evil", "role": "admin", "password": TEMP,
                                 "confirm": TEMP}).status_code == 403
    assert o.get("/settings/backup").status_code == 403


def test_operator_cannot_use_ca_key_for_a_leaf(client, app, ca):
    root, _ = ca
    with app.app_context():
        root_key = db.session.get(Certificate, root).key_id
    r = client.post("/certs/new", {"issuer": root, "template": client.template_id("TLS Server"),
                                   "subj_CN": "reuse", "key": str(root_key)})
    assert b"belongs to a CA" in r.data
    page = client.get("/certs/new").data.decode()
    assert "Root (EC P-384)" not in page and "web.example.test (EC P-256)" in page   # key picker


def test_operator_login_unlocks_keys_and_auditor_login_does_not(client, app, ca):
    root, _ = ca
    client.add_user("olivia", "operator")
    client.add_user("ann", "auditor")
    client.post("/logout")                      # admin logout locks the keys
    assert not security.vault.unlocked
    a = _as(app, "ann")
    assert not security.vault.unlocked          # auditor login cannot unlock
    assert a.get("/certs").status_code == 200   # but can browse while locked
    _as(app, "olivia")
    assert security.vault.unlocked


def test_locked_keys_prompt_for_unlock_then_work(client, app, ca):
    root, leaf = ca
    client.post("/lock")
    assert not security.vault.unlocked
    r = client.post(f"/certs/{leaf}/renew")
    assert r.status_code == 302 and "/unlock" in r.headers["Location"]
    assert client.get("/certs").status_code == 200   # still logged in
    r = client.post("/unlock", {"password": "wrong password!!", "next": f"/certs/{leaf}"})
    assert b"Incorrect password" in r.data and not security.vault.unlocked
    r = client.post("/unlock", {"password": PASSWORD, "next": f"/certs/{leaf}"})
    assert r.status_code == 302 and r.headers["Location"].endswith(f"/certs/{leaf}")
    assert client.post(f"/certs/{leaf}/renew").status_code == 302
    assert security.vault.unlocked


def test_lock_button_is_on_settings_not_header(client, ca):
    lock_form = b'action="/lock"'
    assert lock_form not in client.get("/certs").data
    assert lock_form in client.get("/settings").data
    r = client.post("/lock")
    assert r.status_code == 302 and r.headers["Location"].endswith("/settings")
    page = client.get("/settings").data
    assert lock_form not in page and b"/unlock?next=/settings" in page


def test_creating_a_keyholder_needs_unlocked_keys(client, app, ca):
    client.post("/lock")
    r = client.post("/users/new", {"username": "olivia", "role": "operator", "password": TEMP, "confirm": TEMP})
    assert r.status_code == 302 and "/unlock" in r.headers["Location"]
    assert _user(app, "olivia") is None
    client.add_user("ann", "auditor")           # auditors hold no key, so this works while locked
    assert _user(app, "ann") is not None


def test_role_upgrade_requires_password_and_downgrade_drops_key(client, app, ca):
    client.add_user("ann", "auditor")
    ann = _user(app, "ann")
    r = client.post(f"/users/{ann.id}", {"role": "operator"})
    assert b"set a temporary password" in r.data and _user(app, "ann").role == "auditor"
    client.post(f"/users/{ann.id}", {"role": "operator", "password": TEMP, "confirm": TEMP})
    ann = _user(app, "ann")
    assert ann.role == "operator" and ann.wrapped_key and ann.must_change_password
    client.post(f"/users/{ann.id}", {"role": "auditor"})
    assert _user(app, "ann").wrapped_key is None


def test_last_admin_and_self_protection(client, app, ca):
    me = _user(app, "admin")
    assert b"cannot change your own role" in client.post(f"/users/{me.id}", {"role": "operator"}).data
    client.post(f"/users/{me.id}/delete")
    assert _user(app, "admin") is not None
    client.add_user("bob", "admin")
    bob = _as(app, "bob")
    assert bob.post(f"/users/{me.id}", {"role": "operator"}).status_code == 302   # another admin may
    assert _user(app, "admin").role == "operator"
    r = bob.post(f"/users/{_user(app, 'bob').id}/delete", follow_redirects=True)
    assert b"cannot delete your own account" in r.data


def test_disable_and_reset_end_sessions(client, app, ca):
    client.add_user("olivia", "operator")
    o = _as(app, "olivia")
    uid = _user(app, "olivia").id
    client.post(f"/users/{uid}", {"role": "operator", "disabled": "1"})
    assert o.get("/certs").status_code == 302
    assert Client(app).login("olivia", NEW).status_code == 200   # disabled: login refused
    client.post(f"/users/{uid}", {"role": "operator"})
    o = Client(app)
    o.login("olivia", NEW)
    assert o.get("/certs").status_code == 200
    client.post(f"/users/{uid}", {"role": "operator", "password": TEMP, "confirm": TEMP})
    assert o.get("/certs").status_code == 302                      # reset ends the session
    assert Client(app).login("olivia", TEMP).headers["Location"].endswith("/account")


def test_audit_log_records_usernames(client, app, ca):
    client.add_user("olivia", "operator")
    o = _as(app, "olivia")
    _, leaf = ca
    o.post(f"/certs/{leaf}/revoke", {"reason": "superseded"})
    Client(app).login("olivia", "wrong password here")
    Client(app).login("nobody", "typed-a-password-as-username")
    with app.app_context():
        rows = db.session.scalars(db.select(AuditLog)).all()
        by_action = {(r.action, r.username) for r in rows}
        assert ("revoke", "olivia") in by_action and ("user_create", "admin") in by_action
        failed = [r.detail for r in rows if r.action == "login_failed"]
        assert "user olivia" in failed and "unknown or disabled user" in failed
        assert not any("typed-a-password" in r.detail for r in rows)
    page = client.get("/audit").data.decode()
    assert "olivia" in page


def test_upgrade_from_single_password_database(tmp_path):
    """A database from the single-admin version becomes user "admin" with the same password."""
    old = create_app({"DATA_DIR": str(tmp_path), "TESTING": True, "SESSION_COOKIE_SECURE": False})
    with old.app_context():
        params = security.vault.initialize(PASSWORD)
        dek_blob = security.vault.encrypt(b"secret")
        db.session.execute(db.delete(User))
        db.session.execute(db.text("INSERT INTO settings (name, value) VALUES ('vault', :v)"),
                           {"v": json.dumps(params)})
        db.session.commit()
    security.vault.lock()
    con = sqlite3.connect(tmp_path / "certhaven.db")
    # Recreate audit_log exactly as the single-admin version defined it (no username column).
    con.execute("DROP TABLE audit_log")
    con.execute("CREATE TABLE audit_log (id INTEGER NOT NULL PRIMARY KEY, ts DATETIME NOT NULL, "
                "action VARCHAR(40) NOT NULL, detail VARCHAR(1000) NOT NULL, ip VARCHAR(64))")
    con.execute("INSERT INTO audit_log (ts, action, detail) VALUES ('2026-10-01 00:00:00', 'setup', '')")
    con.commit()
    con.close()

    app = create_app({"DATA_DIR": str(tmp_path), "TESTING": True, "SESSION_COOKIE_SECURE": False})
    with app.app_context():
        admin = db.session.scalar(db.select(User).filter_by(username="admin"))
        assert admin.role == "admin" and admin.password_hash is None
        assert db.session.execute(db.text("SELECT value FROM settings WHERE name='vault'")).first() is None
    c = Client(app)
    r = c.login("admin", PASSWORD)
    assert r.status_code == 302 and "/login" not in r.headers["Location"]
    assert security.vault.decrypt(dek_blob) == b"secret"
    with app.app_context():
        admin = db.session.scalar(db.select(User).filter_by(username="admin"))
        assert Vault.check_password(json.loads(admin.password_hash), PASSWORD)
        login = db.session.scalar(db.select(AuditLog).filter_by(action="login"))
        assert login.username == "admin"   # the added audit column works on the upgraded table


def test_password_change_check_is_rate_limited(client, app, ca):
    for _ in range(5):
        r = client.post("/account/password", {"current": "wrong password!!", "new": NEW, "confirm": NEW},
                        follow_redirects=True)
        assert b"current password is incorrect" in r.data
    # Even the right password is refused now, and login from this address is limited too.
    r = client.post("/account/password", {"current": PASSWORD, "new": NEW, "confirm": NEW}, follow_redirects=True)
    assert b"Too many failed attempts" in r.data
    assert Client(app).login("admin", PASSWORD).status_code == 429
    with app.app_context():
        assert accounts.verify(_user(app, "admin"), PASSWORD)[0]   # the password did not change
        failed = db.session.scalars(db.select(AuditLog).filter_by(action="password_change_failed")).all()
        assert len(failed) == 5


def test_attempt_table_forgets_old_addresses(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(security.time, "monotonic", lambda: now[0])
    for ip in ("10.0.0.1", "10.0.0.2"):
        assert security.register_attempt(ip)
    assert set(security._failures) == {"10.0.0.1", "10.0.0.2"}
    now[0] += security.FAILURE_WINDOW + 1
    assert security.register_attempt("10.0.0.3")
    security._recent_failures("10.0.0.1")
    assert "10.0.0.1" not in security._failures      # expired entries are dropped, not kept empty
    security.clear_failures("10.0.0.3")
    assert "10.0.0.3" not in security._failures


def test_time_display_is_one_global_setting(client, app, ca):
    page = client.get("/certs").data.decode()
    assert 'data-time-display="utc"' in page
    assert re.search(r'<time datetime="\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ" data-kind="date">\d{4}-\d\d-\d\d</time>', page)
    form = {"base_url": "http://pki.example.test", "idle_timeout": "30", "crl_days": "30"}
    r = client.post("/settings", {**form, "time_display": "local"}, follow_redirects=True)
    assert b"Settings saved" in r.data and b'data-time-display="local"' in r.data
    r = client.post("/settings", {**form, "time_display": "mars"}, follow_redirects=True)
    assert b"Choose how times are shown" in r.data

    # Everyone sees the admin's choice; only admins can change it.
    client.add_user("ann", "auditor")
    a = _as(app, "ann")
    assert 'data-time-display="local"' in a.get("/certs").data.decode()
    assert a.post("/settings", {**form, "time_display": "utc"}).status_code == 403
    assert b"Show times in" not in a.get("/account").data


def test_upgrade_drops_per_user_time_display(tmp_path):
    first = create_app({"DATA_DIR": str(tmp_path), "TESTING": True, "SESSION_COOKIE_SECURE": False})
    Client(first).setup()
    with first.app_context():
        db.engine.dispose()
    con = sqlite3.connect(tmp_path / "certhaven.db")   # as left by 0.9.1
    con.execute("ALTER TABLE users ADD COLUMN time_display VARCHAR(10) NOT NULL DEFAULT 'utc'")
    con.commit()
    con.close()
    upgraded = create_app({"DATA_DIR": str(tmp_path), "TESTING": True, "SESSION_COOKIE_SECURE": False})
    with upgraded.app_context():
        columns = {row[1] for row in db.session.execute(db.text("PRAGMA table_info(users)"))}
        assert "time_display" not in columns
        assert db.session.scalar(db.select(User)).username == "admin"


def test_users_are_managed_on_settings(client, app):
    client.setup()
    r = client.add_user("olivia", "operator")
    assert r.headers["Location"].endswith("/settings#users")
    r = client.get("/users")
    assert r.status_code == 302 and r.headers["Location"].endswith("/settings#users")
    html = client.get("/settings").get_data(as_text=True)
    assert 'id="users"' in html and ">olivia</a>" in html and "Add user" in html
    assert not re.search(r'<nav>.*href="/users"', html, re.S)
