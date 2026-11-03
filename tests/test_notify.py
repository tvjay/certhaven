import json
from datetime import timedelta

import pytest

from certhaven import notify
from certhaven.models import Certificate, db, get_setting, utcnow

CONF = """# test
SMTP_HOST=smtp.example.test
SMTP_PORT=2525
SMTP_SECURITY=none
MAIL_TO=admin@example.test, ops@example.test
MAIL_FROM="certhaven@example.test"
SMTP_PASSWORD=p#ss=word
"""


@pytest.fixture
def mail(app, tmp_path, monkeypatch):
    conf = tmp_path / "notify.conf"
    conf.write_text(CONF)
    app.config["NOTIFY_CONF"] = str(conf)
    sent = []
    monkeypatch.setattr(notify, "send_email", lambda cfg, subject, body: sent.append((cfg, subject, body)))
    return sent


def _run(app):
    with app.app_context():
        return notify.run()


def _set_expiry(app, cert_id, days):
    with app.app_context():
        row = db.session.get(Certificate, cert_id)
        row.not_after = utcnow() + timedelta(days=days, hours=1)
        db.session.commit()


def test_config_parsing(app, mail):
    with app.app_context():
        cfg = notify.load_config()
    assert notify.recipients(cfg) == ["admin@example.test", "ops@example.test"]
    assert cfg["MAIL_FROM"] == "certhaven@example.test"
    assert cfg["SMTP_PASSWORD"] == "p#ss=word"


def test_send_email_uses_starttls_and_login(monkeypatch):
    calls = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            calls.append(("connect", host, port))
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            calls.append(("quit",))
        def starttls(self, context):
            calls.append(("starttls",))
        def login(self, user, password):
            calls.append(("login", user, password))
        def send_message(self, msg):
            calls.append(("send", msg["From"], msg["To"], msg["Subject"]))

    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    notify.send_email({"SMTP_HOST": "mail.example.test", "SMTP_USER": "u@example.test", "SMTP_PASSWORD": "pw",
                       "MAIL_TO": "a@example.test,b@example.test"}, "Subject", "Body")
    assert calls == [("connect", "mail.example.test", 587), ("starttls",), ("login", "u@example.test", "pw"),
                     ("send", "u@example.test", "a@example.test, b@example.test", "Subject"), ("quit",)]
    with pytest.raises(ValueError):
        notify.send_email({"SMTP_HOST": "x", "MAIL_TO": "a@x", "SMTP_SECURITY": "tls"}, "s", "b")


def test_unconfigured_is_none(app, tmp_path):
    app.config["NOTIFY_CONF"] = str(tmp_path / "missing.conf")
    with app.app_context():
        assert notify.load_config() is None


def test_expiry_alerts_once_per_stage(client, mail):
    client.setup()
    root = client.issue(None, "Root CA", "Root")
    leaf = client.issue(root, "TLS Server", "web.example.test", sans="web.example.test")
    assert _run(client.app)["result"] == "nothing new"

    _set_expiry(client.app, leaf, 20)
    status = _run(client.app)
    assert status == {**status, "alerts": 1, "result": "sent"}
    _, subject, body = mail[-1]
    assert subject == "[certhaven] 1 certificate expiring"
    assert "web.example.test expires in 20 days" in body and "issuer: Root" in body

    assert _run(client.app)["result"] == "nothing new"   # same stage: not repeated
    _set_expiry(client.app, leaf, 5)
    _run(client.app)
    assert "expires in 5 days" in mail[-1][2]
    _set_expiry(client.app, leaf, -1)
    _run(client.app)
    assert "EXPIRED" in mail[-1][2]
    assert len(mail) == 3


def test_revoked_and_renewed_are_skipped(client, mail):
    client.setup()
    root = client.issue(None, "Root CA", "Root")
    revoked = client.issue(root, "TLS Server", "old.example.test", sans="old.example.test")
    renewed = client.issue(root, "TLS Server", "app.example.test", sans="app.example.test")
    client.post(f"/certs/{revoked}/revoke", {"reason": "superseded"})
    client.post(f"/certs/{renewed}/renew")
    _set_expiry(client.app, revoked, 3)
    _set_expiry(client.app, renewed, 3)
    assert _run(client.app)["result"] == "nothing new"


def test_crl_due_and_expired(client, mail):
    client.setup()
    root = client.issue(None, "Root CA", "Root")
    with client.app.app_context():
        crl = db.session.get(Certificate, root).latest_crl
        crl.next_update = utcnow() + timedelta(days=3)
        db.session.commit()
    _run(client.app)
    assert "CRL #1 for Root expires" in mail[-1][2] and "Log in" in mail[-1][2]
    with client.app.app_context():
        db.session.get(Certificate, root).latest_crl.next_update = utcnow() - timedelta(hours=1)
        db.session.commit()
    _run(client.app)
    assert "CRL #1 for Root EXPIRED" in mail[-1][2]
    client.post(f"/certs/{root}/crl")   # re-signed: new CRL number is current again
    assert _run(client.app)["result"] == "nothing new"


def test_failed_logins_grouped_and_not_repeated(client, mail):
    client.setup()
    _run(client.app)   # first run sets the baseline
    client.post("/logout")
    for _ in range(3):
        client.post("/login", {"username": "admin", "password": "wrong"})
    _run(client.app)
    _, subject, body = mail[-1]
    assert subject == "[certhaven] failed logins"
    assert "3 failed login attempts from 127.0.0.1" in body   # wrong password for admin
    assert _run(client.app)["result"] == "nothing new"


def test_failed_send_is_retried(client, app, mail, monkeypatch):
    client.setup()
    root = client.issue(None, "Root CA", "Root")
    _set_expiry(app, root, 2)

    def boom(cfg, subject, body):
        raise OSError("connection refused")
    monkeypatch.setattr(notify, "send_email", boom)
    status = _run(app)
    assert status["result"] == "error: could not connect to the SMTP server"
    monkeypatch.setattr(notify, "send_email", lambda cfg, s, b: mail.append((cfg, s, b)))
    assert _run(app)["result"] == "sent"


def test_alerts_wait_until_configured(client, app, tmp_path, mail):
    client.setup()
    root = client.issue(None, "Root CA", "Root")
    _set_expiry(app, root, 2)
    real_conf = app.config["NOTIFY_CONF"]
    app.config["NOTIFY_CONF"] = str(tmp_path / "missing.conf")
    assert _run(app)["result"] == "not configured"
    app.config["NOTIFY_CONF"] = real_conf
    assert _run(app)["result"] == "sent"


def test_settings_page_and_buttons(client, mail):
    client.setup()
    page = client.get("/settings").data.decode()
    assert "admin@example.test, ops@example.test" in page and "p#ss" not in page
    r = client.post("/settings/notify-test", follow_redirects=True)
    assert b"Test email sent" in r.data and mail[-1][1] == "[certhaven] Test notification"
    r = client.post("/settings/notify-run", follow_redirects=True)
    assert b"Checks ran" in r.data
    with client.app.app_context():
        assert json.loads(get_setting("notify_last"))["result"] == "nothing new"


FORM = {"smtp_host": "smtp.example.test", "smtp_port": "587", "smtp_security": "starttls",
        "smtp_user": "alerts@example.test", "smtp_password": "first-secret",
        "mail_from": "certhaven@example.test", "mail_to": "a@example.test,  b@example.test",
        "admin_url": "https://pki.example.test/"}


def _saved(app):
    with app.app_context():
        return notify.read_config()


def test_gui_saves_settings_and_password_is_write_only(client, app, tmp_path):
    app.config["NOTIFY_CONF"] = str(tmp_path / "gui-notify.conf")
    client.setup()
    r = client.post("/settings/notify", FORM, follow_redirects=True)
    assert b"Email settings saved" in r.data
    cfg = _saved(app)
    assert cfg["SMTP_HOST"] == "smtp.example.test" and cfg["SMTP_PASSWORD"] == "first-secret"
    assert cfg["MAIL_TO"] == "a@example.test, b@example.test"
    page = client.get("/settings").data.decode()
    assert "first-secret" not in page and "Saved — leave blank to keep" in page

    client.post("/settings/notify", {**FORM, "smtp_password": "", "smtp_port": "2525"})
    assert _saved(app)["SMTP_PASSWORD"] == "first-secret" and _saved(app)["SMTP_PORT"] == "2525"
    client.post("/settings/notify", {**FORM, "smtp_password": "", "clear_password": "1"})
    assert _saved(app)["SMTP_PASSWORD"] == ""
    with app.app_context():
        assert "notify_settings" in [a.action for a in db.session.scalars(db.select(notify.AuditLog))]


@pytest.mark.parametrize("change, message", [
    ({"smtp_host": "smtp.example.test\nSMTP_PASSWORD=x"}, b"line breaks"),
    ({"mail_to": "not-an-address"}, b"Not a valid email address"),
    ({"mail_to": ""}, b"at least one recipient"),
    ({"smtp_port": "70000"}, b"Port must be"),
    ({"smtp_port": "8080"}, b"Port must be"),
    ({"smtp_security": "none"}, b"STARTTLS or SSL/TLS"),
    ({"admin_url": "javascript:alert(1)"}, b"Admin link"),
])
def test_gui_rejects_bad_settings(client, app, tmp_path, change, message):
    app.config["NOTIFY_CONF"] = str(tmp_path / "gui-notify.conf")
    client.setup()
    r = client.post("/settings/notify", {**FORM, **change}, follow_redirects=True)
    assert message in r.data
    assert not (tmp_path / "gui-notify.conf").exists()


def test_tricky_password_round_trips(client, app, tmp_path):
    app.config["NOTIFY_CONF"] = str(tmp_path / "gui-notify.conf")
    client.setup()
    for password in ['"quoted"', " spaces ", "a#b=c'd", "ünïcode"]:
        client.post("/settings/notify", {**FORM, "smtp_password": password})
        assert _saved(app)["SMTP_PASSWORD"] == password


def test_empty_host_turns_alerts_off(client, app, tmp_path):
    app.config["NOTIFY_CONF"] = str(tmp_path / "gui-notify.conf")
    client.setup()
    client.post("/settings/notify", FORM)
    r = client.post("/settings/notify", {**FORM, "smtp_host": ""}, follow_redirects=True)
    assert b"Email alerts are off" in r.data
    with app.app_context():
        assert notify.load_config() is None


def test_cli_dry_run_sends_nothing(client, app, mail):
    client.setup()
    root = client.issue(None, "Root CA", "Root")
    _set_expiry(app, root, 2)
    result = app.test_cli_runner().invoke(args=["notify", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "Root expires in 2 days" in result.output and "dry run" in result.output
    assert mail == []
    assert _run(app)["result"] == "sent"   # dry run did not mark it as sent


def test_test_email_error_is_short(client, mail, monkeypatch):
    client.setup()

    def boom(cfg, subject, body):
        raise OSError("220 internal-db.example.test MySQL banner")
    monkeypatch.setattr(notify, "send_email", boom)
    r = client.post("/settings/notify-test", follow_redirects=True)
    assert b"could not connect to the SMTP server" in r.data
    assert b"MySQL" not in r.data and b"internal-db" not in r.data
