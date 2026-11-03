import io
import os
import re
import sqlite3

from certhaven import create_app
from certhaven.models import AuditLog, Certificate, Key, User, db

from .conftest import PASSWORD, TEMP, Client


def _app(path):
    return create_app({"DATA_DIR": str(path), "TESTING": True, "SESSION_COOKIE_SECURE": False})


def _source_backup(tmp_path):
    """A source instance with a CA hierarchy whose intermediate has no CN, an operator, and its backup."""
    src = Client(_app(tmp_path / "source"))
    src.setup()
    root = src.issue(None, "Root CA", "example-root-ca", algo="ec384")
    inter = src.issue(root, "Intermediate CA", "", subj_O="Example Corp", subj_C="US", name="example-int")
    src.issue(inter, "TLS Server", "www.example.test", sans="www.example.test")
    src.add_user("olivia", "operator")
    return src.get("/settings/backup").data


def _restore(client, data, password=PASSWORD, filename="certhaven-backup.db"):
    return client.post("/settings/restore", {"password": password, "backup": (io.BytesIO(data), filename)},
                       content_type="multipart/form-data")


def _rows(app, model):
    with app.app_context():
        return db.session.scalars(db.select(model)).all()


def test_restore_brings_back_everything_and_logs_everyone_out(tmp_path):
    backup = _source_backup(tmp_path)
    dst = Client(_app(tmp_path / "target"))
    dst.setup()
    dst.issue(None, "Root CA", "Target-only Root")

    r = _restore(dst, backup)
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")
    assert "/login" in dst.get("/certs").headers["Location"]          # the old session is gone

    app = dst.app
    names = sorted(c.name for c in _rows(app, Certificate))
    assert names == ["example-int", "example-root-ca", "www.example.test"]   # names kept, target data replaced
    assert len(_rows(app, Key)) == 3
    assert sorted(u.username for u in _rows(app, User)) == ["admin", "olivia"]
    assert [a for a in _rows(app, AuditLog) if a.action == "restore"]
    assert [f for f in os.listdir(tmp_path / "target") if re.match(r"pre-restore-\d{8}-\d{6}\.db$", f)]

    # The backup's admin logs in, which unlocks the backup's keys: issuing from the restored CA works.
    fresh = Client(app)
    assert fresh.login("admin", PASSWORD).status_code == 302
    inter = next(c.id for c in _rows(app, Certificate) if c.name == "example-int")
    fresh.issue(inter, "TLS Client", "after-restore")


def test_restore_refuses_bad_input_and_changes_nothing(tmp_path):
    backup = _source_backup(tmp_path)
    dst = Client(_app(tmp_path / "target"))
    dst.setup()
    dst.issue(None, "Root CA", "Target Root")

    assert b"Your password is incorrect" in dst.http.get(
        _restore(dst, backup, password="wrong password!!").headers["Location"]).data
    r = _restore(dst, b"-----BEGIN CERTIFICATE-----\n...", filename="cert.pem")
    assert b"Choose a certhaven backup file" in dst.http.get(r.headers["Location"]).data

    other = tmp_path / "other.db"
    con = sqlite3.connect(other)
    con.execute("CREATE TABLE notes (body BLOB)")
    con.execute("INSERT INTO notes VALUES (?)", (os.urandom(3 * 1024 * 1024),))   # larger than 2 MB
    con.commit()
    con.close()
    r = _restore(dst, other.read_bytes())
    assert r.status_code == 302, "a backup over 2 MB must reach the check, not fail on size"
    assert b"not a certhaven backup" in dst.http.get(r.headers["Location"]).data

    assert [c.name for c in _rows(dst.app, Certificate)] == ["Target Root"]
    assert dst.get("/certs").status_code == 200                       # still logged in


def test_only_admins_can_restore(tmp_path):
    backup = _source_backup(tmp_path)
    dst = Client(_app(tmp_path / "target"))
    dst.setup()
    dst.add_user("olivia", "operator")
    olivia = Client(dst.app)
    olivia.login("olivia", TEMP)
    olivia.post("/account/password", {"current": TEMP, "new": "olivia long password", "confirm": "olivia long password"})
    assert _restore(olivia, backup, password="olivia long password").status_code == 403


def test_import_refuses_a_database_backup(tmp_path):
    backup = _source_backup(tmp_path)
    dst = Client(_app(tmp_path / "target"))
    dst.setup()
    r = dst.post("/import", {"file": (io.BytesIO(backup), "certhaven-backup.db")},
                 content_type="multipart/form-data", follow_redirects=True)
    assert b"This is a certhaven database backup" in r.data and b"Restore backup" in r.data
    assert _rows(dst.app, Certificate) == []
