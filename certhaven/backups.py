"""Database backups: download a consistent copy, and restore one in place of the live database.

A backup is the whole SQLite database: users, the private keys (still encrypted with the data key
wrapped by each user's password), certificates with their names, settings and the audit log. The
email settings file lives outside the database and is not part of it.
"""
import glob
import os
import secrets
import sqlite3
import tempfile
import time

from flask import current_app

from .crypto.bundle import SQLITE_HEADER
from .models import db, forget_settings, upgrade_schema, utcnow
from .security import MAX_RESTORE_SIZE, reset_failures, vault

# A backup must hold at least these tables to be a certhaven database.
REQUIRED_TABLES = {"certificates", "keys", "settings"}
# Copies of the database saved before a restore are kept this long, then removed at the next restore.
PRE_RESTORE_KEEP_DAYS = 180


def serialize(db_path):
    """A consistent copy of the database as bytes (SQLite online backup)."""
    src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    dst = sqlite3.connect(":memory:")
    try:
        src.backup(dst)
        return dst.serialize()
    finally:
        src.close()
        dst.close()


def _copy(src_path, dst_path):
    src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True)
    dst = sqlite3.connect(dst_path)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()


def check(path):
    """Raise ValueError unless path is an intact certhaven database someone can log in to."""
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            if con.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("The backup file is damaged (SQLite integrity check failed).")
            tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
            if not REQUIRED_TABLES <= tables:
                raise ValueError("That SQLite file is not a certhaven backup.")
            users = con.execute("SELECT COUNT(*) FROM users").fetchone()[0] if "users" in tables else 0
            legacy_admin = con.execute("SELECT COUNT(*) FROM settings WHERE name = 'vault'").fetchone()[0]
            if not users and not legacy_admin:
                raise ValueError("The backup has no user accounts, so nobody could log in after restoring it.")
        finally:
            con.close()
    except sqlite3.DatabaseError:
        raise ValueError("That file is not a certhaven backup.")


def restore(data):
    """Replace the live database with the backup in data (bytes). Returns the path of the copy of
    the previous database. Ends every session and locks the private keys."""
    if len(data) > MAX_RESTORE_SIZE or not data.startswith(SQLITE_HEADER):
        raise ValueError("Choose a certhaven backup file (.db), as downloaded from Settings.")
    data_dir = current_app.config["DATA_DIR"]
    db_path = current_app.config["DB_PATH"]
    fd, upload = tempfile.mkstemp(dir=data_dir, prefix=".restore-", suffix=".db")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(upload, 0o600)
        check(upload)

        saved = os.path.join(data_dir, f"pre-restore-{utcnow():%Y%m%d-%H%M%S}.db")
        _copy(db_path, saved)
        os.chmod(saved, 0o600)
        _prune_pre_restore(data_dir)

        # Close every pooled connection, then overwrite the live database page by page.
        db.session.remove()
        db.engine.dispose()
        _copy(upload, db_path)
    finally:
        os.remove(upload)

    db.create_all()        # tables added after the backup was taken
    upgrade_schema()       # and anything else older versions lack
    vault.lock()           # the data key may differ; each user unlocks with the backup's passwords
    reset_failures()
    current_app.extensions.pop("certhaven_configured", None)
    forget_settings()
    _rotate_secret_key(data_dir)
    return saved


def _rotate_secret_key(data_dir):
    """A new session-signing key ends every session. Sessions name users by id, and ids in the
    restored database may belong to different people."""
    key = secrets.token_hex(32)
    path = os.path.join(data_dir, "secret_key")
    fd, tmp = tempfile.mkstemp(dir=data_dir, prefix=".secret-")
    with os.fdopen(fd, "w") as f:
        f.write(key)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    current_app.secret_key = key


def _prune_pre_restore(data_dir):
    """Remove pre-restore copies older than PRE_RESTORE_KEEP_DAYS; the newest is always kept."""
    cutoff = time.time() - PRE_RESTORE_KEEP_DAYS * 86400
    copies = sorted(glob.glob(os.path.join(data_dir, "pre-restore-*.db")), key=os.path.getmtime)
    for path in copies[:-1]:
        if os.path.getmtime(path) < cutoff:
            os.remove(path)
