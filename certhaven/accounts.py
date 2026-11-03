"""User accounts: password checks and storage.

Every user has an scrypt password hash. Operators and admins also hold the vault data
key wrapped with their own password, which is what lets their login unlock the
private keys. Auditors get no wrapped key, so their password cannot decrypt anything.
"""
import json
import re
from functools import lru_cache

from .crypto.vault import Vault
from .models import ROLES, User, db
from .security import MIN_PASSWORD, clear_failures, register_attempt, unlock_slots, vault

_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,39}$")


def clean_username(name):
    name = (name or "").strip().lower()
    if not _USERNAME_RE.match(name):
        raise ValueError("Usernames are 2–40 characters: letters, digits, dot, dash or underscore.")
    return name


def check_new_password(password, confirm):
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"Use at least {MIN_PASSWORD} characters.")
    if password != confirm:
        raise ValueError("The passwords do not match.")


def check_role(role):
    if role not in ROLES:
        raise ValueError("Unknown role.")
    return role


def find(username):
    user = db.session.scalar(db.select(User).filter_by(username=(username or "").strip().lower()))
    return user if user is not None and not user.disabled else None


@lru_cache(maxsize=1)
def _dummy_hash():
    return Vault.hash_password("not-a-real-password")


def verify(user, password):
    """Return (ok, data_key). data_key is set for operators and admins on success."""
    if user is None:
        Vault.check_password(_dummy_hash(), password)   # same cost, so timing does not reveal users
        return False, None
    if user.keyed and user.wrapped_key:
        dek = Vault.unwrap(json.loads(user.wrapped_key), password)
        return dek is not None, dek
    if user.password_hash:
        return Vault.check_password(json.loads(user.password_hash), password), None
    return False, None


class CheckRefused(Exception):
    """A password check was not run: too many attempts, or too many checks at once."""

    def __init__(self, message, status):
        super().__init__(message)
        self.status = status


def checked_verify(user, password, ip):
    """verify() behind the per-IP attempt limit and the cap on concurrent checks.
    Used by every page that takes a password. Raises CheckRefused instead of checking."""
    if not register_attempt(ip):
        raise CheckRefused("Too many failed attempts. Wait 15 minutes and try again.", 429)
    if not unlock_slots.acquire(timeout=10):
        raise CheckRefused("The server is busy. Try again in a moment.", 503)
    try:
        ok, dek = verify(user, password)
    finally:
        unlock_slots.release()
    if ok:
        clear_failures(ip)
    return ok, dek


def set_password(user, password, dek=None, temporary=False):
    """Store a new password. Operators and admins get the data key wrapped with it, taken
    from `dek` when known, otherwise from the unlocked vault (raises VaultLocked if locked).
    Ends the user's other sessions."""
    if user.keyed:
        params = Vault.wrap(dek, password) if dek else vault.rewrap(password)
        user.wrapped_key = json.dumps(params)
    else:
        user.wrapped_key = None
    user.password_hash = json.dumps(Vault.hash_password(password))
    user.must_change_password = temporary
    user.session_version = (user.session_version or 0) + 1


def active_admins():
    return db.session.scalar(db.select(db.func.count(User.id)).filter_by(role="admin", disabled=False))
