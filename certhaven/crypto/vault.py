"""Holds the data key that encrypts every private key in the database.

The data key (DEK) is random. On disk it only exists wrapped with a key derived
from the admin password (scrypt -> AES-256-GCM). Logging in unwraps it into this
process's memory; locking, an idle timeout or a restart discards it. A wrong
password fails the GCM tag check, so the wrapped key doubles as the verifier.
"""
import base64
import hmac
import os
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

_WRAP_AAD = b"certmgr-dek-v1"  # kept from the old name: existing keys are sealed with it
_DATA_AAD = b"certmgr-data-v1"


class VaultLocked(Exception):
    pass


def _b64(data):
    return base64.b64encode(data).decode()


def _unb64(text):
    return base64.b64decode(text)


class Vault:
    SCRYPT_N = 2 ** 17
    SCRYPT_R = 8
    SCRYPT_P = 1

    def __init__(self):
        self._dek = None
        self._lock = threading.RLock()
        self._last = 0.0
        self._timeout = None   # the idle timeout last seen by a request
        self._reaper = None
        self._held = threading.Event()   # set while the data key is in memory

    @property
    def unlocked(self):
        return self._dek is not None

    @staticmethod
    def _kek(password, salt, n, r, p):
        return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode())

    @classmethod
    def wrap(cls, dek, password):
        salt = os.urandom(16)
        nonce = os.urandom(12)
        kek = cls._kek(password, salt, cls.SCRYPT_N, cls.SCRYPT_R, cls.SCRYPT_P)
        return {
            "v": 1,
            "n": cls.SCRYPT_N, "r": cls.SCRYPT_R, "p": cls.SCRYPT_P,
            "salt": _b64(salt),
            "nonce": _b64(nonce),
            "wrapped": _b64(AESGCM(kek).encrypt(nonce, dek, _WRAP_AAD)),
        }

    @classmethod
    def unwrap(cls, params, password):
        kek = cls._kek(password, _unb64(params["salt"]), params["n"], params["r"], params["p"])
        try:
            return AESGCM(kek).decrypt(_unb64(params["nonce"]), _unb64(params["wrapped"]), _WRAP_AAD)
        except InvalidTag:
            return None

    @classmethod
    def hash_password(cls, password):
        """scrypt hash for verifying a password without unwrapping anything."""
        salt = os.urandom(16)
        digest = cls._kek(password, salt, cls.SCRYPT_N, cls.SCRYPT_R, cls.SCRYPT_P)
        return {"v": 1, "n": cls.SCRYPT_N, "r": cls.SCRYPT_R, "p": cls.SCRYPT_P,
                "salt": _b64(salt), "hash": _b64(digest)}

    @classmethod
    def check_password(cls, params, password):
        digest = cls._kek(password, _unb64(params["salt"]), params["n"], params["r"], params["p"])
        return hmac.compare_digest(digest, _unb64(params["hash"]))

    def load(self, dek):
        """Unlock with a data key already unwrapped from a user's password."""
        self._set(dek)

    def _set(self, dek):
        with self._lock:
            self._dek = dek
            self._last = time.monotonic()
            self._held.set()

    def initialize(self, password):
        dek = AESGCM.generate_key(bit_length=256)
        params = self.wrap(dek, password)
        self._set(dek)
        return params

    def rewrap(self, new_password):
        with self._lock:
            if self._dek is None:
                raise VaultLocked()
            return self.wrap(self._dek, new_password)

    def lock(self):
        with self._lock:
            self._dek = None
            self._held.clear()

    def touch(self):
        self._last = time.monotonic()

    def expire_if_idle(self, timeout_seconds):
        with self._lock:
            self._timeout = timeout_seconds
            if self._dek is not None and time.monotonic() - self._last > timeout_seconds:
                self.lock()
            # Requests check the timeout as they arrive; this thread enforces it when none do.
            if self._reaper is None:
                self._reaper = threading.Thread(target=self._reap, name="vault-idle-lock", daemon=True)
                self._reaper.start()

    REAP_INTERVAL = 30

    def _reap(self):
        while True:
            self._held.wait()   # nothing to expire while locked
            time.sleep(self.REAP_INTERVAL)
            self.expire_if_idle(self._timeout)

    def encrypt(self, data):
        with self._lock:
            if self._dek is None:
                raise VaultLocked()
            nonce = os.urandom(12)
            return nonce + AESGCM(self._dek).encrypt(nonce, data, _DATA_AAD)

    def decrypt(self, blob):
        with self._lock:
            if self._dek is None:
                raise VaultLocked()
            return AESGCM(self._dek).decrypt(blob[:12], blob[12:], _DATA_AAD)
