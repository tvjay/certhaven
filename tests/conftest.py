import re

import pytest

from certhaven import create_app, security
from certhaven.crypto.vault import Vault
from certhaven.models import Certificate, Template, db

PASSWORD = "correct horse battery staple"
TEMP = "temporary password 123"


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    monkeypatch.setattr(Vault, "SCRYPT_N", 2 ** 10)
    security.vault.lock()
    security._failures.clear()
    yield
    security.vault.lock()


@pytest.fixture
def app(tmp_path):
    return create_app({"DATA_DIR": str(tmp_path), "TESTING": True, "SESSION_COOKIE_SECURE": False})


class Client:
    def __init__(self, app):
        self.app = app
        self.http = app.test_client()

    def csrf(self):
        with self.http.session_transaction() as s:
            if "csrf" not in s:
                s["csrf"] = "test-token"
            return s["csrf"]

    def get(self, url, **kw):
        return self.http.get(url, **kw)

    def post(self, url, data=None, **kw):
        data = dict(data or {})
        data.setdefault("_csrf", self.csrf())
        return self.http.post(url, data=data, **kw)

    def setup(self, base_url="http://pki.example.test"):
        r = self.post("/setup", {"username": "admin", "password": PASSWORD, "confirm": PASSWORD,
                                 "base_url": base_url})
        assert r.status_code == 302, r.data
        return r

    def login(self, username, password):
        return self.post("/login", {"username": username, "password": password})

    def add_user(self, username, role, password=TEMP):
        r = self.post("/users/new", {"username": username, "role": role, "password": password,
                                     "confirm": password})
        assert r.status_code == 302, r.data
        return r

    def template_id(self, name):
        with self.app.app_context():
            return db.session.scalar(db.select(Template).filter_by(name=name)).id

    def issue(self, issuer, template, cn, sans="", algo="ec256", **extra):
        data = {"issuer": "" if issuer is None else str(issuer), "template": self.template_id(template),
                "subj_CN": cn, "sans": sans, "key": "new", "key_algo": algo, **extra}
        r = self.post("/certs/new", data)
        assert r.status_code == 302, r.data
        m = re.search(r"/certs/(\d+)$", r.headers["Location"])
        assert m, f"issue failed, redirected to {r.headers['Location']}"
        return int(m.group(1))

    def cert(self, id):
        with self.app.app_context():
            return db.session.get(Certificate, id).x509


@pytest.fixture
def client(app):
    return Client(app)
