import json
import logging
from datetime import datetime, timezone
from functools import cached_property

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from flask import g, has_request_context
from flask_sqlalchemy import SQLAlchemy

from .crypto.certs import Profile, common_name, name_text
from .crypto.keys import fingerprint

db = SQLAlchemy()


def utcnow():
    """Naive UTC; every datetime in the database is naive UTC."""
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


class Setting(db.Model):
    __tablename__ = "settings"
    name = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text, nullable=False)


def _request_settings():
    """All settings, read once per request (the table holds a handful of rows). None outside a
    request, where callers such as the alert job read the database directly."""
    if not has_request_context():
        return None
    if "settings" not in g:
        g.settings = dict(db.session.execute(db.select(Setting.name, Setting.value)).all())
    return g.settings


def forget_settings():
    """Drop this request's copy, after the database itself was replaced (restore)."""
    if has_request_context():
        g.pop("settings", None)


def get_setting(name, default=None):
    cached = _request_settings()
    if cached is not None:
        return cached.get(name, default)
    row = db.session.get(Setting, name)
    return row.value if row else default


def set_setting(name, value):
    row = db.session.get(Setting, name)
    if row:
        row.value = value
    else:
        db.session.add(Setting(name=name, value=value))
    if has_request_context() and "settings" in g:
        g.settings[name] = value


class Key(db.Model):
    __tablename__ = "keys"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    algo = db.Column(db.String(40), nullable=False)
    fingerprint = db.Column(db.String(64), unique=True, nullable=False)
    public_pem = db.Column(db.Text, nullable=False)
    # PKCS#8 PEM encrypted with the vault data key (AES-256-GCM).
    encrypted = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    certificates = db.relationship("Certificate", back_populates="key")
    csrs = db.relationship("CSR", back_populates="key")

    def public_key(self):
        return serialization.load_pem_public_key(self.public_pem.encode())


class Certificate(db.Model):
    __tablename__ = "certificates"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    fingerprint = db.Column(db.String(64), unique=True, nullable=False)
    serial = db.Column(db.String(64), nullable=False)
    subject = db.Column(db.Text, nullable=False)
    issuer_subject = db.Column(db.Text, nullable=False)
    not_before = db.Column(db.DateTime, nullable=False)
    not_after = db.Column(db.DateTime, nullable=False)
    is_ca = db.Column(db.Boolean, default=False, nullable=False)
    self_signed = db.Column(db.Boolean, default=False, nullable=False)
    pem = db.Column(db.Text, nullable=False)
    # SHA-256 of the public key, to find the matching private key without parsing every row.
    pubkey_fp = db.Column(db.String(64), index=True)
    revoked_at = db.Column(db.DateTime)
    revocation_reason = db.Column(db.String(40))
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    key_id = db.Column(db.Integer, db.ForeignKey("keys.id"))
    issuer_id = db.Column(db.Integer, db.ForeignKey("certificates.id"))

    key = db.relationship("Key", back_populates="certificates")
    issuer = db.relationship("Certificate", remote_side=[id], back_populates="children")
    children = db.relationship("Certificate", back_populates="issuer", order_by="Certificate.name")
    crls = db.relationship("CRL", back_populates="ca", cascade="all, delete-orphan",
                           order_by="CRL.number.desc()")

    # Parsed once per loaded row; the PEM of a stored certificate never changes.
    @cached_property
    def x509(self):
        return x509.load_pem_x509_certificate(self.pem.encode())

    @property
    def status(self):
        if self.revoked_at:
            return "revoked"
        now = utcnow()
        if now > self.not_after:
            return "expired"
        if now < self.not_before:
            return "pending"
        return "valid"

    @property
    def days_left(self):
        return (self.not_after - utcnow()).days

    @property
    def latest_crl(self):
        return self.crls[0] if self.crls else None

    @property
    def common_name(self):
        return common_name(self.x509.subject)

    @property
    def sorted_children(self):
        return sorted(self.children, key=lambda c: (c.name.lower(), c.not_after))


class CSR(db.Model):
    __tablename__ = "csrs"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    pem = db.Column(db.Text, nullable=False)
    subject = db.Column(db.Text, nullable=False)
    pubkey_fp = db.Column(db.String(64), index=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    key_id = db.Column(db.Integer, db.ForeignKey("keys.id"))
    cert_id = db.Column(db.Integer, db.ForeignKey("certificates.id"))

    key = db.relationship("Key", back_populates="csrs")
    cert = db.relationship("Certificate")

    @cached_property
    def x509(self):
        return x509.load_pem_x509_csr(self.pem.encode())


class Template(db.Model):
    __tablename__ = "templates"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    is_ca = db.Column(db.Boolean, default=False, nullable=False)
    path_length = db.Column(db.Integer)
    key_usage = db.Column(db.String(300), default="", nullable=False)
    ext_key_usage = db.Column(db.String(300), default="", nullable=False)
    validity_days = db.Column(db.Integer, nullable=False)
    key_algo = db.Column(db.String(20), nullable=False)
    subject_defaults = db.Column(db.Text, default="{}", nullable=False)

    @property
    def key_usage_list(self):
        return [u for u in self.key_usage.split(",") if u]

    @property
    def eku_list(self):
        return [u for u in self.ext_key_usage.split(",") if u]

    @property
    def defaults(self):
        return json.loads(self.subject_defaults or "{}")

    def profile(self):
        return Profile(
            is_ca=self.is_ca,
            path_length=self.path_length if self.is_ca else None,
            key_usage=self.key_usage_list,
            ext_key_usage=self.eku_list,
        )


class CRL(db.Model):
    __tablename__ = "crls"
    # Two CRLs from one CA must never share a number (RFC 5280 §5.2.3).
    __table_args__ = (db.Index("uq_crls_ca_number", "ca_id", "number", unique=True),)
    id = db.Column(db.Integer, primary_key=True)
    ca_id = db.Column(db.Integer, db.ForeignKey("certificates.id"), nullable=False)
    number = db.Column(db.Integer, nullable=False)
    this_update = db.Column(db.DateTime, nullable=False)
    next_update = db.Column(db.DateTime, nullable=False)
    pem = db.Column(db.Text, nullable=False)

    ca = db.relationship("Certificate", back_populates="crls")

    @cached_property
    def x509(self):
        return x509.load_pem_x509_crl(self.pem.encode())


class AuditLog(db.Model):
    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=utcnow, nullable=False)
    action = db.Column(db.String(40), nullable=False)
    detail = db.Column(db.String(1000), default="", nullable=False)
    ip = db.Column(db.String(64))
    username = db.Column(db.String(80))


# The "time_display" setting: how pages show times to everyone.
TIME_DISPLAYS = {"utc": "UTC", "local": "Local time zone"}

# Lowest to highest; each role can do everything the ones before it can.
ROLES = ("auditor", "operator", "admin")
ROLE_LABELS = {"auditor": "Auditor", "operator": "Operator", "admin": "Admin"}
ROLE_DESCRIPTIONS = {
    "auditor": "Read-only, including the audit log. Cannot unlock private keys.",
    "operator": "Issue, sign, renew and revoke end-entity certificates; re-sign CRLs.",
    "admin": "Everything: CAs, imports, deletions, key exports, users, settings and backups.",
}


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    # scrypt hash (JSON). Missing only for an admin migrated from the single-password version
    # until their first login.
    password_hash = db.Column(db.Text)
    # The vault data key wrapped with this user's password (JSON); only operators and admins.
    wrapped_key = db.Column(db.Text)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    disabled = db.Column(db.Boolean, default=False, nullable=False)
    # Bumped on password change, reset, role change or disable to end existing sessions.
    session_version = db.Column(db.Integer, default=1, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_login = db.Column(db.DateTime)

    @property
    def keyed(self):
        """Operators and admins can unlock the private keys."""
        return self.role in ("operator", "admin")

    @property
    def role_label(self):
        return ROLE_LABELS.get(self.role, self.role)

    def has_role(self, role):
        return ROLES.index(self.role) >= ROLES.index(role)


def _add_column(table, column, ddl):
    columns = {row[1] for row in db.session.execute(db.text(f"PRAGMA table_info({table})"))}
    if column not in columns:
        db.session.execute(db.text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))


def upgrade_schema():
    """Bring an existing database up to date. Safe to run on every start.
    Kept for databases restored from older backups, not only for upgrades in place."""
    # Columns first: the ORM queries below select every mapped column.
    _add_column("audit_log", "username", "VARCHAR(80)")
    _add_column("certificates", "pubkey_fp", "VARCHAR(64)")
    _add_column("csrs", "pubkey_fp", "VARCHAR(64)")
    # 0.9.1 kept the time display per user; it is now the global "time_display" setting.
    if "time_display" in {row[1] for row in db.session.execute(db.text("PRAGMA table_info(users)"))}:
        db.session.execute(db.text("ALTER TABLE users DROP COLUMN time_display"))
    db.session.execute(db.text(
        "CREATE INDEX IF NOT EXISTS ix_certificates_pubkey_fp ON certificates (pubkey_fp)"))
    db.session.execute(db.text("CREATE INDEX IF NOT EXISTS ix_csrs_pubkey_fp ON csrs (pubkey_fp)"))
    for model in (Certificate, CSR):
        for row in db.session.scalars(db.select(model).filter(model.pubkey_fp.is_(None))):
            row.pubkey_fp = fingerprint(row.x509.public_key())
    # The single-admin version kept the wrapped data key in settings: it becomes user "admin".
    legacy = db.session.get(Setting, "vault")
    if legacy is not None:
        if db.session.scalar(db.select(db.func.count(User.id))) == 0:
            db.session.add(User(username="admin", role="admin", wrapped_key=legacy.value))
        db.session.delete(legacy)
    # Version 2 shows the email attribute as E= instead of its OID; stored subjects are used to
    # match issuers, so rewrite them all in the new form once.
    if get_setting("subject_format") != "2":
        for cert in db.session.scalars(db.select(Certificate)):
            parsed = cert.x509
            cert.subject, cert.issuer_subject = name_text(parsed.subject), name_text(parsed.issuer)
        for req in db.session.scalars(db.select(CSR)):
            req.subject = name_text(req.x509.subject)
        set_setting("subject_format", "2")
    # Databases created before CRL numbers were unique get the index, unless they already hold
    # duplicates (then it is left out rather than failing to start).
    dupes = db.session.execute(db.text(
        "SELECT 1 FROM crls GROUP BY ca_id, number HAVING COUNT(*) > 1 LIMIT 1")).first()
    if dupes is None:
        db.session.execute(db.text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_crls_ca_number ON crls (ca_id, number)"))
    else:
        logging.getLogger(__name__).warning("crls has duplicate (ca_id, number) rows; unique index not created")
    db.session.commit()
