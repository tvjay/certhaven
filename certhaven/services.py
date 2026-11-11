"""Business logic between the database models and the crypto modules.

Functions here add/flush rows but never commit; views commit once per request.
"""
import json
from datetime import timedelta

from cryptography.hazmat.primitives import hashes, serialization
from flask import g, has_app_context, has_request_context, request
from sqlalchemy.orm import selectinload

from .crypto import certs as certlib
from .crypto import crl as crllib
from .crypto import csr as csrlib
from .crypto import keys as keylib
from .models import CRL, CSR, AuditLog, Certificate, DeletedRevocation, Key, Template, db, get_setting, utcnow
from .security import vault

# A CRL this close to its next update is due: re-signed at unlock, flagged on the dashboard and in alerts.
CRL_DUE_MARGIN = timedelta(days=7)
# A CA whose key is offline is flagged earlier, to leave time to fetch the key and import it.
OFFLINE_CRL_DUE_MARGIN = timedelta(days=30)
CRL_DAYS_MIN, CRL_DAYS_MAX = 8, 365
CRLS_KEPT = 5
MAX_VALIDITY_DAYS = 36500


def audit(action, detail=""):
    user = g.get("user") if has_app_context() else None
    db.session.add(AuditLog(action=action, detail=(detail or "")[:1000],
                            ip=request.remote_addr if has_request_context() else None,
                            username=user.username if user is not None else None))


# --- keys -----------------------------------------------------------------

def load_private_key(key_row):
    return keylib.load_private(vault.decrypt(key_row.encrypted))


def save_key(private_key, name):
    keylib.check_supported(private_key)
    fp = keylib.fingerprint(private_key)
    existing = db.session.scalar(db.select(Key).filter_by(fingerprint=fp))
    if existing:
        return existing, False
    row = Key(name=name or keylib.describe(private_key), algo=keylib.describe(private_key),
              fingerprint=fp, public_pem=keylib.public_pem(private_key),
              encrypted=vault.encrypt(keylib.to_pem(private_key)))
    db.session.add(row)
    db.session.flush()
    # Attach the key to any certificates or CSRs already holding its public half.
    for model in (Certificate, CSR):
        for item in db.session.scalars(db.select(model).filter_by(key_id=None, pubkey_fp=fp)):
            item.key = row
    return row, True


def key_from_form(form, name, default_algo):
    """The key a form asks for: a newly generated one ("new"), or an existing key by id.
    Returns (key_row, belongs_to_a_ca) so each caller applies its own rule for CA keys."""
    if form.get("key", "new") == "new":
        algo = form.get("key_algo", default_algo)
        if algo not in keylib.ALGORITHMS:
            raise ValueError("Unknown key algorithm.")
        return save_key(keylib.generate(algo), name)[0], False
    try:
        key_row = db.session.get(Key, int(form.get("key")))
    except (TypeError, ValueError):
        key_row = None
    if key_row is None:
        raise ValueError("Unknown key.")
    return key_row, key_row.id in ca_key_ids()


def ca_key_ids():
    """Ids of keys that belong to a CA certificate."""
    return set(db.session.scalars(db.select(Certificate.key_id).filter(
        Certificate.is_ca, Certificate.key_id.isnot(None))))


def key_for_public(public_key):
    return _key_with_fingerprint(keylib.fingerprint(public_key))


def _key_with_fingerprint(fp):
    return db.session.scalar(db.select(Key).filter_by(fingerprint=fp))


# --- certificates ---------------------------------------------------------

def _issued_by(child, parent):
    try:
        child.verify_directly_issued_by(parent)
        return True
    except Exception:
        return False


def find_issuer(cert):
    candidates = db.session.scalars(db.select(Certificate).filter_by(
        is_ca=True, subject=certlib.name_text(cert.issuer)))
    for candidate in candidates:
        if _issued_by(cert, candidate.x509):
            return candidate
    return None


def save_cert(cert, name=None):
    fp = cert.fingerprint(hashes.SHA256()).hex()
    existing = db.session.scalar(db.select(Certificate).filter_by(fingerprint=fp))
    if existing:
        return existing, False
    bc = certlib.basic_constraints(cert)
    self_signed = cert.issuer == cert.subject and _issued_by(cert, cert)
    # Look up related rows before creating ours, so autoflush never sees a half-built row.
    issuer = None if self_signed else find_issuer(cert)
    pubkey_fp = keylib.fingerprint(cert.public_key())
    key = _key_with_fingerprint(pubkey_fp)
    row = Certificate(
        name=name or certlib.common_name(cert.subject) or certlib.name_text(cert.subject) or "Certificate",
        fingerprint=fp,
        serial=format(cert.serial_number, "x"),
        subject=certlib.name_text(cert.subject),
        issuer_subject=certlib.name_text(cert.issuer),
        not_before=cert.not_valid_before_utc.replace(tzinfo=None),
        not_after=cert.not_valid_after_utc.replace(tzinfo=None),
        is_ca=bool(bc and bc.ca),
        self_signed=self_signed,
        pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        pubkey_fp=pubkey_fp,
        key=key,
        issuer=issuer,
    )
    db.session.add(row)
    db.session.flush()
    if row.is_ca:
        # Adopt certificates imported before their issuer.
        orphans = db.session.scalars(db.select(Certificate).filter_by(
            issuer_id=None, self_signed=False, issuer_subject=row.subject))
        for orphan in orphans:
            if orphan.id != row.id and _issued_by(orphan.x509, cert):
                orphan.issuer = row
    return row, True


def chain(row):
    """Issuers of row, nearest first, up to the root."""
    out, seen = [], {row.id}
    node = row.issuer
    while node is not None and node.id not in seen:
        out.append(node)
        seen.add(node.id)
        node = node.issuer
    return out


def signing_cas(with_crls=False):
    """Valid CAs whose private key is in the database. with_crls loads their CRLs in one query."""
    stmt = db.select(Certificate).filter(Certificate.is_ca, Certificate.key_id.isnot(None)).order_by(
        db.func.lower(Certificate.name))
    if with_crls:
        stmt = stmt.options(selectinload(Certificate.crls))
    return [r for r in db.session.scalars(stmt) if r.status == "valid"]


def _base_url():
    return (get_setting("base_url", "") or "").rstrip("/")


def crl_url(ca_id):
    base = _base_url()
    return f"{base}/crl/{ca_id}.crl" if base else None


def aia_url(ca_id):
    base = _base_url()
    return f"{base}/ca/{ca_id}.crt" if base else None


def issue_certificate(*, name, subject, public_key, key_row, issuer_row, profile, sans, days):
    """Sign a new certificate. issuer_row=None means self-signed with key_row."""
    if not 1 <= days <= MAX_VALIDITY_DAYS:
        raise ValueError(f"Validity must be between 1 and {MAX_VALIDITY_DAYS} days.")
    now = utcnow()
    not_before = now - timedelta(minutes=5)
    not_after = now + timedelta(days=days)
    warnings = []
    if issuer_row is not None:
        if not issuer_row.is_ca:
            raise ValueError(f"{issuer_row.name} is not a CA certificate.")
        if issuer_row.key is None:
            raise ValueError(f"The private key for {issuer_row.name} is not in the database.")
        if issuer_row.status != "valid":
            raise ValueError(f"The issuing CA {issuer_row.name} is {issuer_row.status}.")
        issuer_cert = issuer_row.x509
        bc = certlib.basic_constraints(issuer_cert)
        if profile.is_ca and bc and bc.path_length is not None:
            if bc.path_length == 0:
                raise ValueError(f"{issuer_row.name} has path length 0 and cannot issue sub-CAs.")
            if profile.path_length is None or profile.path_length >= bc.path_length:
                profile.path_length = bc.path_length - 1
                warnings.append(f"Path length reduced to {profile.path_length} to fit under the issuer.")
        if not_after > issuer_row.not_after:
            not_after = issuer_row.not_after
            warnings.append(f"Validity shortened to end with the issuing CA on {not_after:%Y-%m-%d}.")
        signer = load_private_key(issuer_row.key)
        crl, aia = crl_url(issuer_row.id), aia_url(issuer_row.id)
    else:
        if key_row is None:
            raise ValueError("A self-signed certificate needs its private key.")
        issuer_cert, signer, crl, aia = None, load_private_key(key_row), None, None

    cert = certlib.issue(subject=subject, public_key=public_key, signer_key=signer,
                         issuer_cert=issuer_cert, profile=profile, sans=sans,
                         not_before=not_before, not_after=not_after, crl_url=crl, aia_url=aia)
    row, _ = save_cert(cert, name)
    if key_row is not None:
        row.key = key_row
    if issuer_row is not None:
        row.issuer = issuer_row
    if row.is_ca:
        regenerate_crl(row)
    return row, warnings


def renew(row):
    cert = row.x509
    profile, sans = certlib.profile_from_cert(cert)
    days = max(1, (row.not_after - row.not_before).days)
    if not row.self_signed and row.issuer is None:
        raise ValueError("The issuer of this certificate is not in the database.")
    return issue_certificate(name=row.name, subject=cert.subject, public_key=cert.public_key(),
                             key_row=row.key, issuer_row=None if row.self_signed else row.issuer,
                             profile=profile, sans=sans, days=days)


def revoke(row, reason):
    if reason not in crllib.REASONS:
        raise ValueError("Unknown revocation reason.")
    row.revoked_at = utcnow()
    row.revocation_reason = reason
    if row.issuer is not None and row.issuer.key is not None:
        regenerate_crl(row.issuer)


def delete_cert(row):
    """Delete a certificate. A revoked one that has not expired leaves a DeletedRevocation behind, so its
    CA's CRL keeps listing it; otherwise deleting it would make clients trust it again. Returns that record,
    or None."""
    if row.children:
        raise ValueError("This CA has issued certificates; delete or move those first.")
    kept = None
    if row.on_crl and row.issuer_id:
        kept = DeletedRevocation(ca_id=row.issuer_id, name=row.name, serial=row.serial, revoked_at=row.revoked_at,
                                 revocation_reason=row.revocation_reason, not_after=row.not_after)
        db.session.add(kept)
    for req in db.session.scalars(db.select(CSR).filter_by(cert_id=row.id)):
        req.cert = None
    db.session.delete(row)
    return kept


# --- CRLs -----------------------------------------------------------------

def regenerate_crl(ca_row):
    if ca_row.key is None:
        raise ValueError(f"The private key for {ca_row.name} is not in the database.")
    last = ca_row.latest_crl
    number = last.number + 1 if last else 1
    revoked = [(int(serial, 16), when, reason) for serial, when, reason in db.session.execute(
        db.select(Certificate.serial, Certificate.revoked_at, Certificate.revocation_reason)
        .filter(Certificate.issuer_id == ca_row.id, Certificate.revoked_at.isnot(None)))]
    now = utcnow()
    # Revoked certificates deleted before they expired stay on the CRL until then; expired ones are dropped.
    for gone in list(ca_row.deleted_revocations):
        if gone.not_after > now:
            revoked.append((int(gone.serial, 16), gone.revoked_at, gone.revocation_reason))
        else:
            db.session.delete(gone)
    days = crl_days_for(ca_row)
    crl = crllib.build(ca_row.x509, load_private_key(ca_row.key), revoked, number, now, days)
    row = CRL(ca=ca_row, number=number, this_update=now, next_update=now + timedelta(days=days),
              pem=crl.public_bytes(serialization.Encoding.PEM).decode())
    db.session.add(row)
    db.session.flush()
    db.session.expire(ca_row, ["crls"])
    for old in ca_row.crls[CRLS_KEPT:]:
        db.session.delete(old)
    return row


def crl_days_for(ca):
    """Days a new CRL from ca is valid: its own setting, else the global one."""
    return ca.crl_days or int(get_setting("crl_days", "30"))


def crl_due(ca, now):
    """True when ca has no CRL yet or its latest one expires within the margin: CRL_DUE_MARGIN while
    certhaven holds the key, OFFLINE_CRL_DUE_MARGIN while it is offline."""
    latest = ca.latest_crl
    margin = CRL_DUE_MARGIN if ca.key_id else OFFLINE_CRL_DUE_MARGIN
    return latest is None or latest.next_update - now < margin


def take_key_offline(ca_row):
    """Re-sign ca_row's CRL with its full validity, then remove its private key from the database.
    The certificate stays; importing the key file later attaches it again (see save_key).
    Returns the new CRL."""
    if not ca_row.is_ca or ca_row.key is None:
        raise ValueError(f"{ca_row.name} has no private key in certhaven to take offline.")
    crl = regenerate_crl(ca_row)   # the CRL clients will use until the key is back
    key = ca_row.key
    for model in (Certificate, CSR):   # renewed copies of the CA certificate share the key
        for item in db.session.scalars(db.select(model).filter_by(key_id=key.id)):
            item.key = None
    db.session.delete(key)
    return crl


def offline_cas_due(now):
    """Valid CAs whose key is offline and whose last CRL is due: only importing the key can renew it."""
    rows = db.session.scalars(db.select(Certificate).filter(Certificate.is_ca, Certificate.key_id.is_(None))
                              .options(selectinload(Certificate.crls)))
    return [ca for ca in rows if ca.status == "valid" and ca.latest_crl and crl_due(ca, now)]


def refresh_due_crls():
    """Re-sign CRLs that are missing or due. Returns count."""
    now = utcnow()
    due = [ca for ca in signing_cas() if crl_due(ca, now)]
    for ca in due:
        regenerate_crl(ca)
    return len(due)


# --- CSRs -----------------------------------------------------------------

def save_csr(csr, name=None):
    pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    pubkey_fp = keylib.fingerprint(csr.public_key())
    existing = db.session.scalar(db.select(CSR).filter_by(pubkey_fp=pubkey_fp, pem=pem))
    if existing:
        return existing, False
    if not csr.is_signature_valid:
        raise ValueError("The CSR signature is invalid.")
    row = CSR(name=name or certlib.common_name(csr.subject) or "CSR", pem=pem,
              subject=certlib.name_text(csr.subject), pubkey_fp=pubkey_fp,
              key=_key_with_fingerprint(pubkey_fp))
    db.session.add(row)
    db.session.flush()
    return row, True


def create_csr(name, subject, sans, key_row):
    req = csrlib.build(subject, load_private_key(key_row), sans)
    row, _ = save_csr(req, name)
    row.key = key_row
    return row


# --- templates ------------------------------------------------------------

BUILTIN_TEMPLATES = [
    dict(name="Root CA", is_ca=True, path_length=None, key_usage="keyCertSign,cRLSign,digitalSignature",
         ext_key_usage="", validity_days=7300, key_algo="ec384"),
    dict(name="Intermediate CA", is_ca=True, path_length=0, key_usage="keyCertSign,cRLSign,digitalSignature",
         ext_key_usage="", validity_days=3650, key_algo="ec384"),
    dict(name="TLS Server", is_ca=False, path_length=None, key_usage="digitalSignature,keyEncipherment",
         ext_key_usage="serverAuth", validity_days=397, key_algo="ec256"),
    dict(name="TLS Client", is_ca=False, path_length=None, key_usage="digitalSignature",
         ext_key_usage="clientAuth", validity_days=397, key_algo="ec256"),
    dict(name="TLS Server + Client", is_ca=False, path_length=None,
         key_usage="digitalSignature,keyEncipherment", ext_key_usage="serverAuth,clientAuth",
         validity_days=397, key_algo="ec256"),
]


def seed_templates():
    for spec in BUILTIN_TEMPLATES:
        if not db.session.scalar(db.select(Template).filter_by(name=spec["name"])):
            db.session.add(Template(subject_defaults=json.dumps({}), **spec))
