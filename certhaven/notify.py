"""Email alerts: certificate expiry, CRL due/expired, failed logins.

Runs from a systemd timer (`flask --app wsgi notify`). It only reads stored data,
so it works while the vault is locked. Each alert has a key recorded in the
"notify_state" setting once sent, so every warning goes out once per stage.
SMTP settings are edited on the Settings page and stored in a KEY=VALUE file in
the data directory (mode 0600), kept out of the database and its backups. The
timer must read them while the vault is locked, so they are not encrypted.
"""
import json
import os
import re
import smtplib
import tempfile
import socket
import ssl
from collections import defaultdict
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.utils import formataddr
from functools import lru_cache

import click
from flask import current_app
from sqlalchemy.orm import selectinload

from .models import AuditLog, Certificate, db, get_setting, set_setting, utcnow
from .services import CRL_DUE_MARGIN

EXPIRY_THRESHOLDS = (1, 7, 14, 30)
EXPIRED_GRACE = timedelta(days=7)   # still report certificates that expired this recently
STATE_RETENTION = timedelta(days=400)


@lru_cache(maxsize=1)
def hostname():
    return socket.getfqdn()


# --- configuration --------------------------------------------------------

FIELDS = ("SMTP_HOST", "SMTP_PORT", "SMTP_SECURITY", "SMTP_USER", "SMTP_PASSWORD",
          "MAIL_FROM", "MAIL_FROM_NAME", "MAIL_TO", "ADMIN_URL")
# Shown as the sender in mail clients when MAIL_FROM_NAME is empty.
DEFAULT_FROM_NAME = "certhaven"
SECURITY_MODES = ("starttls", "ssl", "none")
# Mail ports only, so the SMTP setting cannot be used to probe other services from the server.
SMTP_PORTS = (25, 465, 587, 2525)
_EMAIL_RE = re.compile(r"^[^@\s,<>\"]+@[^@\s,<>\"]+\.[^@\s,<>\"]+$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$|^\[[0-9A-Fa-f:.]+\]$")


def read_config():
    """All stored settings (possibly incomplete); {} when there is no readable file."""
    cfg = {}
    try:
        with open(current_app.config["NOTIFY_CONF"], encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                cfg[key.strip()] = value
    except (FileNotFoundError, PermissionError):
        return {}
    return cfg


def load_config():
    """Return the SMTP settings, or None when not configured."""
    cfg = read_config()
    if not cfg.get("SMTP_HOST") or not recipients(cfg):
        return None
    return cfg


def recipients(cfg):
    return [a.strip() for a in cfg.get("MAIL_TO", "").split(",") if a.strip()]


def validate(values):
    """Check settings from the form; return a clean dict or raise ValueError."""
    clean = {k: (values.get(k) or "").strip() for k in FIELDS}
    clean["SMTP_PASSWORD"] = values.get("SMTP_PASSWORD") or ""   # passwords may have edge spaces
    for key, value in clean.items():
        if any(c in value for c in "\r\n\0"):
            raise ValueError("Settings cannot contain line breaks.")
        if len(value) > 500:
            raise ValueError(f"{key} is too long.")
    if len(clean["MAIL_FROM_NAME"]) > 100:
        raise ValueError("The sender name is too long (100 characters at most).")
    if not clean["SMTP_HOST"]:
        return {**clean, "SMTP_HOST": ""}   # saving without a host turns alerts off
    if not _HOST_RE.match(clean["SMTP_HOST"]):
        raise ValueError("SMTP server must be a hostname or IP address.")
    clean["SMTP_SECURITY"] = clean["SMTP_SECURITY"].lower() or "starttls"
    if clean["SMTP_SECURITY"] not in SECURITY_MODES:
        raise ValueError("Security must be STARTTLS, SSL/TLS or none.")
    if clean["SMTP_PORT"]:
        if not clean["SMTP_PORT"].isdigit() or int(clean["SMTP_PORT"]) not in SMTP_PORTS:
            raise ValueError("Port must be one of " + ", ".join(map(str, SMTP_PORTS)) + ".")
    if clean["SMTP_USER"] and clean["SMTP_SECURITY"] == "none":
        raise ValueError("Use STARTTLS or SSL/TLS when logging in, so the password is not sent in clear text.")
    to = recipients(clean)
    if not to:
        raise ValueError("Enter at least one recipient.")
    bad = [a for a in to + ([clean["MAIL_FROM"]] if clean["MAIL_FROM"] else []) if not _EMAIL_RE.match(a)]
    if bad:
        raise ValueError(f"Not a valid email address: {bad[0]}")
    clean["MAIL_TO"] = ", ".join(to)
    if clean["ADMIN_URL"] and not clean["ADMIN_URL"].startswith(("https://", "http://")):
        raise ValueError("Admin link must start with https:// or http://.")
    return clean


def save_config(values):
    """Validate and write the settings file atomically with mode 0600."""
    clean = validate(values)
    path = current_app.config["NOTIFY_CONF"]
    lines = ["# certhaven email alerts. Managed from Settings in the web UI."]
    lines += [f'{key}="{clean[key]}"' for key in FIELDS]
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".notify-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return clean


def describe_error(exc):
    """A short, user-facing reason for a failed send. The full error goes to the server log only,
    so connection details from arbitrary hosts are not echoed back into the web UI."""
    current_app.logger.warning("email alert failed: %r", exc)
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "the SMTP server rejected the username or password"
    if isinstance(exc, ssl.SSLError):
        return "the TLS handshake failed; check the security setting and port"
    if isinstance(exc, smtplib.SMTPException):
        return "the SMTP server refused the message"
    if isinstance(exc, OSError):
        return "could not connect to the SMTP server"
    return "unexpected error (see the server log)"


def send_email(cfg, subject, body):
    security = cfg.get("SMTP_SECURITY", "starttls").lower()
    if security not in ("starttls", "ssl", "none"):
        raise ValueError(f"SMTP_SECURITY must be starttls, ssl or none, not {security!r}")
    host = cfg["SMTP_HOST"]
    port = int(cfg.get("SMTP_PORT") or {"ssl": 465, "starttls": 587, "none": 25}[security])
    msg = EmailMessage()
    msg["Subject"] = subject
    address = cfg.get("MAIL_FROM") or cfg.get("SMTP_USER") or f"certhaven@{hostname()}"
    msg["From"] = formataddr((cfg.get("MAIL_FROM_NAME") or DEFAULT_FROM_NAME, address))
    msg["To"] = ", ".join(recipients(cfg))
    msg.set_content(body)
    context = ssl.create_default_context()
    if security == "ssl":
        smtp = smtplib.SMTP_SSL(host, port, context=context, timeout=20)
    else:
        smtp = smtplib.SMTP(host, port, timeout=20)
    with smtp:
        if security == "starttls":
            smtp.starttls(context=context)
        if cfg.get("SMTP_USER"):
            smtp.login(cfg["SMTP_USER"], cfg.get("SMTP_PASSWORD", ""))
        smtp.send_message(msg)


# --- collecting alerts ----------------------------------------------------

def _latest_valid_expiry(now):
    """(subject, issuer) -> the latest expiry among valid certificates, in one grouped query."""
    rows = db.session.execute(
        db.select(Certificate.subject, Certificate.issuer_subject, db.func.max(Certificate.not_after))
        .filter(Certificate.status_clause("valid", now))
        .group_by(Certificate.subject, Certificate.issuer_subject))
    return {(subject, issuer): latest for subject, issuer, latest in rows}


def collect(now, state):
    """Return (alerts, newest audit id). Each alert is (key, section, text)."""
    sent = state.get("sent", {})
    alerts = []
    # Only what can raise an alert: certificates near or just past expiry, and CAs for their CRLs.
    soon, recent = now + timedelta(days=max(EXPIRY_THRESHOLDS)), now - EXPIRED_GRACE
    certs = db.session.scalars(db.select(Certificate).filter(
        Certificate.is_ca | Certificate.not_after.between(recent, soon))
        .options(selectinload(Certificate.crls))).all()
    latest_valid = _latest_valid_expiry(now)

    for cert in sorted(certs, key=lambda c: c.not_after):
        if cert.revoked_at:
            continue
        kind = "CA certificate" if cert.is_ca else "Certificate"
        if cert.not_after <= now:
            if now - cert.not_after > EXPIRED_GRACE:
                continue
            bucket, text = "expired", f"{kind} {cert.name} EXPIRED on {cert.not_after:%Y-%m-%d %H:%M} UTC"
        else:
            days = (cert.not_after - now).days
            bucket = next((t for t in EXPIRY_THRESHOLDS if days < t), None)
            if bucket is None:
                continue
            when = "in less than a day" if days == 0 else f"in {days} day{'s' if days != 1 else ''}"
            text = f"{kind} {cert.name} expires {when} ({cert.not_after:%Y-%m-%d} UTC)"
        # Skip it if a newer valid certificate with the same subject and issuer replaces it.
        if latest_valid.get((cert.subject, cert.issuer_subject), cert.not_after) > cert.not_after:
            continue
        key = f"cert:{cert.fingerprint}:{bucket}"
        if key not in sent:
            issuer = cert.issuer.name if cert.issuer else ("self-signed" if cert.self_signed else cert.issuer_subject)
            alerts.append((key, "Certificates", f"{text}; issuer: {issuer}"))

    for ca in certs:
        crl = ca.latest_crl if ca.is_ca and ca.status == "valid" else None
        if crl is None:
            continue
        if crl.next_update <= now:
            kind, text = "expired", (f"CRL #{crl.number} for {ca.name} EXPIRED on {crl.next_update:%Y-%m-%d %H:%M} UTC. "
                                     "Clients that check revocation may reject its certificates")
        elif crl.next_update - now < CRL_DUE_MARGIN:
            kind, text = "due", f"CRL #{crl.number} for {ca.name} expires {crl.next_update:%Y-%m-%d %H:%M} UTC"
        else:
            continue
        key = f"crl:{ca.id}:{crl.number}:{kind}"
        if key not in sent:
            alerts.append((key, "Revocation lists", text + ". Log in to certhaven to re-sign it."))

    newest = db.session.scalar(db.select(db.func.max(AuditLog.id))) or 0
    last = state.get("last_audit_id")
    if last is not None:
        failures = db.session.scalars(db.select(AuditLog).filter(
            AuditLog.id > last, AuditLog.id <= newest, AuditLog.action == "login_failed")).all()
        by_ip = defaultdict(list)
        for row in failures:
            by_ip[row.ip or "unknown"].append(row.ts)
        for ip, times in sorted(by_ip.items()):
            span = (f"at {times[0]:%Y-%m-%d %H:%M}" if len(times) == 1
                    else f"between {min(times):%Y-%m-%d %H:%M} and {max(times):%H:%M}")
            alerts.append((None, "Failed logins",
                           f"{len(times)} failed login attempt{'s' if len(times) != 1 else ''} from {ip} {span} UTC"))
    return alerts, newest


def _subject(alerts):
    counts = defaultdict(int)
    for _, section, _ in alerts:
        counts[section] += 1
    parts = []
    if counts["Certificates"]:
        parts.append(f"{counts['Certificates']} certificate{'s' if counts['Certificates'] != 1 else ''} expiring")
    if counts["Revocation lists"]:
        parts.append(f"{counts['Revocation lists']} CRL{'s' if counts['Revocation lists'] != 1 else ''} due")
    if counts["Failed logins"]:
        parts.append("failed logins")
    return "[certhaven] " + ", ".join(parts)


def _body(cfg, alerts):
    lines = []
    for section in ("Certificates", "Revocation lists", "Failed logins"):
        items = [text for _, s, text in alerts if s == section]
        if items:
            lines += [section, "-" * len(section)] + [f"- {t}" for t in items] + [""]
    if cfg.get("ADMIN_URL"):
        lines.append(f"Open certhaven: {cfg['ADMIN_URL']}")
    lines.append(f"Sent by certhaven on {hostname()}. Times are UTC.")
    return "\n".join(lines)


# --- running --------------------------------------------------------------

def _record(status, state=None):
    """Store the run's status for the Settings page; state only when the run completed."""
    if state is not None:
        set_setting("notify_state", json.dumps(state))
    set_setting("notify_last", json.dumps(status))
    db.session.commit()
    return status


def run(dry_run=False):
    """Collect and send new alerts. Returns a status dict, also stored for the Settings page."""
    now = utcnow()
    state = json.loads(get_setting("notify_state", "{}"))
    alerts, newest = collect(now, state)
    status = {"time": now.isoformat(), "alerts": len(alerts)}
    cfg = load_config()

    if dry_run:
        status["result"] = "dry run"
        status["preview"] = _body(cfg or {}, alerts) if alerts else ""
        return status
    if alerts:
        if cfg is None:
            status["result"] = "not configured"
            return _record(status)   # alerts stay pending until email is configured
        try:
            send_email(cfg, _subject(alerts), _body(cfg, alerts))
        except Exception as exc:  # report any SMTP/network failure; retry next run
            status["result"] = f"error: {describe_error(exc)}"
            return _record(status)
        status["result"] = "sent"
    else:
        status["result"] = "nothing new"

    sent = state.setdefault("sent", {})
    for key, _, _ in alerts:
        if key:
            sent[key] = now.isoformat()
    cutoff = now - STATE_RETENTION
    state["sent"] = {k: t for k, t in sent.items() if datetime.fromisoformat(t) > cutoff}
    state["last_audit_id"] = newest
    return _record(status, state)


def send_test():
    cfg = load_config()
    if cfg is None:
        raise ValueError("Email is not configured. Enter an SMTP server and recipient under Settings.")
    send_email(cfg, "[certhaven] Test notification",
               f"This is a test from certhaven on {hostname()}.\n"
               "Alerts for certificate expiry, CRLs and failed logins will be sent to this address.")
    return recipients(cfg)


def summary():
    """What the Settings page shows. Never includes the password itself."""
    raw = read_config()
    return {
        "configured": bool(raw.get("SMTP_HOST")) and bool(recipients(raw)),
        "values": {k: raw.get(k, "") for k in FIELDS if k != "SMTP_PASSWORD"},
        "default_from_name": DEFAULT_FROM_NAME,
        "password_set": bool(raw.get("SMTP_PASSWORD")),
        "last": json.loads(get_setting("notify_last", "null")),
    }


def register_cli(app):
    @app.cli.command("notify")
    @click.option("--dry-run", is_flag=True, help="Show what would be sent without sending or recording it.")
    @click.option("--test", is_flag=True, help="Send a test email and exit.")
    def notify_command(dry_run, test):
        """Send email alerts for expiring certificates, CRLs and failed logins."""
        if test:
            click.echo(f"Test email sent to {', '.join(send_test())}.")
            return
        status = run(dry_run=dry_run)
        if status.get("preview"):
            click.echo(status["preview"])
        click.echo(f"{status['alerts']} alert(s): {status['result']}")
        if status["result"].startswith("error"):
            raise SystemExit(1)
