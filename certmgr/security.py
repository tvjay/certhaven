import hmac
import secrets
import threading
import time

from flask import abort, current_app, flash, g, redirect, render_template, request, session, url_for
from markupsafe import Markup
from werkzeug.exceptions import HTTPException

from .crypto.vault import Vault, VaultLocked
from .models import User, db, get_setting

vault = Vault()

MIN_PASSWORD = 12
SESSION_MAX_AGE = 12 * 3600   # log in again after 12 hours, however active

PUBLIC_ENDPOINTS = {"static", "auth.login", "auth.setup", "public.crl", "public.ca_cert"}
# Reachable while a user must still replace a temporary password.
PASSWORD_CHANGE_ENDPOINTS = {"auth.logout", "account.index", "account.password"}

# Minimum role per endpoint. Anything not listed needs "auditor" for GET and "admin" for
# every other method, so a new action is admin-only until it is classified here.
ENDPOINT_ROLES = {
    "auth.logout": "auditor",
    "account.index": "auditor",
    "account.password": "auditor",
    "auth.unlock": "operator",
    "auth.lock": "operator",
    "certs.new": "operator",          # CA certificates are admin-only inside the view
    "certs.renew": "operator",        # likewise for renewing or revoking a CA
    "certs.revoke": "operator",
    "certs.regenerate_crl": "operator",
    "csrs.import_csr": "operator",
    "csrs.new": "operator",
    "csrs.sign": "operator",
    "keys.new": "operator",
    "main.regenerate_crls": "operator",
    "main.settings": "admin",
    "main.backup": "admin",
    "certs.pkcs12": "admin",
    "templates.edit": "admin",
    "importer.index": "admin",
}
BLUEPRINT_ROLES = {"users": "admin"}

# Uploads are limited to MAX_CONTENT_LENGTH (2 MB) except here: a database backup can be larger.
MAX_RESTORE_SIZE = 64 * 1024 * 1024
LARGE_UPLOAD_ENDPOINTS = {"main.restore"}

MAX_FAILURES = 5
FAILURE_WINDOW = 15 * 60
_failures = {}
_failures_lock = threading.Lock()

# Each password check runs scrypt with ~128 MB of memory; cap how many run at once.
unlock_slots = threading.BoundedSemaphore(2)


def _recent_failures(ip):
    """Attempts from ip inside the window. IPs with none are dropped, so the table only
    ever holds addresses that tried to log in during the last FAILURE_WINDOW."""
    cutoff = time.monotonic() - FAILURE_WINDOW
    times = [t for t in _failures.get(ip, []) if t > cutoff]
    if times:
        _failures[ip] = times
    else:
        _failures.pop(ip, None)
    return times


def register_attempt(ip):
    """Count a login attempt before the password is checked, so parallel requests
    cannot all slip past the limit. Returns False if the IP is over the limit."""
    with _failures_lock:
        times = _recent_failures(ip)
        if len(times) >= MAX_FAILURES:
            return False
        _failures[ip] = times + [time.monotonic()]
        return True


def clear_failures(ip):
    with _failures_lock:
        _failures.pop(ip, None)


def reset_failures():
    with _failures_lock:
        _failures.clear()


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def csrf_field():
    return Markup('<input type="hidden" name="_csrf" value="%s">') % csrf_token()


def is_configured():
    # Once the first admin exists the app stays configured (the last admin cannot be
    # removed), so stop counting users on every request after that.
    if current_app.extensions.get("certmgr_configured"):
        return True
    configured = db.session.scalar(db.select(db.func.count(User.id))) > 0
    if configured:
        current_app.extensions["certmgr_configured"] = True
    return configured


def current_user():
    return g.get("user")


def has_role(role):
    user = current_user()
    return user is not None and user.has_role(role)


def require_role(role):
    if not has_role(role):
        abort(403)


def login_session(user):
    now = time.time()
    session.clear()
    session.update(uid=user.id, sv=user.session_version, iat=now, seen=now,
                   csrf=secrets.token_urlsafe(32))


def _session_user(idle):
    uid = session.get("uid")
    if not uid:
        return None
    user = db.session.get(User, uid)
    if user is None or user.disabled or user.session_version != session.get("sv"):
        return None
    now = time.time()
    if now - session.get("seen", 0) > idle or now - session.get("iat", 0) > SESSION_MAX_AGE:
        return None
    session["seen"] = now
    return user


def required_role(endpoint, method):
    if endpoint in ENDPOINT_ROLES:
        return ENDPOINT_ROLES[endpoint]
    blueprint = endpoint.split(".", 1)[0]
    if blueprint in BLUEPRINT_ROLES:
        return BLUEPRINT_ROLES[blueprint]
    return "auditor" if method in ("GET", "HEAD") else "admin"


def safe_next(target):
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("main.dashboard")


def _page_for(app, path):
    """A GET page to return to after unlocking: the path itself, else its parent."""
    adapter = app.url_map.bind("")
    for candidate in (path, path.rsplit("/", 1)[0]):
        try:
            adapter.match(candidate, method="GET")
            return candidate
        except HTTPException:
            continue
    return None


# (key, label, endpoint, minimum role)
NAV = [
    ("dashboard", "Dashboard", "main.dashboard", "auditor"),
    ("cas", "CAs", "certs.cas", "auditor"),
    ("certs", "Certificates", "certs.index", "auditor"),
    ("csrs", "CSRs", "csrs.index", "auditor"),
    ("keys", "Keys", "keys.index", "auditor"),
    ("templates", "Templates", "templates.index", "auditor"),
    ("import", "Import", "importer.index", "admin"),
    ("audit", "Audit log", "main.audit", "auditor"),
    ("users", "Users", "users.index", "admin"),
    ("settings", "Settings", "main.settings", "admin"),
]


def init_app(app):
    app.jinja_env.globals.update(csrf_field=csrf_field, nav_items=NAV, can=has_role)

    @app.context_processor
    def _ctx():
        user = current_user()
        return {"logged_in": user is not None, "current_user": user, "keys_unlocked": vault.unlocked,
                "time_display": get_setting("time_display", "utc")}

    @app.before_request
    def _guard():
        if request.method == "POST":
            if request.endpoint in LARGE_UPLOAD_ENDPOINTS:
                request.max_content_length = MAX_RESTORE_SIZE   # before the form is parsed
            sent = request.form.get("_csrf", "")
            expected = session.get("csrf", "")
            if not expected or not hmac.compare_digest(sent, expected):
                abort(400, "Invalid or missing CSRF token. Reload the page and try again.")

        if request.endpoint is None or request.endpoint in PUBLIC_ENDPOINTS:
            return None
        if not is_configured():
            return redirect(url_for("auth.setup"))
        idle = int(get_setting("idle_timeout", "30")) * 60
        vault.expire_if_idle(idle)
        user = _session_user(idle)
        if user is None:
            csrf = session.get("csrf")
            session.clear()
            if csrf:
                session["csrf"] = csrf
            target = request.full_path.rstrip("?") if request.method == "GET" else None
            return redirect(url_for("auth.login", next=target))
        g.user = user
        if user.keyed:
            vault.touch()
        if user.must_change_password and request.endpoint not in PASSWORD_CHANGE_ENDPOINTS:
            flash("Choose a new password before continuing.", "warning")
            return redirect(url_for("account.index"))
        require_role(required_role(request.endpoint, request.method))
        return None

    @app.errorhandler(VaultLocked)
    def _locked(_exc):
        db.session.rollback()
        flash("The private keys are locked. Enter your password to unlock them, then try again.", "warning")
        return redirect(url_for("auth.unlock", next=_page_for(app, request.path)))

    @app.errorhandler(403)
    def _forbidden(_exc):
        return render_template("error.html", code=403, title="Not allowed",
                               message="Your role does not allow this. Ask an admin if you need access."), 403

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        if request.endpoint not in ("static", "public.crl", "public.ca_cert"):
            resp.headers["Cache-Control"] = "no-store"
        return resp
