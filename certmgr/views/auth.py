import json

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for

from .. import accounts, services
from ..crypto.vault import Vault
from ..models import User, db, set_setting, utcnow
from ..security import MIN_PASSWORD, current_user, is_configured, login_session, safe_next, vault

bp = Blueprint("auth", __name__)


def _check_password(user, password):
    """Returns ((ok, dek), None), or (None, status) after flashing why no check was run."""
    try:
        return accounts.checked_verify(user, password, request.remote_addr or "?"), None
    except accounts.CheckRefused as exc:
        flash(str(exc), "error")
        return None, exc.status


def _refresh_crls():
    try:
        refreshed = services.refresh_due_crls()
        if refreshed:
            services.audit("crl_refresh", f"{refreshed} CRL(s) re-signed after unlock")
    except ValueError as exc:
        flash(f"CRL refresh failed: {exc}", "error")


@bp.route("/setup", methods=["GET", "POST"])
def setup():
    if is_configured():
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        base_url = request.form.get("base_url", "").strip().rstrip("/")
        try:
            username = accounts.clean_username(request.form.get("username", ""))
            password = request.form.get("password", "")
            accounts.check_new_password(password, request.form.get("confirm", ""))
            if base_url and not base_url.startswith(("http://", "https://")):
                raise ValueError("The public base URL must start with http:// or https://.")
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            user = User(username=username, role="admin", session_version=1,
                        wrapped_key=json.dumps(vault.initialize(password)),
                        password_hash=json.dumps(Vault.hash_password(password)), last_login=utcnow())
            db.session.add(user)
            set_setting("base_url", base_url)
            services.seed_templates()
            db.session.flush()
            g.user = user
            services.audit("setup", f"Initial setup; admin {username} created")
            db.session.commit()
            login_session(user)
            flash("Setup complete. Start by creating a root CA.", "success")
            return redirect(url_for("main.dashboard"))
    return render_template("setup.html", min_password=MIN_PASSWORD)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if not is_configured():
        return redirect(url_for("auth.setup"))
    if request.method == "POST":
        username = request.form.get("username", "")
        user = accounts.find(username)
        result, status = _check_password(user, request.form.get("password", ""))
        if status:
            return render_template("login.html", next=request.form.get("next", "")), status
        ok, dek = result
        if ok:
            if dek:
                vault.load(dek)
            if user.password_hash is None:   # admin migrated from the single-password version
                user.password_hash = json.dumps(Vault.hash_password(request.form.get("password", "")))
            user.last_login = utcnow()
            login_session(user)
            g.user = user
            services.audit("login", user.role_label)
            if dek:
                _refresh_crls()
            db.session.commit()
            if user.must_change_password:
                return redirect(url_for("account.index"))
            return redirect(safe_next(request.form.get("next")))
        # Name the account only if it exists, so a password typed into the wrong box is not logged.
        services.audit("login_failed", f"user {user.username}" if user else "unknown or disabled user")
        db.session.commit()
        flash("Incorrect username or password.", "error")
    return render_template("login.html", next=request.values.get("next", ""))


@bp.route("/unlock", methods=["GET", "POST"])
def unlock():
    target = safe_next(request.values.get("next"))
    if vault.unlocked:
        return redirect(target)
    if request.method == "POST":
        result, status = _check_password(current_user(), request.form.get("password", ""))
        if status:
            return render_template("unlock.html", next=target), status
        ok, dek = result
        if ok and dek:
            vault.load(dek)
            services.audit("unlock")
            _refresh_crls()
            db.session.commit()
            flash("Private keys unlocked.", "success")
            return redirect(target)
        services.audit("unlock_failed")
        db.session.commit()
        flash("Incorrect password.", "error")
    return render_template("unlock.html", next=target)


@bp.post("/lock")
def lock():
    vault.lock()
    services.audit("lock")
    db.session.commit()
    flash("Private keys locked for everyone. Viewing still works; signing needs an unlock.", "success")
    return redirect(url_for("main.settings"))


@bp.post("/logout")
def logout():
    user = current_user()
    services.audit("logout")
    db.session.commit()
    if user.keyed:
        vault.lock()
    session.clear()
    flash("Logged out." + (" Private keys are locked." if user.keyed else ""), "success")
    return redirect(url_for("auth.login"))
