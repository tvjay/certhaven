from flask import Blueprint, flash, redirect, render_template, request, url_for

from .. import accounts, services
from ..models import ROLE_DESCRIPTIONS, db
from ..security import MIN_PASSWORD, current_user, login_session

bp = Blueprint("account", __name__)


@bp.route("/account")
def index():
    user = current_user()
    return render_template("account.html", user=user, min_password=MIN_PASSWORD,
                           role_description=ROLE_DESCRIPTIONS[user.role])


@bp.post("/account/password")
def password():
    user = current_user()
    new = request.form.get("new", "")
    try:
        accounts.check_new_password(new, request.form.get("confirm", ""))
        # Same per-IP limit as login and unlock, so a stolen session cannot guess the password.
        ok, dek = accounts.checked_verify(user, request.form.get("current", ""), request.remote_addr or "?")
        if not ok:
            services.audit("password_change_failed")
            db.session.commit()
            raise ValueError("The current password is incorrect.")
        if new == request.form.get("current", ""):
            raise ValueError("Choose a password different from the current one.")
    except (ValueError, accounts.CheckRefused) as exc:
        flash(str(exc), "error")
        return redirect(url_for(".index"))
    # The data key comes from the current password, so this works while the vault is locked.
    accounts.set_password(user, new, dek=dek)
    services.audit("password_change")
    db.session.commit()
    login_session(user)   # stay logged in here; other sessions end
    flash("Password changed. Your other sessions have been logged out.", "success")
    return redirect(url_for("main.dashboard"))
