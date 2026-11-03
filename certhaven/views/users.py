from flask import Blueprint, flash, redirect, render_template, request, url_for

from .. import accounts, services
from ..models import ROLE_DESCRIPTIONS, ROLE_LABELS, ROLES, User, db
from ..security import MIN_PASSWORD, current_user

bp = Blueprint("users", __name__)


def _render_form(user=None, values=None):
    return render_template("user_form.html", user=user, values=values or {}, roles=ROLES,
                           role_labels=ROLE_LABELS, role_descriptions=ROLE_DESCRIPTIONS,
                           min_password=MIN_PASSWORD)


@bp.route("/users")
def index():
    # Users are managed on Settings; this keeps old links and bookmarks working.
    return redirect(url_for("main.settings", _anchor="users"))


@bp.route("/users/new", methods=["GET", "POST"])
def new():
    if request.method == "POST":
        form = request.form
        try:
            username = accounts.clean_username(form.get("username"))
            if db.session.scalar(db.select(User).filter_by(username=username)):
                raise ValueError("That username is taken.")
            role = accounts.check_role(form.get("role"))
            password = form.get("password", "")
            accounts.check_new_password(password, form.get("confirm", ""))
        except ValueError as exc:
            flash(str(exc), "error")
            return _render_form(values=form)
        user = User(username=username, role=role, session_version=0)
        accounts.set_password(user, password, temporary=True)   # keyed roles need the vault unlocked
        db.session.add(user)
        services.audit("user_create", f"{username} as {user.role_label}")
        db.session.commit()
        flash(f"Created {username}. Give them the temporary password; they must change it at first login.",
              "success")
        return redirect(url_for("main.settings", _anchor="users"))
    return _render_form(values={"role": "operator"})


@bp.route("/users/<int:id>", methods=["GET", "POST"])
def edit(id):
    user = db.get_or_404(User, id)
    me = current_user()
    if request.method == "POST":
        form = request.form
        try:
            role = accounts.check_role(form.get("role"))
            disabled = bool(form.get("disabled"))
            password = form.get("password", "")
            demoting_admin = user.role == "admin" and (role != "admin" or disabled)
            if user.id == me.id and (role != user.role or disabled):
                raise ValueError("You cannot change your own role or disable yourself.")
            if demoting_admin and not user.disabled and accounts.active_admins() <= 1:
                raise ValueError("Keep at least one active admin.")
            gains_keys = role in ("operator", "admin") and not user.wrapped_key
            if gains_keys and not password:
                raise ValueError("To give this user access to the private keys, set a temporary password: "
                                 "the keys are protected with each user's own password.")
            if password:
                accounts.check_new_password(password, form.get("confirm", ""))
        except ValueError as exc:
            flash(str(exc), "error")
            return _render_form(user, values=form)

        changes = []
        if role != user.role:
            changes.append(f"role {user.role_label} -> {ROLE_LABELS[role]}")
            user.role = role
            if not user.keyed:
                user.wrapped_key = None
            user.session_version += 1
        if disabled != user.disabled:
            changes.append("disabled" if disabled else "enabled")
            user.disabled = disabled
            user.session_version += 1
        if password:
            accounts.set_password(user, password, temporary=True)   # keyed roles need the vault unlocked
            changes.append("password reset")
        if changes:
            services.audit("user_update", f"{user.username}: {', '.join(changes)}")
            db.session.commit()
            flash(f"Updated {user.username}: {', '.join(changes)}.", "success")
        return redirect(url_for("main.settings", _anchor="users"))
    return _render_form(user, values={"role": user.role, "disabled": user.disabled})


@bp.post("/users/<int:id>/delete")
def delete(id):
    user = db.get_or_404(User, id)
    if user.id == current_user().id:
        flash("You cannot delete your own account.", "error")
    elif user.role == "admin" and not user.disabled and accounts.active_admins() <= 1:
        flash("Keep at least one active admin.", "error")
    else:
        services.audit("user_delete", user.username)
        db.session.delete(user)
        db.session.commit()
        flash(f"Deleted {user.username}. Their audit log entries are kept.", "success")
    return redirect(url_for("main.settings", _anchor="users"))
