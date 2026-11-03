import os
from datetime import timedelta

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for

from .. import __version__, accounts, backups, build_date, notify, services
from ..models import (CSR, ROLE_DESCRIPTIONS, TIME_DISPLAYS, AuditLog, Certificate, Key, User, db, get_setting,
                      set_setting, utcnow)
from ..security import current_user
from . import download

bp = Blueprint("main", __name__)


@bp.route("/")
def dashboard():
    now = utcnow()
    # The same rules as Certificate.status, as SQL, so the counts need no rows loaded.
    revoked = Certificate.revoked_at.isnot(None)
    valid = ~revoked & (Certificate.not_before <= now) & (Certificate.not_after >= now)
    expired = ~revoked & (Certificate.not_after < now)
    count = db.func.count(Certificate.id)
    cas, certs, n_valid, n_revoked, n_expired = db.session.execute(db.select(
        count.filter(Certificate.is_ca), count.filter(~Certificate.is_ca), count.filter(valid),
        count.filter(revoked), count.filter(expired))).one()
    expiring = db.session.scalars(db.select(Certificate).filter(
        valid, Certificate.not_after < now + timedelta(days=30)).order_by(Certificate.not_after)).all()
    crls_due = [ca for ca in services.signing_cas(with_crls=True) if services.crl_due(ca, now)]
    counts = {
        "cas": cas, "certs": certs, "valid": n_valid, "revoked": n_revoked, "expired": n_expired,
        "private_keys": db.session.scalar(db.select(db.func.count(Key.id))),
        "csrs": db.session.scalar(db.select(db.func.count(CSR.id)).filter(CSR.cert_id.is_(None))),
    }
    recent = db.session.scalars(db.select(AuditLog).order_by(AuditLog.id.desc()).limit(10)).all()
    return render_template("dashboard.html", counts=counts, expiring=expiring, crls_due=crls_due,
                           recent=recent, base_url=get_setting("base_url", ""))


@bp.route("/audit")
def audit():
    page = max(1, request.args.get("page", 1, type=int))
    rows = db.paginate(db.select(AuditLog).order_by(AuditLog.id.desc()), page=page, per_page=100,
                       error_out=False)
    return render_template("audit.html", rows=rows)


@bp.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        base_url = request.form.get("base_url", "").strip().rstrip("/")
        time_display = request.form.get("time_display", "utc")
        try:
            idle = int(request.form.get("idle_timeout", "30"))
            crl_days = int(request.form.get("crl_days", "30"))
        except ValueError:
            idle = crl_days = -1
        if base_url and not base_url.startswith(("http://", "https://")):
            flash("The public base URL must start with http:// or https://.", "error")
        elif not 5 <= idle <= 1440:
            flash("Idle timeout must be between 5 and 1440 minutes.", "error")
        elif not 8 <= crl_days <= 365:
            flash("CRL validity must be between 8 and 365 days.", "error")
        elif time_display not in TIME_DISPLAYS:
            flash("Choose how times are shown.", "error")
        else:
            set_setting("base_url", base_url)
            set_setting("idle_timeout", str(idle))
            set_setting("crl_days", str(crl_days))
            set_setting("time_display", time_display)
            services.audit("settings", f"base_url={base_url} idle={idle} crl_days={crl_days} "
                                       f"times={time_display}")
            db.session.commit()
            flash("Settings saved.", "success")
            return redirect(url_for(".settings"))
    return render_template("settings.html", base_url=get_setting("base_url", ""),
                           idle_timeout=get_setting("idle_timeout", "30"),
                           crl_days=get_setting("crl_days", "30"), notify=notify.summary(),
                           time_display=get_setting("time_display", "utc"), time_displays=TIME_DISPLAYS,
                           users=db.session.scalars(db.select(User).order_by(User.username)).all(),
                           role_descriptions=ROLE_DESCRIPTIONS,
                           version=__version__, build_date=build_date())


@bp.post("/settings/notify")
def notify_save():
    form = request.form
    values = {key: form.get(key.lower(), "") for key in notify.FIELDS if key != "SMTP_PASSWORD"}
    # The password field is write-only: blank keeps the stored one.
    if form.get("smtp_password"):
        values["SMTP_PASSWORD"] = form["smtp_password"]
    elif form.get("clear_password"):
        values["SMTP_PASSWORD"] = ""
    else:
        values["SMTP_PASSWORD"] = notify.read_config().get("SMTP_PASSWORD", "")
    try:
        clean = notify.save_config(values)
    except ValueError as exc:
        flash(f"Email settings not saved: {exc}", "error")
        return redirect(url_for(".settings") + "#email")
    detail = (f"server={clean['SMTP_HOST']}:{clean['SMTP_PORT'] or 'default'} to={clean['MAIL_TO']}"
              if clean["SMTP_HOST"] else "alerts turned off")
    services.audit("notify_settings", detail)
    db.session.commit()
    flash("Email settings saved." + (" Send a test email to check them." if clean["SMTP_HOST"]
                                     else " Email alerts are off."), "success")
    return redirect(url_for(".settings") + "#email")


@bp.post("/settings/notify-test")
def notify_test():
    try:
        to = notify.send_test()
        services.audit("notify_test", ", ".join(to))
        db.session.commit()
        flash(f"Test email sent to {', '.join(to)}.", "success")
    except ValueError as exc:   # not configured
        flash(f"Test email failed: {exc}", "error")
    except Exception as exc:  # SMTP/network failure: a short reason here, details in the server log
        flash(f"Test email failed: {notify.describe_error(exc)}.", "error")
    return redirect(url_for(".settings") + "#email")


@bp.post("/settings/notify-run")
def notify_run():
    status = notify.run()
    category = "error" if status["result"].startswith("error") or status["result"] == "not configured" else "success"
    flash(f"Checks ran: {status['alerts']} new alert(s), {status['result']}.", category)
    return redirect(url_for(".settings") + "#email")


@bp.post("/settings/regenerate-crls")
def regenerate_crls():
    count = 0
    for ca in services.signing_cas():
        services.regenerate_crl(ca)
        count += 1
    services.audit("crl_regenerate_all", f"{count} CRL(s)")
    db.session.commit()
    flash(f"Re-signed {count} CRL(s).", "success")
    return redirect(request.referrer or url_for(".dashboard"))


@bp.route("/settings/backup")
def backup():
    data = backups.serialize(current_app.config["DB_PATH"])
    services.audit("backup")
    db.session.commit()
    return download(data, f"certhaven-backup-{utcnow():%Y%m%d-%H%M}.db", "application/vnd.sqlite3")


@bp.post("/settings/restore")
def restore():
    upload = request.files.get("backup")
    filename = os.path.basename(upload.filename) if upload and upload.filename else ""
    username = current_user().username
    try:
        ok, _ = accounts.checked_verify(current_user(), request.form.get("password", ""),
                                        request.remote_addr or "?")
        if not ok:
            raise ValueError("Your password is incorrect.")
        if not filename:
            raise ValueError("Choose a backup file.")
        saved = backups.restore(upload.read())
    except (ValueError, accounts.CheckRefused) as exc:
        db.session.rollback()
        flash(f"Nothing was restored: {exc}", "error")
        return redirect(url_for(".settings") + "#backup")
    # Recorded in the restored database; the user who did it may not exist there.
    db.session.add(AuditLog(action="restore", username=username, ip=request.remote_addr,
                            detail=f"{filename}; the previous database was saved as {os.path.basename(saved)}"))
    db.session.commit()
    session.clear()
    flash("Backup restored. Everyone was logged out: log in with an account from the backup. "
          f"The previous database was saved on the server as {os.path.basename(saved)}.", "success")
    return redirect(url_for("auth.login"))
