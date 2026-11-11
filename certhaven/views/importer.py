from flask import Blueprint, flash, redirect, render_template, request, url_for

from .. import services
from ..crypto import bundle
from ..crypto import keys as keylib
from ..models import Certificate, db
from . import upload_or_text

bp = Blueprint("importer", __name__)


@bp.route("/import", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        try:
            data = upload_or_text()
            if not data:
                raise ValueError("Paste PEM data or choose a file.")
            found_keys, found_certs, found_csrs = bundle.parse(data, request.form.get("password") or None)
            if not (found_keys or found_certs or found_csrs):
                raise ValueError("No keys, certificates or CSRs were found.")
            name = request.form.get("name", "").strip() or None
            added = {"keys": 0, "certificates": 0, "CSRs": 0}
            skipped = 0
            offline_cas = {ca.id for ca in db.session.scalars(
                db.select(Certificate).filter(Certificate.is_ca, Certificate.key_id.is_(None)))}
            # Keys first so certificates attach to them as they are saved.
            for key in found_keys:
                _, created = services.save_key(key, name or keylib.describe(key))
                added["keys"] += created
                skipped += not created
            # A CA key brought back from offline storage: renew its CRL now, which is usually why.
            for ca in db.session.scalars(db.select(Certificate).filter(
                    Certificate.id.in_(offline_cas), Certificate.key_id.isnot(None))):
                if ca.status == "valid":
                    crl = services.regenerate_crl(ca)
                    flash(f"The key for {ca.name} is back online. Its CRL was re-signed and is valid until "
                          f"{crl.next_update:%Y-%m-%d}.", "success")
            for cert in found_certs:
                _, created = services.save_cert(cert, name if len(found_certs) == 1 else None)
                added["certificates"] += created
                skipped += not created
            for req in found_csrs:
                _, created = services.save_csr(req, name)
                added["CSRs"] += created
                skipped += not created
            summary = ", ".join(f"{n} {label}" for label, n in added.items() if n) or "nothing new"
            services.audit("import", summary)
            db.session.commit()
            flash(f"Imported {summary}." + (f" {skipped} item(s) were already present." if skipped else ""),
                  "success")
            return redirect(url_for(".index"))
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    return render_template("import.html")
