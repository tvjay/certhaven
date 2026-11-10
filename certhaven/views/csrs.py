from flask import Blueprint, flash, redirect, render_template, request, url_for
from sqlalchemy.orm import selectinload

from .. import services
from ..crypto import certs as certlib
from ..crypto import csr as csrlib
from ..crypto import keys as keylib
from ..models import CSR, Certificate, Key, Template, db
from ..security import has_role, require_role
from . import download, safe_filename, subject_from_form, upload_or_text

bp = Blueprint("csrs", __name__)


@bp.route("/csrs")
def index():
    rows = db.session.scalars(db.select(CSR).options(selectinload(CSR.cert))
                              .order_by(CSR.created_at.desc())).all()
    return render_template("csr_list.html", rows=rows)


@bp.post("/csrs/import")
def import_csr():
    try:
        data = upload_or_text()
        if not data:
            raise ValueError("Paste a CSR or choose a file.")
        req = csrlib.load(data)
        row, created = services.save_csr(req, request.form.get("name", "").strip() or None)
        if created:
            services.audit("import_csr", row.subject)
        db.session.commit()
        if not created:
            flash("That CSR is already in the database.", "warning")
        return redirect(url_for(".detail", id=row.id))
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for(".index"))


@bp.route("/csrs/new", methods=["GET", "POST"])
def new():
    values = request.form if request.method == "POST" else {"key": "new", "key_algo": "ec256"}
    if request.method == "POST":
        try:
            subject = certlib.build_name(subject_from_form(request.form))
            sans = certlib.parse_sans(request.form.get("sans", ""))
            if len(subject) == 0 and not sans:
                raise ValueError("Enter a subject or at least one SAN.")
            name = request.form.get("name", "").strip() or certlib.common_name(subject) or "CSR"
            key_row, is_ca_key = services.key_from_form(request.form, name, "ec256")
            if is_ca_key:
                require_role("admin")   # a CSR for a CA key re-certifies the CA
            row = services.create_csr(name, subject, sans, key_row)
            services.audit("create_csr", row.subject)
            db.session.commit()
            flash("CSR created.", "success")
            return redirect(url_for(".detail", id=row.id))
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
    ca_keys = set() if has_role("admin") else services.ca_key_ids()
    keys = [k for k in db.session.scalars(db.select(Key).order_by(Key.name)) if k.id not in ca_keys]
    return render_template("csr_new.html", values=values, subject_fields=certlib.SUBJECT_FIELDS,
                           algorithms=keylib.ALGORITHMS, keys=keys)


@bp.route("/csrs/<int:id>")
def detail(id):
    row = db.get_or_404(CSR, id)
    req = row.x509
    templates = [t for t in db.session.scalars(db.select(Template).order_by(Template.is_ca, Template.name))
                 if has_role("admin") or not t.is_ca]
    return render_template(
        "csr_detail.html", row=row, req=req, valid=req.is_signature_valid,
        public_key=keylib.describe(req.public_key()),
        sans_text=certlib.sans_to_text(certlib.get_sans(req)),
        issuers=services.signing_cas(), templates=templates)


@bp.post("/csrs/<int:id>/sign")
def sign(id):
    row = db.get_or_404(CSR, id)
    req = row.x509
    try:
        if not req.is_signature_valid:
            raise ValueError("The CSR signature is invalid.")
        issuer_row = db.session.get(Certificate, request.form.get("issuer", 0, type=int))
        if issuer_row is None:
            raise ValueError("Choose an issuing CA.")
        template = db.session.get(Template, request.form.get("template", 0, type=int))
        if template is None:
            raise ValueError("Choose a template.")
        if template.is_ca:
            require_role("admin")   # signing a CSR into a CA certificate creates a new CA
        sans = certlib.parse_sans(request.form.get("sans", ""))
        if len(req.subject) == 0 and not sans:
            raise ValueError("The CSR has no subject; add at least one SAN.")
        days = int(request.form.get("days") or template.validity_days)
        name = request.form.get("name", "").strip() or row.name
        cert_row, warnings = services.issue_certificate(
            name=name, subject=req.subject, public_key=req.public_key(),
            key_row=row.key or services.key_for_public(req.public_key()), issuer_row=issuer_row,
            profile=template.profile(), sans=sans, days=days)
        row.cert = cert_row
        services.audit("sign_csr", f"{row.subject} -> serial {cert_row.serial} by {issuer_row.name} "
                       f"({template.name})")
        db.session.commit()
        for w in warnings:
            flash(w, "warning")
        flash("CSR signed.", "success")
        return redirect(url_for("certs.detail", id=cert_row.id))
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for(".detail", id=id))


@bp.route("/csrs/<int:id>/download")
def download_csr(id):
    row = db.get_or_404(CSR, id)
    return download(row.pem, f"{safe_filename(row.name, f'csr-{row.id}')}.csr", "application/pkcs10")


@bp.post("/csrs/<int:id>/delete")
def delete(id):
    row = db.get_or_404(CSR, id)
    services.audit("delete_csr", row.subject)
    db.session.delete(row)
    db.session.commit()
    flash("CSR deleted.", "success")
    return redirect(url_for(".index"))
