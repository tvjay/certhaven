from collections import defaultdict

from cryptography.hazmat.primitives import serialization
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for

from .. import services
from ..crypto import bundle
from ..crypto import certs as certlib
from ..crypto import crl as crllib
from ..crypto import keys as keylib
from ..models import Certificate, Key, Template, db, utcnow
from ..security import has_role, require_role
from . import download, safe_filename, subject_from_form, subject_values

bp = Blueprint("certs", __name__)


def _templates():
    return db.session.scalars(db.select(Template).order_by(Template.is_ca.desc(), Template.name)).all()


@bp.route("/cas")
def cas():
    # Every CA in one query and the issued counts in another; the tree is built in memory.
    all_cas = db.session.scalars(db.select(Certificate).filter(Certificate.is_ca).order_by(
        db.func.lower(Certificate.name), Certificate.not_after)).all()
    issued = dict(db.session.execute(db.select(Certificate.issuer_id, db.func.count()).filter(
        Certificate.issuer_id.isnot(None)).group_by(Certificate.issuer_id)).all())
    by_issuer = defaultdict(list)
    for ca in all_cas:
        by_issuer[ca.issuer_id].append(ca)
    # Depth-first so each CA appears directly under its issuer, indented by depth.
    rows, seen = [], set()

    def walk(ca, depth):
        if ca.id in seen:
            return
        seen.add(ca.id)
        rows.append((ca, depth))
        for child in by_issuer[ca.id]:
            walk(child, depth + 1)

    for root in by_issuer[None]:
        walk(root, 0)
    return render_template("cas.html", rows=rows, issued=issued)


@bp.route("/certs")
def index():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "")
    kind = request.args.get("kind", "")
    issuer = request.args.get("issuer", type=int)
    stmt = db.select(Certificate)
    if q:
        like = f"%{q}%"
        stmt = stmt.filter(db.or_(Certificate.name.ilike(like), Certificate.subject.ilike(like),
                                  Certificate.serial.ilike(like)))
    if kind == "ca":
        stmt = stmt.filter(Certificate.is_ca)
    elif kind == "ee":
        stmt = stmt.filter(~Certificate.is_ca)
    if issuer:
        stmt = stmt.filter(Certificate.issuer_id == issuer)
    if status:
        stmt = stmt.filter(Certificate.status_clause(status, utcnow()) if status in Certificate.STATUSES
                           else db.false())
    rows = db.session.scalars(stmt.order_by(db.func.lower(Certificate.name), Certificate.not_after)).all()
    return render_template("cert_list.html", rows=rows, q=q, status=status, kind=kind,
                           issuer=db.session.get(Certificate, issuer) if issuer else None)


def _usable_keys():
    """Keys that may back a new certificate: never a CA's key (key reuse)."""
    ca_keys = services.ca_key_ids()
    return [k for k in db.session.scalars(db.select(Key).order_by(Key.name)) if k.id not in ca_keys]


@bp.route("/certs/new", methods=["GET", "POST"])
def new():
    is_admin = has_role("admin")
    if request.method == "POST" and not is_admin:
        requested = db.session.get(Template, request.form.get("template", 0, type=int))
        if request.form.get("issuer", "") == "" or (requested is not None and requested.is_ca):
            abort(403)
    issuers = services.signing_cas()
    # Operators issue end-entity certificates only; CAs and self-signed roots need an admin.
    templates = [t for t in _templates() if is_admin or not t.is_ca]
    if not templates:
        flash("Create a template first.", "error")
        return redirect(url_for("templates.index"))
    if not is_admin and not issuers:
        flash("There is no CA to issue from yet. An admin needs to create one.", "error")
        return redirect(url_for("certs.cas"))

    if "issuer" in request.values and (is_admin or request.values.get("issuer")):
        issuer_value = request.values.get("issuer", "")
    else:
        issuer_value = str(issuers[0].id) if issuers else ""
    template = db.session.get(Template, request.values.get("template", 0, type=int))
    if template is not None and template not in templates:
        template = None
    if template is None:
        want_ca = issuer_value == ""
        preferred = "Root CA" if want_ca else "TLS Server"
        template = (next((t for t in templates if t.name == preferred), None)
                    or next((t for t in templates if t.is_ca == want_ca), templates[0]))

    if request.method == "POST":
        form = request.form
        try:
            subject = certlib.build_name(subject_from_form(form))
            sans = certlib.parse_sans(form.get("sans", ""))
            if len(subject) == 0 and not sans:
                raise ValueError("Enter a subject or at least one SAN.")
            days = int(form.get("days") or template.validity_days)
            issuer_row = None
            if issuer_value:
                issuer_row = db.session.get(Certificate, int(issuer_value))
                if issuer_row is None:
                    raise ValueError("Unknown issuer.")
            name = form.get("name", "").strip() or certlib.common_name(subject) or "Certificate"
            key_row, is_ca_key = services.key_from_form(form, name, template.key_algo)
            if is_ca_key:
                raise ValueError("That key belongs to a CA. Use a new key for this certificate.")
            row, warnings = services.issue_certificate(
                name=name, subject=subject, public_key=key_row.public_key(), key_row=key_row,
                issuer_row=issuer_row, profile=template.profile(), sans=sans, days=days)
            services.audit("issue", f"{row.name} serial {row.serial} by "
                           f"{issuer_row.name if issuer_row else 'self'} ({template.name})")
            db.session.commit()
            for w in warnings:
                flash(w, "warning")
            flash(f"Issued {row.name}.", "success")
            return redirect(url_for(".detail", id=row.id))
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
        values = form
    else:
        values = {"key": "new", "key_algo": template.key_algo, **subject_values(template.defaults)}

    return render_template("cert_new.html", issuers=issuers, templates=templates, template=template,
                           issuer_value=issuer_value, values=values, keys=_usable_keys(),
                           algorithms=keylib.ALGORITHMS, subject_fields=certlib.SUBJECT_FIELDS)


@bp.route("/certs/<int:id>")
def detail(id):
    row = db.get_or_404(Certificate, id)
    return render_template("cert_detail.html", row=row, info=certlib.details(row.x509),
                           chain=services.chain(row), reasons=crllib.REASON_LABELS,
                           crl_url=services.crl_url(row.id), aia_url=services.aia_url(row.id))


@bp.post("/certs/<int:id>/revoke")
def revoke(id):
    row = db.get_or_404(Certificate, id)
    if row.is_ca:
        require_role("admin")
    if row.revoked_at:
        flash("Already revoked.", "error")
        return redirect(url_for(".detail", id=id))
    try:
        reason = request.form.get("reason", "unspecified")
        services.revoke(row, reason)
        services.audit("revoke", f"{row.name} serial {row.serial} ({reason})")
        db.session.commit()
        msg = "Certificate revoked"
        if row.issuer and row.issuer.key:
            msg += f" and the CRL for {row.issuer.name} was re-signed"
        flash(msg + ".", "success")
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for(".detail", id=id))


@bp.post("/certs/<int:id>/renew")
def renew(id):
    row = db.get_or_404(Certificate, id)
    if row.is_ca:
        require_role("admin")
    try:
        new_row, warnings = services.renew(row)
        services.audit("renew", f"{row.name} serial {row.serial} -> {new_row.serial}")
        db.session.commit()
        for w in warnings:
            flash(w, "warning")
        flash("Renewed with the same key. The old certificate is unchanged; revoke it as superseded "
              "once the new one is deployed.", "success")
        return redirect(url_for(".detail", id=new_row.id))
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for(".detail", id=id))


@bp.post("/certs/<int:id>/delete")
def delete(id):
    row = db.get_or_404(Certificate, id)
    try:
        name, serial = row.name, row.serial
        services.delete_cert(row)
        services.audit("delete_cert", f"{name} serial {serial}")
        db.session.commit()
        flash(f"Deleted {name}. Its private key, if any, is still under Keys.", "success")
        return redirect(url_for(".index"))
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for(".detail", id=id))


@bp.route("/certs/<int:id>/download/<fmt>")
def download_cert(id, fmt):
    row = db.get_or_404(Certificate, id)
    base = safe_filename(row.name, f"cert-{row.id}")
    if fmt == "pem":
        return download(row.pem, f"{base}.pem", "application/x-pem-file")
    if fmt == "der":
        return download(row.x509.public_bytes(serialization.Encoding.DER), f"{base}.der",
                        "application/pkix-cert")
    if fmt == "chain":
        pems = [row.pem] + [c.pem for c in services.chain(row)]
        return download("".join(pems), f"{base}-fullchain.pem", "application/x-pem-file")
    abort(404)


@bp.route("/certs/<int:id>/pkcs12", methods=["GET", "POST"])
def pkcs12(id):
    row = db.get_or_404(Certificate, id)
    if row.key is None:
        flash("The private key for this certificate is not in the database.", "error")
        return redirect(url_for(".detail", id=id))
    if request.method == "POST":
        password = request.form.get("password", "")
        if password != request.form.get("confirm", ""):
            flash("The passwords do not match.", "error")
        elif not password and not request.form.get("unencrypted"):
            flash("Enter a password, or tick “Export without a password” to download the file unprotected.",
                  "error")
        else:
            chain = [c.x509 for c in services.chain(row)] if request.form.get("chain") else []
            data = bundle.pkcs12_bytes(row.name, services.load_private_key(row.key), row.x509, chain,
                                       password or None)
            services.audit("export_pkcs12", f"{row.name} serial {row.serial} "
                           f"({'encrypted' if password else 'unencrypted'})")
            db.session.commit()
            return download(data, f"{safe_filename(row.name, f'cert-{row.id}')}.p12",
                            "application/x-pkcs12")
    return render_template("pkcs12.html", row=row)


@bp.post("/certs/<int:id>/crl")
def regenerate_crl(id):
    row = db.get_or_404(Certificate, id)
    if not row.is_ca:
        abort(404)
    try:
        crl = services.regenerate_crl(row)
        services.audit("crl_regenerate", f"{row.name} CRL #{crl.number}")
        db.session.commit()
        flash(f"CRL #{crl.number} signed.", "success")
    except ValueError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for(".detail", id=id))


@bp.route("/certs/<int:id>/crl.pem")
def download_crl(id):
    row = db.get_or_404(Certificate, id)
    if not row.latest_crl:
        abort(404)
    return download(row.latest_crl.pem, f"{safe_filename(row.name, f'ca-{row.id}')}.crl.pem",
                    "application/x-pem-file")
