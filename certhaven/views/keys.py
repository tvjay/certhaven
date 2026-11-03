from flask import Blueprint, flash, redirect, render_template, request, url_for
from sqlalchemy.orm import selectinload

from .. import services
from ..crypto import keys as keylib
from ..models import Key, db
from . import download, safe_filename

bp = Blueprint("keys", __name__)


@bp.route("/keys")
def index():
    q = request.args.get("q", "").strip()
    algo = request.args.get("algo", "")
    usage = request.args.get("usage", "")
    # Load what uses each key in two queries, not two per key.
    stmt = db.select(Key).options(selectinload(Key.certificates), selectinload(Key.csrs))
    if q:
        like = f"%{q}%"
        stmt = stmt.filter(db.or_(Key.name.ilike(like), Key.fingerprint.ilike(like.replace(":", ""))))
    if algo:
        stmt = stmt.filter(Key.algo == algo)
    rows = db.session.scalars(stmt.order_by(db.func.lower(Key.name))).all()
    if usage == "used":
        rows = [k for k in rows if k.certificates or k.csrs]
    elif usage == "unused":
        rows = [k for k in rows if not k.certificates and not k.csrs]
    key_types = db.session.scalars(db.select(Key.algo).distinct().order_by(Key.algo)).all()
    return render_template("key_list.html", rows=rows, algorithms=keylib.ALGORITHMS, q=q, algo=algo,
                           usage=usage, key_types=key_types, filtered=bool(q or algo or usage))


@bp.post("/keys/new")
def new():
    algo = request.form.get("algo", "ec256")
    if algo not in keylib.ALGORITHMS:
        flash("Unknown key algorithm.", "error")
        return redirect(url_for(".index"))
    name = request.form.get("name", "").strip() or keylib.ALGORITHMS[algo]
    row, _ = services.save_key(keylib.generate(algo), name)
    services.audit("create_key", f"{row.name} ({row.algo})")
    db.session.commit()
    flash(f"Generated {row.algo} key {row.name}.", "success")
    return redirect(url_for(".index"))


@bp.post("/keys/<int:id>/export")
def export(id):
    row = db.get_or_404(Key, id)
    password = request.form.get("password", "")
    if password != request.form.get("confirm", ""):
        flash("The passwords do not match.", "error")
        return redirect(url_for(".index"))
    if not password and not request.form.get("unencrypted"):
        flash("Enter a password, or tick “Export without a password” to download the key unprotected.", "error")
        return redirect(url_for(".index") + f"#key-{row.id}")
    pem = keylib.to_pem(services.load_private_key(row), password or None)
    services.audit("export_key", f"{row.name} ({'encrypted' if password else 'unencrypted'})")
    db.session.commit()
    return download(pem, f"{safe_filename(row.name, f'key-{row.id}')}.key", "application/x-pem-file")


@bp.route("/keys/<int:id>/public.pem")
def public(id):
    row = db.get_or_404(Key, id)
    return download(row.public_pem, f"{safe_filename(row.name, f'key-{row.id}')}.pub.pem",
                    "application/x-pem-file")


@bp.post("/keys/<int:id>/rename")
def rename(id):
    row = db.get_or_404(Key, id)
    name = request.form.get("name", "").strip()
    if name:
        row.name = name[:200]
        db.session.commit()
    return redirect(url_for(".index"))


@bp.post("/keys/<int:id>/delete")
def delete(id):
    row = db.get_or_404(Key, id)
    if row.certificates or row.csrs:
        flash("This key is used by certificates or CSRs; delete those first.", "error")
        return redirect(url_for(".index"))
    services.audit("delete_key", f"{row.name} ({row.algo}) {row.fingerprint}")
    db.session.delete(row)
    db.session.commit()
    flash("Key deleted.", "success")
    return redirect(url_for(".index"))
