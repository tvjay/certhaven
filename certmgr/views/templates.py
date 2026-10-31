import json

from flask import Blueprint, flash, redirect, render_template, request, url_for

from .. import services
from ..crypto import certs as certlib
from ..crypto import keys as keylib
from ..models import Template, db
from . import subject_from_form, subject_values

bp = Blueprint("templates", __name__)


@bp.route("/templates")
def index():
    rows = db.session.scalars(db.select(Template).order_by(Template.is_ca.desc(), Template.name)).all()
    return render_template("template_list.html", rows=rows, algorithms=keylib.ALGORITHMS)


def _apply(row, form):
    name = form.get("name", "").strip()
    if not name:
        raise ValueError("Enter a name.")
    clash = db.session.scalar(db.select(Template).filter_by(name=name))
    if clash and clash is not row:
        raise ValueError("A template with that name already exists.")
    algo = form.get("key_algo", "ec256")
    if algo not in keylib.ALGORITHMS:
        raise ValueError("Unknown key algorithm.")
    try:
        days = int(form.get("validity_days", ""))
        path_length = int(form["path_length"]) if form.get("path_length", "").strip() else None
    except ValueError:
        raise ValueError("Validity and path length must be whole numbers.")
    if days < 1 or (path_length is not None and path_length < 0):
        raise ValueError("Validity must be positive and path length zero or more.")
    defaults = subject_from_form(form)
    certlib.build_name(defaults)  # validates
    row.name = name
    row.is_ca = bool(form.get("is_ca"))
    row.path_length = path_length if row.is_ca else None
    known_ku = {n for n, _, _ in certlib.KEY_USAGES}
    known_eku = {n for n, _, _ in certlib.EXT_KEY_USAGES}
    row.key_usage = ",".join(u for u in form.getlist("key_usage") if u in known_ku)
    row.ext_key_usage = ",".join(u for u in form.getlist("ext_key_usage") if u in known_eku)
    row.validity_days = days
    row.key_algo = algo
    row.subject_defaults = json.dumps({k: v for k, v in defaults.items() if v})


@bp.route("/templates/new", methods=["GET", "POST"])
@bp.route("/templates/<int:id>/edit", methods=["GET", "POST"])
def edit(id=None):
    row = db.get_or_404(Template, id) if id else None
    if request.method == "POST":
        target = row or Template()
        try:
            _apply(target, request.form)
            if row is None:
                db.session.add(target)
            services.audit("template_save", target.name)
            db.session.commit()
            flash(f"Saved template {target.name}.", "success")
            return redirect(url_for(".index"))
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "error")
        form = request.form
        values = {k: form.get(k) for k in form}
        values["key_usage"] = form.getlist("key_usage")
        values["ext_key_usage"] = form.getlist("ext_key_usage")
    elif row:
        values = {"name": row.name, "is_ca": row.is_ca, "path_length": row.path_length,
                  "key_usage": row.key_usage_list, "ext_key_usage": row.eku_list,
                  "validity_days": row.validity_days, "key_algo": row.key_algo,
                  **subject_values(row.defaults)}
    else:
        values = {"key_usage": ["digitalSignature"], "ext_key_usage": ["serverAuth"],
                  "validity_days": 397, "key_algo": "ec256"}
    return render_template("template_form.html", row=row, values=values,
                           key_usages=certlib.KEY_USAGES, ext_key_usages=certlib.EXT_KEY_USAGES,
                           algorithms=keylib.ALGORITHMS, subject_fields=certlib.SUBJECT_FIELDS)


@bp.post("/templates/<int:id>/delete")
def delete(id):
    row = db.get_or_404(Template, id)
    services.audit("template_delete", row.name)
    db.session.delete(row)
    db.session.commit()
    flash("Template deleted.", "success")
    return redirect(url_for(".index"))
