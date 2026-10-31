"""Unauthenticated endpoints referenced from issued certificates (CDP and AIA).
They serve stored, already-signed data, so they work while the vault is locked."""
from cryptography.hazmat.primitives import serialization
from flask import Blueprint, Response, abort

from ..models import Certificate, db

bp = Blueprint("public", __name__)


@bp.route("/crl/<int:ca_id>.crl")
def crl(ca_id):
    ca = db.session.get(Certificate, ca_id)
    if ca is None or not ca.is_ca or ca.latest_crl is None:
        abort(404)
    der = ca.latest_crl.x509.public_bytes(serialization.Encoding.DER)
    resp = Response(der, mimetype="application/pkix-crl")
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp


@bp.route("/ca/<int:ca_id>.crt")
def ca_cert(ca_id):
    ca = db.session.get(Certificate, ca_id)
    if ca is None or not ca.is_ca:
        abort(404)
    resp = Response(ca.x509.public_bytes(serialization.Encoding.DER), mimetype="application/pkix-cert")
    resp.headers["Cache-Control"] = "public, max-age=86400"
    return resp
