import re

from flask import Response, request

from ..crypto.certs import SUBJECT_KEYS


def subject_from_form(form):
    return {k: form.get(f"subj_{k}", "").strip() for k in SUBJECT_KEYS}


def subject_values(values):
    return {f"subj_{k}": v for k, v in values.items()}


def upload_or_text(file_field="file", text_field="text"):
    upload = request.files.get(file_field)
    if upload and upload.filename:
        return upload.read()
    return request.form.get(text_field, "").strip().encode()


def safe_filename(name, fallback):
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name or "").strip("._")
    return cleaned[:80] or fallback


def download(data, filename, mimetype):
    resp = Response(data, mimetype=mimetype)
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp
