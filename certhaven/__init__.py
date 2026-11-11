import os
import secrets
from datetime import datetime

from flask import Flask
from markupsafe import Markup
from werkzeug.middleware.proxy_fix import ProxyFix

from .models import db, upgrade_schema

__version__ = "0.11.3"

# Where users of this instance can get its source code, linked from every page. certhaven is licensed under
# the AGPL: if you run a modified version for others, point this at the source of your version.
SOURCE_URL = "https://github.com/tvjay/certhaven"
LICENSE_NAME = "AGPL-3.0-or-later"


def build_date():
    """When the installed package was built (naive UTC), or None when running from a source checkout.
    packaging/build-deb.sh writes the BUILD_DATE file."""
    try:
        with open(os.path.join(os.path.dirname(__file__), "BUILD_DATE")) as f:
            return datetime.strptime(f.read().strip(), "%Y-%m-%dT%H:%M:%SZ")
    except (OSError, ValueError):
        return None


def _secret_key(data_dir):
    path = os.path.join(data_dir, "secret_key")
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


def create_app(config=None):
    app = Flask(__name__)
    config = config or {}
    data_dir = config.get("DATA_DIR") or os.environ.get("CERTHAVEN_DATA_DIR") or app.instance_path
    os.makedirs(data_dir, exist_ok=True)

    app.config.update(
        DATA_DIR=data_dir,
        DB_PATH=os.path.join(data_dir, "certhaven.db"),
        SECRET_KEY=_secret_key(data_dir),
        SESSION_COOKIE_NAME="certhaven_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Set CERTHAVEN_INSECURE_COOKIES=1 only for local development over plain http.
        SESSION_COOKIE_SECURE=os.environ.get("CERTHAVEN_INSECURE_COOKIES") != "1",
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        NOTIFY_CONF=os.environ.get("CERTHAVEN_NOTIFY_CONF", os.path.join(data_dir, "notify.conf")),
    )
    app.config.update(config)
    app.config.setdefault("SQLALCHEMY_DATABASE_URI", "sqlite:///" + app.config["DB_PATH"])

    # gunicorn listens on 127.0.0.1 behind nginx, which overwrites X-Forwarded-For/-Proto.
    # X-Forwarded-Host is not trusted: nginx passes it through from clients unchanged.
    if os.environ.get("CERTHAVEN_BEHIND_PROXY", "1") == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    db.init_app(app)
    with app.app_context():
        db.create_all()
        # The web service upgrades the schema when it starts. The alert job, which starts a fresh app
        # every 15 minutes, sets CERTHAVEN_MIGRATE=0 to skip repeating that.
        if os.environ.get("CERTHAVEN_MIGRATE", "1") != "0":
            upgrade_schema()

    from . import notify, security
    from .views import account, auth, certs, csrs, importer, keys, main, public, templates, users

    security.init_app(app)
    notify.register_cli(app)
    for module in (auth, account, users, main, certs, csrs, keys, templates, importer, public):
        app.register_blueprint(module.bp)
    app.jinja_env.globals.update(source_url=SOURCE_URL, license_name=LICENSE_NAME)

    # Times are stored and rendered in UTC. The <time> element carries the exact instant, so
    # app.js can rewrite it in the browser's time zone for users who chose local time.
    @app.template_filter("dt")
    def format_dt(value):
        return _time_tag(value, "datetime", "%Y-%m-%d %H:%M UTC")

    @app.template_filter("d")
    def format_date(value):
        return _time_tag(value, "date", "%Y-%m-%d")

    return app


def _time_tag(value, kind, fmt):
    if not value:
        return ""
    if isinstance(value, str):   # ISO text, e.g. stored status timestamps
        value = datetime.fromisoformat(value)
    return Markup('<time datetime="%s" data-kind="%s">%s</time>') % (
        value.strftime("%Y-%m-%dT%H:%M:%SZ"), kind, value.strftime(fmt))
