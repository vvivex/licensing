import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from typing import Any, ContextManager, Generator

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix


KEY_PATTERN = re.compile(r"VZ(?:-[A-F0-9]{4}){8}\Z")
DEVICE_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
KEY_HASH_SECRET_MIN_LENGTH = 32
SESSION_SECRET_MIN_LENGTH = 32
ADMIN_PASSWORD_MIN_LENGTH = 16

LOGIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport"
content="width=device-width, initial-scale=1"><title>Vulonz Key Dashboard</title>
<style>{{ styles }}</style></head><body><main class="card narrow">
<h1>Vulonz Key Dashboard</h1><p>Administrator sign in</p>
{% for message in get_flashed_messages() %}<p class="notice">{{ message }}</p>{% endfor %}
<form method="post" action="{{ url_for('admin_login') }}">
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">
<label for="password">Admin password</label>
<input id="password" name="password" type="password" required autofocus
autocomplete="current-password">
<button type="submit">Sign in</button></form></main></body></html>"""

DASHBOARD_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport"
content="width=device-width, initial-scale=1"><title>Vulonz Key Dashboard</title>
<style>{{ styles }}</style></head><body><main class="card">
<header><div><h1>Vulonz Key Dashboard</h1><p>Manage lifetime licenses</p></div>
<form method="post" action="{{ url_for('admin_logout') }}">
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">
<button class="secondary" type="submit">Sign out</button></form></header>
{% for message in get_flashed_messages() %}<p class="notice">{{ message }}</p>{% endfor %}
{% if new_key %}<section class="new-key"><h2>Copy this key now</h2>
<p>It will not be shown again.</p><code>{{ new_key }}</code></section>{% endif %}
<section><h2>Create a lifetime key</h2>
<form method="post" action="{{ url_for('create_key') }}">
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">
<button type="submit">Create key</button></form></section>
<section><h2>Keys</h2>
{% if licenses %}<div class="table-wrap"><table><thead><tr>
<th>Key</th><th>Status</th><th>Created</th><th>Device</th><th>Actions</th>
</tr></thead><tbody>{% for item in licenses %}<tr>
<td><code>{{ item["masked_key"] }}</code></td><td>{{ item["status"] }}</td>
<td>{{ item["created_at"] }}</td><td>{{ "Bound" if item["device_id"] else "Unbound" }}</td>
<td>{% if item["status"] == "active" %}
<form class="inline" method="post" action="{{ url_for('reset_device', license_id=item['id']) }}">
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">
<button class="secondary" type="submit">Reset device</button></form>
<form class="inline" method="post" action="{{ url_for('revoke_key', license_id=item['id']) }}">
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">
<button class="danger" type="submit">Revoke</button></form>
{% endif %}</td></tr>{% endfor %}</tbody></table></div>
{% else %}<p>No keys created yet.</p>{% endif %}</section>
</main></body></html>"""

STYLES = """
:root{color-scheme:dark;font:15px system-ui,sans-serif;background:#071018;color:#eef6fa}
*{box-sizing:border-box}body{margin:0;padding:40px 18px}.card{max-width:1100px;
margin:0 auto;padding:30px;background:#0d1922;border:1px solid #263846;border-radius:14px}
.narrow{max-width:420px}header{display:flex;justify-content:space-between;align-items:center;
gap:20px}h1{font-size:25px;margin:0}h2{font-size:17px;margin:0 0 14px}p{color:#9eafba}
section{margin-top:28px;padding-top:22px;border-top:1px solid #263846}
label{display:block;margin:20px 0 8px}input{width:100%;padding:12px;border-radius:8px;
border:1px solid #364b59;background:#071018;color:#eef6fa}button{padding:10px 15px;
border:0;border-radius:7px;background:#12aebf;color:#041114;font-weight:700;cursor:pointer}
form>button{margin-top:14px}.secondary{background:#263846;color:#eef6fa}
.danger{background:#692f38;color:#fff}.notice{padding:12px;background:#142b36;border-radius:7px}
.new-key{padding:16px;background:#122d33;border:1px solid #16808a;border-radius:9px}
.new-key code{display:block;word-break:break-all;color:#9ff3fa;font-size:18px}
.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;text-align:left}
th,td{padding:12px 10px;border-bottom:1px solid #263846;white-space:nowrap}
td form.inline{display:inline-block;margin:2px}td button{font-size:12px;padding:8px}
"""


def _license_key_hash(key: str, secret: str) -> str:
    canonical = key[3:].replace("-", "")
    return hmac.new(secret.encode("utf-8"), canonical.encode("ascii"), hashlib.sha256).hexdigest()


def _canonicalize_key(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    key = value.strip().upper()
    if not KEY_PATTERN.fullmatch(key):
        return None
    return key


@contextmanager
def _database_connection(path: str) -> Generator[sqlite3.Connection, None, None]:
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 10000")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def _initialize_database(path: str) -> None:
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    with _database_connection(path) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY,
                key_hash TEXT NOT NULL UNIQUE,
                masked_key TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
                created_at INTEGER NOT NULL,
                device_id TEXT,
                device_token_hash TEXT,
                activated_at INTEGER,
                revoked_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS request_limits (
                scope TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                window_started INTEGER NOT NULL,
                attempts INTEGER NOT NULL,
                PRIMARY KEY (scope, ip_address)
            );
            """
        )
        license_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(licenses)")
        }
        if "device_token_hash" not in license_columns:
            connection.execute("ALTER TABLE licenses ADD COLUMN device_token_hash TEXT")


def _rate_limit(
    connection: sqlite3.Connection,
    scope: str,
    ip_address: str,
    limit: int,
    window_seconds: int,
) -> bool:
    now = int(time.time())
    if not connection.in_transaction:
        connection.execute("BEGIN IMMEDIATE")
    row = connection.execute(
        "SELECT window_started, attempts FROM request_limits "
        "WHERE scope = ? AND ip_address = ?",
        (scope, ip_address),
    ).fetchone()
    if row is None or now - row["window_started"] >= window_seconds:
        connection.execute(
            "INSERT INTO request_limits (scope, ip_address, window_started, attempts) "
            "VALUES (?, ?, ?, 1) ON CONFLICT(scope, ip_address) DO UPDATE SET "
            "window_started = excluded.window_started, attempts = 1",
            (scope, ip_address, now),
        )
        return True
    if row["attempts"] >= limit:
        return False
    connection.execute(
        "UPDATE request_limits SET attempts = attempts + 1 "
        "WHERE scope = ? AND ip_address = ?",
        (scope, ip_address),
    )
    return True


def create_app(config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("APP_SECRET_KEY", ""),
        ADMIN_PASSWORD=os.environ.get("ADMIN_PASSWORD", ""),
        KEY_HASH_SECRET=os.environ.get("KEY_HASH_SECRET", ""),
        DATABASE_PATH=os.environ.get("DATABASE_PATH", "/var/data/licenses.sqlite3"),
        TRUST_RENDER_PROXY=os.environ.get("TRUST_RENDER_PROXY", "true").lower() == "true",
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if config:
        app.config.update(config)
    if len(app.config["SECRET_KEY"]) < SESSION_SECRET_MIN_LENGTH:
        raise RuntimeError("APP_SECRET_KEY must contain at least 32 characters.")
    if len(app.config["KEY_HASH_SECRET"]) < KEY_HASH_SECRET_MIN_LENGTH:
        raise RuntimeError("KEY_HASH_SECRET must contain at least 32 characters.")
    if len(app.config["ADMIN_PASSWORD"]) < ADMIN_PASSWORD_MIN_LENGTH:
        raise RuntimeError("ADMIN_PASSWORD must contain at least 16 characters.")
    _initialize_database(app.config["DATABASE_PATH"])
    if app.config["TRUST_RENDER_PROXY"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0)

    def database() -> ContextManager[sqlite3.Connection]:
        return _database_connection(app.config["DATABASE_PATH"])

    def csrf_token() -> str:
        token = session.get("csrf_token")
        if not isinstance(token, str):
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    def validate_csrf() -> None:
        submitted = request.form.get("csrf_token", "")
        stored = session.get("csrf_token", "")
        if not isinstance(stored, str) or not hmac.compare_digest(submitted, stored):
            abort(400, "Invalid form token.")
        session["csrf_token"] = secrets.token_urlsafe(32)

    def administrator_required(function: Any) -> Any:
        @wraps(function)
        def decorated(*args: Any, **kwargs: Any) -> Any:
            if session.get("administrator") is not True:
                return redirect(url_for("admin_login"))
            return function(*args, **kwargs)

        return decorated

    def dashboard(new_key: str | None = None) -> str:
        with database() as connection:
            licenses = connection.execute(
                "SELECT id, masked_key, status, created_at, device_id "
                "FROM licenses ORDER BY created_at DESC, id DESC"
            ).fetchall()
            license_items = [
                {
                    **dict(item),
                    "created_at": time.strftime(
                        "%Y-%m-%d %H:%M UTC", time.gmtime(item["created_at"])
                    ),
                }
                for item in licenses
            ]
        return render_template_string(
            DASHBOARD_PAGE,
            styles=STYLES,
            csrf_token=csrf_token(),
            licenses=license_items,
            new_key=new_key,
        )

    @app.after_request
    def security_headers(response: Any) -> Any:
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if app.config["TRUST_RENDER_PROXY"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
            "base-uri 'none'; frame-ancestors 'none'"
        )
        return response

    @app.get("/healthz")
    def health() -> tuple[dict[str, str], int]:
        return {"status": "ok"}, 200

    @app.get("/")
    def home() -> Any:
        return redirect(url_for("admin_login_page"))

    @app.post("/api/activate")
    @app.post("/api/validate")
    def validate_license() -> tuple[dict[str, str], int]:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return {"error": "A JSON request body is required."}, 400
        key = _canonicalize_key(payload.get("key"))
        raw_device_id = payload.get("device_id")
        device_token = payload.get("device_token")
        if (
            key is None
            or not isinstance(raw_device_id, str)
            or not isinstance(device_token, str)
            or not DEVICE_TOKEN_PATTERN.fullmatch(device_token)
        ):
            return {"error": "A valid license key and installation credentials are required."}, 400
        try:
            device_id = str(uuid.UUID(raw_device_id))
        except (ValueError, AttributeError):
            return {"error": "A valid device ID is required."}, 400

        with database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            license_row = connection.execute(
                "SELECT id, status, device_id, device_token_hash FROM licenses "
                "WHERE key_hash = ?",
                (_license_key_hash(key, app.config["KEY_HASH_SECRET"]),),
            ).fetchone()
            if license_row is None or license_row["status"] != "active":
                if not _rate_limit(
                    connection, "license", request.remote_addr or "unknown", 12, 3600
                ):
                    return {"error": "Too many attempts. Try again later."}, 429
                return {"error": "This lifetime key is invalid or revoked."}, 403
            device_token_hash = hashlib.sha256(device_token.encode("ascii")).hexdigest()
            if license_row["device_id"] is None:
                connection.execute(
                    "UPDATE licenses SET device_id = ?, device_token_hash = ?, "
                    "activated_at = ? WHERE id = ?",
                    (device_id, device_token_hash, int(time.time()), license_row["id"]),
                )
            elif license_row["device_token_hash"] is None:
                return {
                    "error": "Reset this key's device binding in the dashboard before using this app version."
                }, 409
            elif (
                license_row["device_id"] != device_id
                or not hmac.compare_digest(
                    license_row["device_token_hash"], device_token_hash
                )
            ):
                return {"error": "This key is already activated on another installation."}, 409
        return {"status": "valid"}, 200

    @app.get("/admin/login")
    def admin_login_page() -> str:
        return render_template_string(
            LOGIN_PAGE, styles=STYLES, csrf_token=csrf_token()
        )

    @app.post("/admin/login")
    def admin_login() -> tuple[str, int] | Any:
        validate_csrf()
        with database() as connection:
            allowed = _rate_limit(
                connection, "admin-login", request.remote_addr or "unknown", 8, 900
            )
        supplied = request.form.get("password", "")
        if not allowed:
            abort(429)
        if not hmac.compare_digest(supplied, app.config["ADMIN_PASSWORD"]):
            flash("Sign-in failed.")
            return (
                render_template_string(
                    LOGIN_PAGE, styles=STYLES, csrf_token=csrf_token()
                ),
                401,
            )
        session.clear()
        session["administrator"] = True
        session["csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("admin_dashboard"))

    @app.get("/admin")
    @administrator_required
    def admin_dashboard() -> str:
        return dashboard()

    @app.post("/admin/keys/create")
    @administrator_required
    def create_key() -> str:
        validate_csrf()
        random_part = secrets.token_hex(16).upper()
        key = "VZ-" + "-".join(
            random_part[index : index + 4] for index in range(0, len(random_part), 4)
        )
        with database() as connection:
            connection.execute(
                "INSERT INTO licenses (key_hash, masked_key, status, created_at) "
                "VALUES (?, ?, 'active', ?)",
                (
                    _license_key_hash(key, app.config["KEY_HASH_SECRET"]),
                    f"VZ-****-****-****-****-****-****-{random_part[-4:]}",
                    int(time.time()),
                ),
            )
        return dashboard(new_key=key)

    @app.post("/admin/keys/<int:license_id>/revoke")
    @administrator_required
    def revoke_key(license_id: int) -> str:
        validate_csrf()
        with database() as connection:
            connection.execute(
                "UPDATE licenses SET status = 'revoked', revoked_at = ? "
                "WHERE id = ? AND status = 'active'",
                (int(time.time()), license_id),
            )
        flash("Key revoked.")
        return dashboard()

    @app.post("/admin/keys/<int:license_id>/reset-device")
    @administrator_required
    def reset_device(license_id: int) -> str:
        validate_csrf()
        with database() as connection:
            connection.execute(
                "UPDATE licenses SET device_id = NULL, device_token_hash = NULL, "
                "activated_at = NULL "
                "WHERE id = ? AND status = 'active'",
                (license_id,),
            )
        flash("Device binding reset.")
        return dashboard()

    @app.post("/admin/logout")
    @administrator_required
    def admin_logout() -> Any:
        validate_csrf()
        session.clear()
        return redirect(url_for("admin_login_page"))

    return app


app = create_app()
