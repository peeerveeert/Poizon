import hmac
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request


DATA_DIR = Path(os.environ.get("POIZON_DATA_DIR", "/data"))
DATABASE_PATH = DATA_DIR / "poizon-sync.sqlite3"
BACKUP_DIR = DATA_DIR / "backups"
SYNC_TOKEN = os.environ.get("POIZON_SYNC_TOKEN", "")
ALLOWED_ORIGINS = {
    origin.strip()
    for origin in os.environ.get(
        "POIZON_ALLOWED_ORIGINS", "https://peeerveeert.github.io"
    ).split(",")
    if origin.strip()
}
WORKSPACE_RE = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
MAX_DATA_BYTES = 2 * 1024 * 1024

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_DATA_BYTES + 64 * 1024


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def connect_db():
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    return connection


def init_database():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    with connect_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )


def valid_token():
    header = request.headers.get("Authorization", "")
    supplied = header.removeprefix("Bearer ").strip()
    return bool(SYNC_TOKEN) and hmac.compare_digest(supplied, SYNC_TOKEN)


def validate_workspace(workspace):
    return bool(WORKSPACE_RE.fullmatch(workspace))


def save_backup(workspace, serialized_data, updated_at):
    if not serialized_data:
        return
    timestamp = updated_at.replace(":", "-").replace("+", "_")
    backup_path = BACKUP_DIR / f"{workspace}-{timestamp}.json"
    backup_path.write_text(serialized_data, encoding="utf-8")
    backups = sorted(BACKUP_DIR.glob(f"{workspace}-*.json"), reverse=True)
    for old_backup in backups[20:]:
        old_backup.unlink(missing_ok=True)


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, PUT, OPTIONS"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.before_request
def authorize():
    if request.method == "OPTIONS" or request.path == "/health":
        return None
    if not valid_token():
        return jsonify(error="Неверный ключ синхронизации."), 401
    return None


@app.route("/health", methods=["GET"])
def health():
    return jsonify(ok=True, service="poizon-sync")


@app.route("/workspaces/<workspace>", methods=["GET", "PUT", "OPTIONS"])
def workspace_data(workspace):
    if request.method == "OPTIONS":
        return "", 204
    if not validate_workspace(workspace):
        return jsonify(error="Код рабочего пространства должен содержать 3–64 латинских символа, цифры, _ или -."), 400

    if request.method == "GET":
        with connect_db() as connection:
            row = connection.execute(
                "SELECT data, updated_at FROM workspaces WHERE id = ?", (workspace,)
            ).fetchone()
        if row is None:
            return jsonify(error="Рабочее пространство не найдено."), 404
        return jsonify(data=json.loads(row["data"]), updated_at=row["updated_at"])

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        return jsonify(error="Ожидался объект data."), 400
    serialized = json.dumps(payload["data"], ensure_ascii=False, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > MAX_DATA_BYTES:
        return jsonify(error="Данные превышают допустимый размер 2 МБ."), 413

    updated_at = utc_now()
    with connect_db() as connection:
        previous = connection.execute(
            "SELECT data, updated_at FROM workspaces WHERE id = ?", (workspace,)
        ).fetchone()
        if previous is not None:
            save_backup(workspace, previous["data"], previous["updated_at"])
        connection.execute(
            """
            INSERT INTO workspaces (id, data, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at
            """,
            (workspace, serialized, updated_at),
        )
    return jsonify(ok=True, updated_at=updated_at)


init_database()

