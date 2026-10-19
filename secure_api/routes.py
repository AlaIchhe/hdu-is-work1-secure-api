from __future__ import annotations

import html

from flask import Blueprint, current_app, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db
from .security import issue_token, require_auth


bp = Blueprint("api", __name__, url_prefix="/api")
BEARER_TYPE = "Bearer"

_DUMMY_HASH = generate_password_hash(
    "dummy-password-not-used",
    method="scrypt:32768:8:1",
    salt_length=16,
)


def _clean_text(value: str) -> str:
    return html.escape(value, quote=True)


def _json_object():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return None
    return payload


@bp.post("/auth/login")
def login():
    payload = _json_object()
    if payload is None:
        return jsonify(error="A JSON object is required"), 400

    username = payload.get("username")
    password = payload.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="username and password must be strings"), 400
    if not 1 <= len(username) <= 64 or not 1 <= len(password) <= 256:
        return jsonify(error="Invalid credentials"), 401

    user = get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    stored_hash = user["password_hash"] if user is not None else _DUMMY_HASH
    if not check_password_hash(stored_hash, password) or user is None:
        return jsonify(error="Invalid credentials"), 401

    token = issue_token(user["id"], user["username"])
    return jsonify(
        access_token=token,
        token_type=BEARER_TYPE,
        expires_in=current_app.config["JWT_TTL_SECONDS"],
    )


@bp.get("/data")
@require_auth
def list_data():
    rows = get_db().execute(
        """
        SELECT posts.id, posts.title, posts.body, posts.created_at,
               users.username AS author
        FROM posts
        JOIN users ON users.id = posts.user_id
        ORDER BY posts.id ASC
        """
    ).fetchall()
    items = [
        {
            "id": row["id"],
            "author": _clean_text(row["author"]),
            "title": _clean_text(row["title"]),
            "body": _clean_text(row["body"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]
    return jsonify(items=items, count=len(items))


@bp.post("/posts")
@require_auth
def create_post():
    payload = _json_object()
    if payload is None:
        return jsonify(error="A JSON object is required"), 400

    title = payload.get("title")
    body = payload.get("body")
    if not isinstance(title, str) or not isinstance(body, str):
        return jsonify(error="title and body must be strings"), 400
    title = title.strip()
    body = body.strip()
    if not 1 <= len(title) <= 120:
        return jsonify(error="title must contain 1-120 characters"), 400
    if not 1 <= len(body) <= 5000:
        return jsonify(error="body must contain 1-5000 characters"), 400

    connection = get_db()
    cursor = connection.execute(
        "INSERT INTO posts (user_id, title, body) VALUES (?, ?, ?)",
        (g.current_user["id"], title, body),
    )
    connection.commit()
    row = connection.execute(
        "SELECT id, title, body, created_at FROM posts WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()
    return (
        jsonify(
            id=row["id"],
            author=_clean_text(g.current_user["username"]),
            title=_clean_text(row["title"]),
            body=_clean_text(row["body"]),
            created_at=row["created_at"],
        ),
        201,
    )
