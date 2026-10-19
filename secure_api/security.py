from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable, TypeVar

import jwt
from flask import current_app, g, jsonify, request

from .db import get_db


F = TypeVar("F", bound=Callable[..., Any])


def issue_token(user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=current_app.config["JWT_TTL_SECONDS"]),
        "iss": current_app.config["JWT_ISSUER"],
        "aud": current_app.config["JWT_AUDIENCE"],
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(
        payload,
        current_app.config["JWT_SECRET_KEY"],
        algorithm="HS256",
    )


def _unauthorized(message: str = "Authentication required"):
    response = jsonify(error=message)
    response.status_code = 401
    response.headers["WWW-Authenticate"] = 'Bearer realm="secure-api"'
    return response


def require_auth(view: F) -> F:
    @wraps(view)
    def wrapped(*args, **kwargs):
        authorization = request.headers.get("Authorization", "")
        scheme, separator, token = authorization.partition(" ")
        if separator != " " or scheme.lower() != "bearer" or not token.strip():
            return _unauthorized()

        try:
            payload = jwt.decode(
                token.strip(),
                current_app.config["JWT_SECRET_KEY"],
                algorithms=["HS256"],
                audience=current_app.config["JWT_AUDIENCE"],
                issuer=current_app.config["JWT_ISSUER"],
                leeway=5,
                options={"require": ["sub", "iat", "nbf", "exp", "iss", "aud"]},
            )
            user_id = int(payload["sub"])
        except (jwt.PyJWTError, TypeError, ValueError):
            return _unauthorized("Invalid or expired token")

        user = get_db().execute(
            "SELECT id, username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if user is None:
            return _unauthorized("Invalid or expired token")

        g.current_user = {"id": user["id"], "username": user["username"]}
        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]
