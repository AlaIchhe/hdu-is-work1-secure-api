from __future__ import annotations

import pytest

from secure_api import create_app
from secure_api.db import create_user, get_db


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "test.db"),
            "JWT_SECRET_KEY": "test-secret-key-that-is-long-enough-123456",
        }
    )
    with application.app_context():
        create_user("admin", "Correct-Horse-Battery-Staple-1!")
        create_user("alice", "Alice-Strong-Password-2!")
        connection = get_db()
        connection.execute(
            "INSERT INTO posts (user_id, title, body) VALUES (?, ?, ?)",
            (1, "Welcome", "Seed post"),
        )
        connection.commit()
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_headers(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Correct-Horse-Battery-Staple-1!"},
    )
    token = response.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
