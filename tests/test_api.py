from __future__ import annotations

from secure_api.db import get_db


def test_login_returns_jwt(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Correct-Horse-Battery-Staple-1!"},
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["token_type"] == "Bearer"
    assert body["access_token"].count(".") == 2


def test_invalid_password_is_rejected(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "wrong-password"},
    )
    assert response.status_code == 401
    assert "access_token" not in response.get_json()


def test_sql_injection_cannot_bypass_login(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin' OR '1'='1' --", "password": "anything"},
    )
    assert response.status_code == 401


def test_protected_endpoint_requires_token(client):
    response = client.get("/api/data")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Bearer")


def test_tampered_token_is_rejected(client, auth_headers):
    token = auth_headers["Authorization"].split(" ", 1)[1]
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    response = client.get(
        "/api/data", headers={"Authorization": f"Bearer {tampered}"}
    )
    assert response.status_code == 401


def test_authenticated_data_read(client, auth_headers):
    response = client.get("/api/data", headers=auth_headers)
    assert response.status_code == 200
    body = response.get_json()
    assert body["count"] == 1
    assert body["items"][0]["title"] == "Welcome"


def test_xss_payload_is_escaped_on_output(client, auth_headers):
    payload = '<script>alert("xss")</script><img src=x onerror=alert(1)>'
    created = client.post(
        "/api/posts",
        headers=auth_headers,
        json={"title": "XSS test", "body": payload},
    )
    assert created.status_code == 201
    assert "<script>" not in created.get_data(as_text=True)

    response = client.get("/api/data", headers=auth_headers)
    response_text = response.get_data(as_text=True)
    assert "<script>" not in response_text
    assert "&lt;script&gt;" in response_text


def test_sql_injection_payload_is_stored_as_literal_text(client, auth_headers):
    payload = "'); DROP TABLE posts; --"
    response = client.post(
        "/api/posts",
        headers=auth_headers,
        json={"title": "SQLi test", "body": payload},
    )
    assert response.status_code == 201

    check = client.get("/api/data", headers=auth_headers)
    assert check.status_code == 200
    bodies = [item["body"] for item in check.get_json()["items"]]
    assert "&#x27;); DROP TABLE posts; --" in bodies


def test_passwords_are_hashed_with_scrypt(app):
    with app.app_context():
        row = get_db().execute(
            "SELECT password_hash FROM users WHERE username = ?", ("admin",)
        ).fetchone()
    assert row["password_hash"].startswith("scrypt:")
    assert row["password_hash"] != "Correct-Horse-Battery-Staple-1!"
