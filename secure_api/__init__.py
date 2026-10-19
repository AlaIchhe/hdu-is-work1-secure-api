from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify, request

from .db import close_db, init_app as init_db_app, init_db, register_cli
from .routes import bp


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)

    default_db_path = Path(app.instance_path) / "secure_api.db"
    app.config.from_mapping(
        DATABASE_PATH=os.getenv("DATABASE_PATH", str(default_db_path)),
        JWT_SECRET_KEY=os.getenv("JWT_SECRET_KEY"),
        JWT_ISSUER="secure-api-lab",
        JWT_AUDIENCE="secure-api-client",
        JWT_TTL_SECONDS=900,
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    secret = app.config.get("JWT_SECRET_KEY")
    if not isinstance(secret, str) or len(secret) < 32:
        raise RuntimeError(
            "JWT_SECRET_KEY must be set to a random value of at least 32 characters"
        )

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    app.teardown_appcontext(close_db)
    init_db_app(app)
    register_cli(app)
    with app.app_context():
        init_db()

    app.register_blueprint(bp)

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify(error="Not found"), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return jsonify(error="Method not allowed"), 405

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify(error="Request body too large"), 413

    return app
