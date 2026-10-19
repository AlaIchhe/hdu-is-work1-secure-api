from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import click
from flask import Flask, current_app, g
from werkzeug.security import generate_password_hash


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts (user_id);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        database_path = current_app.config["DATABASE_PATH"]
        if database_path != ":memory:":
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        g.db = connection
    return g.db


def close_db(_error=None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db() -> None:
    connection = get_db()
    connection.executescript(SCHEMA)
    connection.commit()


def create_user(username: str, password: str) -> int:
    password_hash = generate_password_hash(
        password,
        method="scrypt:32768:8:1",
        salt_length=16,
    )
    connection = get_db()
    cursor = connection.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash),
    )
    connection.commit()
    return int(cursor.lastrowid)


def seed_demo_data() -> None:
    admin_password = current_app.config.get("DEMO_ADMIN_PASSWORD")
    user_password = current_app.config.get("DEMO_USER_PASSWORD")
    if not admin_password or not user_password:
        return

    connection = get_db()
    existing = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if existing:
        return

    admin_id = create_user("admin", admin_password)
    alice_id = create_user("alice", user_password)
    connection.executemany(
        "INSERT INTO posts (user_id, title, body) VALUES (?, ?, ?)",
        [
            (admin_id, "Welcome", "This post is seeded for the secure API demo."),
            (alice_id, "Alice's note", "Only authenticated users can read this feed."),
        ],
    )
    connection.commit()


def init_app(app: Flask) -> None:
    app.config.setdefault("DEMO_ADMIN_PASSWORD", os.getenv("DEMO_ADMIN_PASSWORD"))
    app.config.setdefault("DEMO_USER_PASSWORD", os.getenv("DEMO_USER_PASSWORD"))


def register_cli(app: Flask) -> None:
    @app.cli.command("init-db")
    def init_db_command() -> None:
        """Create database tables and optionally seed demo users."""
        init_db()
        seed_demo_data()
        click.echo("Database initialized.")
