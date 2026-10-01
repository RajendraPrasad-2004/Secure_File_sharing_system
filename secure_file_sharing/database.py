"""
database.py - SQLite connection handling and schema initialisation.
Uses Python's built-in sqlite3 module with parameterised queries only
(this prevents SQL injection).
"""
import sqlite3
import os
from flask import g, current_app

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    username              TEXT NOT NULL UNIQUE,
    email                 TEXT NOT NULL UNIQUE,
    password_hash         TEXT NOT NULL,
    public_key            TEXT NOT NULL,            -- RSA public key (PEM)
    encrypted_private_key TEXT NOT NULL,            -- RSA private key, AES-GCM wrapped
    failed_attempts       INTEGER NOT NULL DEFAULT 0,
    locked_until          TEXT,
    created_at            TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS files (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id           INTEGER NOT NULL,
    original_filename  TEXT NOT NULL,
    encrypted_filename TEXT NOT NULL UNIQUE,        -- random name on disk
    encrypted_aes_key  TEXT NOT NULL,               -- AES key wrapped with owner's RSA public key
    nonce              TEXT NOT NULL,               -- 12-byte GCM nonce (base64)
    file_size          INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS file_shares (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id             INTEGER NOT NULL,
    owner_id            INTEGER NOT NULL,
    shared_with_user_id INTEGER NOT NULL,
    encrypted_aes_key   TEXT NOT NULL,              -- same AES key, wrapped with RECIPIENT's public key
    created_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (file_id, shared_with_user_id),
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
    FOREIGN KEY (owner_id) REFERENCES users(id),
    FOREIGN KEY (shared_with_user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS security_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,                              -- NULL for unknown users
    action     TEXT NOT NULL,
    ip_address TEXT,
    timestamp  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status     TEXT NOT NULL
);
"""


def get_db():
    """Return a per-request SQLite connection."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    """Create the database file and tables if they do not exist."""
    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    app.teardown_appcontext(close_db)
