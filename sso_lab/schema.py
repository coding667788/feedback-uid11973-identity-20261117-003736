"""RP database schema (shared by all RP worker processes).

The tables carry the anti-confusion invariants:

``login_txns``
    One row per *started* login; primary key is the ``state`` nonce.  A row pins
    the browser session id, the chosen issuer, the exact callback URL (including
    ``?issuer=``), the authorization endpoint and token endpoint of that issuer,
    client id, redirect URI, nonce and PKCE challenge.  There is no "last state"
    slot anywhere: lookups happen by state only.

``login_sessions``
    One row per established login.  The user key is the composite
    ``(issuer, subject)``; the e-mail column is display-only and carries no
    uniqueness.

``callback_attempts``
    Audit trail of every callback, one row per callback attempt, so tests can
    assert how many sessions a burst of identical callbacks produced.

``rp_events``
    Crash / lifecycle breadcrumbs (used by the crash tests).
"""

from __future__ import annotations

import sqlite3

from .db import connect, write_txn

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS login_txns (
    state                  TEXT PRIMARY KEY,
    browser_sid            TEXT NOT NULL,
    issuer_key             TEXT NOT NULL,
    issuer                 TEXT NOT NULL,
    authorization_endpoint TEXT NOT NULL,
    token_endpoint         TEXT NOT NULL,
    client_id              TEXT NOT NULL,
    redirect_uri           TEXT NOT NULL,
    nonce                  TEXT NOT NULL,
    pkce_verifier          TEXT NOT NULL,
    pkce_challenge         TEXT NOT NULL,
    created_at             REAL NOT NULL,
    expires_at             REAL NOT NULL,
    status                 TEXT NOT NULL,
    consumed_at            REAL,
    claim_pid              INTEGER,
    claimed_at             REAL
);
CREATE INDEX IF NOT EXISTS idx_txn_browser ON login_txns(browser_sid, status);

CREATE TABLE IF NOT EXISTS login_sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL UNIQUE,
    browser_sid   TEXT NOT NULL,
    issuer        TEXT NOT NULL,
    subject       TEXT NOT NULL,
    email         TEXT,
    display_name  TEXT,
    id_token_hash TEXT NOT NULL,
    state         TEXT NOT NULL,
    created_at    REAL NOT NULL,
    expires_at    REAL NOT NULL,
    UNIQUE (browser_sid, issuer, subject)
);
CREATE INDEX IF NOT EXISTS idx_sessions_browser ON login_sessions(browser_sid);

CREATE TABLE IF NOT EXISTS callback_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    callback_id  TEXT NOT NULL,
    state        TEXT,
    browser_sid  TEXT,
    issuer_key   TEXT,
    outcome      TEXT NOT NULL,
    reason       TEXT,
    wsgi_pid     INTEGER,
    session_id   TEXT,
    created_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_state ON callback_attempts(state);

CREATE TABLE IF NOT EXISTS rp_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    detail      TEXT,
    wsgi_pid    INTEGER,
    created_at  REAL NOT NULL
);
"""


def connect_rp(path) -> sqlite3.Connection:
    conn = connect(path)
    ensure_schema(conn)
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create tables if needed (idempotent, safe from several processes)."""
    if conn.execute("PRAGMA user_version").fetchone()[0] >= SCHEMA_VERSION:
        return
    try:
        with write_txn(conn):
            for statement in _statements(SCHEMA):
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    except sqlite3.OperationalError:
        # Another process may have created it first; verify.
        if conn.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION:
            raise


def _statements(script: str) -> list[str]:
    return [part.strip() for part in script.split(";") if part.strip()]
