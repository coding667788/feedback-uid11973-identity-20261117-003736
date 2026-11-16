"""SQLite access shared by the RP processes, the two IdPs and the tools.

Design notes
------------
* Rollback-journal mode (not WAL).  The durable unit is a plain ``COMMIT`` and
  every connection uses ``synchronous=FULL``.
* Every write path opens ``BEGIN IMMEDIATE`` so concurrent writers serialise on
  SQLite's write lock instead of racing on read-then-write sequences.
* Ten-second busy timeout absorbs the short lock contention of the crash tests
  (many processes hitting the same row).
* Two repositories live in one RP database; the IdPs each have their own file.
"""

from __future__ import annotations

import contextlib
import sqlite3
from pathlib import Path
from typing import Any, Iterator


def connect(path: str | Path, *, timeout: float = 20.0) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(path),
        timeout=timeout,
        isolation_level=None,  # explicit transactions
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = DELETE")
    conn.execute("PRAGMA synchronous = FULL")
    conn.execute("PRAGMA busy_timeout = 20000")
    return conn


@contextlib.contextmanager
def write_txn(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Serialised write transaction; commits on success, rolls back on error."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def one(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
    return conn.execute(sql, params).fetchone()
