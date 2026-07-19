from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from secai.settings import get_settings

SCHEMA_VERSION = 7
_POSTGRES_POOL_SIZE = 5
_pool: ConnectionPool[Any] | None = None
_pool_url: str | None = None
_pool_lock = threading.Lock()


def database_backend() -> str:
    """Return the configured database backend and reject unsupported URLs."""
    database_url = get_settings().database_url
    if database_url.startswith("sqlite:///"):
        return "sqlite"
    if database_url.startswith(("postgresql://", "postgres://")):
        return "postgresql"
    raise ValueError("DATABASE_URL must use sqlite:/// or postgresql://")


def _db_path() -> str:
    """Return the configured SQLite path."""
    return get_settings().database_url.replace("sqlite:///", "", 1)


class PostgreSQLConnection:
    """Expose the compact DB-API surface used by SecAi repositories."""

    dialect = "postgresql"

    def __init__(self, connection: psycopg.Connection[Any]):
        self._connection = connection

    def execute(self, query: str, params: tuple[Any, ...] = ()):
        query = "begin" if query.strip().lower() == "begin immediate" else query.replace("?", "%s")
        return self._connection.execute(query, params)


def _postgres_pool() -> ConnectionPool[Any]:
    global _pool, _pool_url

    database_url = get_settings().database_url
    with _pool_lock:
        if _pool is not None and _pool_url != database_url:
            _pool.close()
            _pool = None
        if _pool is None:
            _pool = ConnectionPool(
                conninfo=database_url,
                min_size=1,
                max_size=_POSTGRES_POOL_SIZE,
                kwargs={"row_factory": dict_row},
            )
            _pool_url = database_url
        return _pool


@contextmanager
def connect() -> Iterator[Any]:
    """Borrow a pooled PostgreSQL connection or open the local SQLite database."""
    if database_backend() == "postgresql":
        with _postgres_pool().connection() as raw_connection:
            yield PostgreSQLConnection(raw_connection)
        return

    path = _db_path()
    if path not in (":memory:", ""):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("pragma foreign_keys = on")
    connection.execute("pragma busy_timeout = 5000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    """Create the current database schema."""
    from secai.database.schema import initialize

    with connect() as connection:
        initialize(connection, _db_path() if database_backend() == "sqlite" else "", SCHEMA_VERSION)


def close_database_pool() -> None:
    """Close the process-wide PostgreSQL pool during application shutdown."""
    global _pool, _pool_url

    with _pool_lock:
        if _pool is not None:
            _pool.close()
        _pool = None
        _pool_url = None
