"""Durable storage for HAVX+lo SECURTY.

Uses PostgreSQL when DATABASE_URL is set, otherwise a SQLite file under DATA_DIR.
Railway deployments should either attach a Postgres plugin (DATABASE_URL) or a
volume mounted at the DATA_DIR path so state survives redeploys.
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any

import aiosqlite

try:
    import asyncpg
except Exception:  # pragma: no cover - asyncpg always present via requirements
    asyncpg = None

SCHEMA_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS settings (
        guild_id BIGINT PRIMARY KEY,
        data TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS whitelist (
        guild_id BIGINT NOT NULL,
        user_id BIGINT NOT NULL,
        added_by BIGINT NOT NULL,
        added_at TEXT NOT NULL,
        PRIMARY KEY (guild_id, user_id)
    )""",
    """CREATE TABLE IF NOT EXISTS trusted_bots (
        guild_id BIGINT NOT NULL,
        bot_id BIGINT NOT NULL,
        added_by BIGINT NOT NULL,
        added_at TEXT NOT NULL,
        PRIMARY KEY (guild_id, bot_id)
    )""",
    """CREATE TABLE IF NOT EXISTS lockdown (
        guild_id BIGINT PRIMARY KEY,
        snapshot TEXT NOT NULL,
        activated_by BIGINT NOT NULL,
        activated_at TEXT NOT NULL
    )""",
]


def _norm_url(url: str) -> str:
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://"):]
    return url


class _SQLiteBackend:
    def __init__(self, path: str):
        self.path = path
        self._db: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._db = await aiosqlite.connect(self.path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        for stmt in SCHEMA_STATEMENTS:
            await self._db.execute(stmt)
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()

    async def execute(self, sql: str, params: tuple = ()) -> None:
        async with self._lock:
            await self._db.execute(sql, params)
            await self._db.commit()

    async def fetchone(self, sql: str, params: tuple = ()):
        async with self._lock:
            cur = await self._db.execute(sql, params)
            row = await cur.fetchone()
            await cur.close()
            return row

    async def fetchall(self, sql: str, params: tuple = ()):
        async with self._lock:
            cur = await self._db.execute(sql, params)
            rows = await cur.fetchall()
            await cur.close()
            return rows

    def p(self, index: int) -> str:
        return "?"


class _PostgresBackend:
    def __init__(self, url: str):
        self.url = _norm_url(url)
        self._pool = None

    async def connect(self) -> None:
        self._pool = await asyncpg.create_pool(self.url, min_size=1, max_size=5)
        async with self._pool.acquire() as conn:
            for stmt in SCHEMA_STATEMENTS:
                await conn.execute(stmt)

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()

    async def execute(self, sql: str, params: tuple = ()) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(sql, *params)

    async def fetchone(self, sql: str, params: tuple = ()):
        async with self._pool.acquire() as conn:
            return await conn.fetchrow(sql, *params)

    async def fetchall(self, sql: str, params: tuple = ()):
        async with self._pool.acquire() as conn:
            return await conn.fetch(sql, *params)

    def p(self, index: int) -> str:
        return f"${index}"


class Database:
    """Public storage facade with identical semantics for both backends."""

    def __init__(self, url: str = "", sqlite_path: str = "data/havx.sqlite3"):
        self.url = (url or "").strip()
        self.sqlite_path = sqlite_path
        if self.url.startswith(("postgres://", "postgresql://")) and asyncpg is not None:
            self.backend = _PostgresBackend(self.url)
            self.kind = "postgres"
        else:
            self.backend = _SQLiteBackend(sqlite_path)
            self.kind = "sqlite"

    async def connect(self) -> None:
        await self.backend.connect()

    async def close(self) -> None:
        await self.backend.close()

    # ---- settings ----
    async def get_settings(self, guild_id: int, defaults: dict) -> dict:
        row = await self.backend.fetchone(
            f"SELECT data FROM settings WHERE guild_id = {self.backend.p(1)}", (guild_id,)
        )
        data = dict(defaults)
        if row:
            try:
                data.update(json.loads(row[0]))
            except (ValueError, TypeError):
                pass
        return data

    async def save_settings(self, guild_id: int, data: dict) -> None:
        p = self.backend.p
        if self.kind == "postgres":
            await self.backend.execute(
                f"INSERT INTO settings (guild_id, data) VALUES ({p(1)}, {p(2)}) "
                f"ON CONFLICT (guild_id) DO UPDATE SET data = EXCLUDED.data",
                (guild_id, json.dumps(data)),
            )
        else:
            await self.backend.execute(
                f"INSERT INTO settings (guild_id, data) VALUES ({p(1)}, {p(2)}) "
                f"ON CONFLICT(guild_id) DO UPDATE SET data = excluded.data",
                (guild_id, json.dumps(data)),
            )

    # ---- whitelist ----
    async def whitelist_add(self, guild_id: int, user_id: int, added_by: int, added_at: str) -> None:
        p = self.backend.p
        if self.kind == "postgres":
            await self.backend.execute(
                f"INSERT INTO whitelist (guild_id, user_id, added_by, added_at) "
                f"VALUES ({p(1)}, {p(2)}, {p(3)}, {p(4)}) "
                f"ON CONFLICT (guild_id, user_id) DO UPDATE SET added_by = EXCLUDED.added_by, added_at = EXCLUDED.added_at",
                (guild_id, user_id, added_by, added_at),
            )
        else:
            await self.backend.execute(
                f"INSERT INTO whitelist (guild_id, user_id, added_by, added_at) "
                f"VALUES ({p(1)}, {p(2)}, {p(3)}, {p(4)}) "
                f"ON CONFLICT(guild_id, user_id) DO UPDATE SET added_by = excluded.added_by, added_at = excluded.added_at",
                (guild_id, user_id, added_by, added_at),
            )

    async def whitelist_remove(self, guild_id: int, user_id: int) -> bool:
        p = self.backend.p
        row = await self.backend.fetchone(
            f"SELECT 1 FROM whitelist WHERE guild_id = {p(1)} AND user_id = {p(2)}",
            (guild_id, user_id),
        )
        if not row:
            return False
        await self.backend.execute(
            f"DELETE FROM whitelist WHERE guild_id = {p(1)} AND user_id = {p(2)}",
            (guild_id, user_id),
        )
        return True

    async def whitelist_list(self, guild_id: int) -> list[tuple[int, int, str]]:
        p = self.backend.p
        rows = await self.backend.fetchall(
            f"SELECT user_id, added_by, added_at FROM whitelist WHERE guild_id = {p(1)} ORDER BY added_at",
            (guild_id,),
        )
        return [(int(r[0]), int(r[1]), str(r[2])) for r in rows]

    async def is_whitelisted(self, guild_id: int, user_id: int) -> bool:
        p = self.backend.p
        row = await self.backend.fetchone(
            f"SELECT 1 FROM whitelist WHERE guild_id = {p(1)} AND user_id = {p(2)}",
            (guild_id, user_id),
        )
        return bool(row)

    # ---- trusted bots ----
    async def trust_add(self, guild_id: int, bot_id: int, added_by: int, added_at: str) -> None:
        p = self.backend.p
        if self.kind == "postgres":
            await self.backend.execute(
                f"INSERT INTO trusted_bots (guild_id, bot_id, added_by, added_at) "
                f"VALUES ({p(1)}, {p(2)}, {p(3)}, {p(4)}) "
                f"ON CONFLICT (guild_id, bot_id) DO UPDATE SET added_by = EXCLUDED.added_by, added_at = EXCLUDED.added_at",
                (guild_id, bot_id, added_by, added_at),
            )
        else:
            await self.backend.execute(
                f"INSERT INTO trusted_bots (guild_id, bot_id, added_by, added_at) "
                f"VALUES ({p(1)}, {p(2)}, {p(3)}, {p(4)}) "
                f"ON CONFLICT(guild_id, bot_id) DO UPDATE SET added_by = excluded.added_by, added_at = excluded.added_at",
                (guild_id, bot_id, added_by, added_at),
            )

    async def trust_remove(self, guild_id: int, bot_id: int) -> bool:
        p = self.backend.p
        row = await self.backend.fetchone(
            f"SELECT 1 FROM trusted_bots WHERE guild_id = {p(1)} AND bot_id = {p(2)}",
            (guild_id, bot_id),
        )
        if not row:
            return False
        await self.backend.execute(
            f"DELETE FROM trusted_bots WHERE guild_id = {p(1)} AND bot_id = {p(2)}",
            (guild_id, bot_id),
        )
        return True

    async def trust_list(self, guild_id: int) -> list[int]:
        p = self.backend.p
        rows = await self.backend.fetchall(
            f"SELECT bot_id FROM trusted_bots WHERE guild_id = {p(1)} ORDER BY bot_id", (guild_id,)
        )
        return [int(r[0]) for r in rows]

    async def is_trusted_bot(self, guild_id: int, bot_id: int) -> bool:
        p = self.backend.p
        row = await self.backend.fetchone(
            f"SELECT 1 FROM trusted_bots WHERE guild_id = {p(1)} AND bot_id = {p(2)}",
            (guild_id, bot_id),
        )
        return bool(row)

    # ---- lockdown snapshot ----
    async def lockdown_save(self, guild_id: int, snapshot: dict, activated_by: int, activated_at: str) -> None:
        p = self.backend.p
        if self.kind == "postgres":
            await self.backend.execute(
                f"INSERT INTO lockdown (guild_id, snapshot, activated_by, activated_at) "
                f"VALUES ({p(1)}, {p(2)}, {p(3)}, {p(4)}) "
                f"ON CONFLICT (guild_id) DO UPDATE SET snapshot = EXCLUDED.snapshot, "
                f"activated_by = EXCLUDED.activated_by, activated_at = EXCLUDED.activated_at",
                (guild_id, json.dumps(snapshot), activated_by, activated_at),
            )
        else:
            await self.backend.execute(
                f"INSERT INTO lockdown (guild_id, snapshot, activated_by, activated_at) "
                f"VALUES ({p(1)}, {p(2)}, {p(3)}, {p(4)}) "
                f"ON CONFLICT(guild_id) DO UPDATE SET snapshot = excluded.snapshot, "
                f"activated_by = excluded.activated_by, activated_at = excluded.activated_at",
                (guild_id, json.dumps(snapshot), activated_by, activated_at),
            )

    async def lockdown_load(self, guild_id: int) -> dict | None:
        p = self.backend.p
        row = await self.backend.fetchone(
            f"SELECT snapshot, activated_by, activated_at FROM lockdown WHERE guild_id = {p(1)}",
            (guild_id,),
        )
        if not row:
            return None
        return {
            "snapshot": json.loads(row[0]),
            "activated_by": int(row[1]),
            "activated_at": str(row[2]),
        }

    async def lockdown_delete(self, guild_id: int) -> None:
        p = self.backend.p
        await self.backend.execute(
            f"DELETE FROM lockdown WHERE guild_id = {p(1)}", (guild_id,)
        )

    # ---- single-instance guard ----
    ADVISORY_LOCK_KEY = 9876543210

    async def acquire_instance_lock(self) -> bool:
        """Prevent two bot processes from running against the same database."""
        if self.kind != "postgres":
            return True
        try:
            import asyncpg as _pg
            self._lock_conn = await _pg.connect(self.backend.url)
            got = await self._lock_conn.fetchval(
                "SELECT pg_try_advisory_lock($1)", self.ADVISORY_LOCK_KEY
            )
            return bool(got)
        except Exception:  # pragma: no cover - fail open on transient DB errors
            return True

    async def release_instance_lock(self) -> None:
        conn = getattr(self, "_lock_conn", None)
        if conn is not None:
            try:
                await conn.execute("SELECT pg_advisory_unlock($1)", self.ADVISORY_LOCK_KEY)
                await conn.close()
            except Exception:
                pass
            self._lock_conn = None
