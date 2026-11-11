"""Whitelist management. Mutations are gated to the real guild owner upstream."""
from __future__ import annotations

from datetime import datetime, timezone

import discord

from database import Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class WhitelistManager:
    def __init__(self, db: Database):
        self.db = db

    async def add(self, guild_id: int, target_id: int, actor_id: int) -> bool:
        await self.db.whitelist_add(guild_id, target_id, actor_id, _now())
        return True

    async def remove(self, guild_id: int, target_id: int) -> bool:
        return await self.db.whitelist_remove(guild_id, target_id)

    async def list(self, guild_id: int) -> list[tuple[int, int, str]]:
        return await self.db.whitelist_list(guild_id)

    async def contains(self, guild_id: int, target_id: int) -> bool:
        return await self.db.is_whitelisted(guild_id, target_id)

    async def add_bot(self, guild_id: int, bot_id: int, actor_id: int) -> None:
        await self.db.trust_add(guild_id, bot_id, actor_id, _now())

    async def remove_bot(self, guild_id: int, bot_id: int) -> bool:
        return await self.db.trust_remove(guild_id, bot_id)

    async def list_bots(self, guild_id: int) -> list[int]:
        return await self.db.trust_list(guild_id)
