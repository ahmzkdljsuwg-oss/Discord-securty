"""Core security engine: settings, identity checks, audit lookup and punishments."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

import discord

from config import DEFAULT_SETTINGS
from database import Database

log = logging.getLogger("havx.security")

DANGEROUS_PERMS = (
    "administrator",
    "manage_guild",
    "manage_roles",
    "manage_channels",
    "manage_webhooks",
    "ban_members",
    "kick_members",
    "manage_messages",
    "mention_everyone",
)


class SecurityEngine:
    def __init__(self, bot: discord.Client, db: Database):
        self.bot = bot
        self.db = db
        self._settings: dict[int, dict] = {}
        self._busy: set[int] = set()
        self._locks: dict[int, asyncio.Lock] = {}

    # ---------------- settings ----------------
    async def settings(self, guild: discord.Guild) -> dict:
        if guild.id not in self._settings:
            self._settings[guild.id] = await self.db.get_settings(guild.id, DEFAULT_SETTINGS)
        return self._settings[guild.id]

    async def save(self, guild: discord.Guild, data: dict) -> None:
        self._settings[guild.id] = data
        await self.db.save_settings(guild.id, data)

    async def set_flag(self, guild: discord.Guild, key: str, value) -> dict:
        data = await self.settings(guild)
        data[key] = value
        await self.save(guild, data)
        return data

    # ---------------- identity ----------------
    @staticmethod
    def is_owner(guild: discord.Guild, user: discord.abc.User) -> bool:
        return getattr(user, "id", None) == guild.owner_id

    async def is_whitelisted(self, guild: discord.Guild, user_id: int) -> bool:
        return await self.db.is_whitelisted(guild.id, user_id)

    async def is_trusted_bot(self, guild: discord.Guild, user_id: int) -> bool:
        return await self.db.is_trusted_bot(guild.id, user_id)

    async def is_exempt(self, guild: discord.Guild, member: Optional[discord.Member]) -> bool:
        """Trusted identities that protections must not punish."""
        if member is None:
            return False
        if member.id == self.bot.user.id:
            return True
        if self.is_owner(guild, member):
            return True
        if await self.is_whitelisted(guild, member.id):
            return True
        if member.bot and await self.is_trusted_bot(guild, member.id):
            return True
        data = await self.settings(guild)
        immune_ids = {int(r) for r in data.get("immune_roles", [])}
        if immune_ids and any(role.id in immune_ids for role in member.roles):
            return True
        return False

    async def is_trusted_actor(self, guild: discord.Guild, user: Optional[discord.abc.User]) -> bool:
        if user is None:
            return False
        if self.is_owner(guild, user):
            return True
        if await self.is_whitelisted(guild, user.id):
            return True
        if getattr(user, "bot", False) and await self.is_trusted_bot(guild, user.id):
            return True
        return False

    # ---------------- concurrency ----------------
    def lock_for(self, guild_id: int) -> asyncio.Lock:
        if guild_id not in self._locks:
            self._locks[guild_id] = asyncio.Lock()
        return self._locks[guild_id]

    def claim(self, guild_id: int) -> bool:
        if guild_id in self._busy:
            return False
        self._busy.add(guild_id)
        return True

    def release(self, guild_id: int) -> None:
        self._busy.discard(guild_id)

    # ---------------- audit log ----------------
    async def find_actor(
        self,
        guild: discord.Guild,
        action: discord.AuditLogAction,
        target_id: Optional[int] = None,
        within: int = 20,
    ) -> Optional[discord.AuditLogEntry]:
        """Return the most recent audit entry for an action, matched to target when given."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=within)
        try:
            async for entry in guild.audit_logs(limit=8, action=action):
                created = entry.created_at
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                if created < cutoff:
                    break
                if target_id is None:
                    return entry
                tid = getattr(entry.target, "id", None)
                if tid == target_id:
                    return entry
        except discord.Forbidden:
            log.warning("Missing View Audit Log in guild %s", guild.id)
        except discord.HTTPException as exc:
            log.warning("Audit log fetch failed: %s", exc)
        return None

    # ---------------- punishments ----------------
    async def strip_dangerous_roles(self, guild: discord.Guild, member: discord.Member) -> list[str]:
        removed: list[str] = []
        me = guild.me
        for role in list(member.roles):
            if role.is_default() or role.managed or role == guild.default_role:
                continue
            dangerous = any(getattr(role.permissions, p, False) for p in DANGEROUS_PERMS)
            if not dangerous:
                continue
            if me.top_role <= role:
                continue
            try:
                await member.remove_roles(role, reason="HAVX+lo SECURTY: dangerous role stripped")
                removed.append(role.name)
            except (discord.Forbidden, discord.HTTPException):
                continue
        return removed

    async def timeout_member(self, member: discord.Member, minutes: int, reason: str) -> bool:
        try:
            until = datetime.now(timezone.utc) + timedelta(minutes=minutes)
            await member.timeout(until, reason=reason)
            return True
        except (discord.Forbidden, discord.HTTPException):
            return False

    async def punish(
        self,
        guild: discord.Guild,
        member: Optional[discord.Member],
        punishment: str,
        reason: str,
        *,
        timeout_minutes: int = 10,
    ) -> tuple[str, bool]:
        """Apply a punishment. Returns (description, success)."""
        if member is None:
            return ("member not found", False)
        if self.is_owner(guild, member):
            return ("owner is never punished", False)
        try:
            if punishment == "ban":
                await member.ban(reason=reason, delete_message_days=0)
                return ("banned", True)
            if punishment == "kick":
                await member.kick(reason=reason)
                return ("kicked", True)
            if punishment == "timeout":
                ok = await self.timeout_member(member, timeout_minutes, reason)
                return ("timed out" if ok else "timeout failed", ok)
            if punishment == "strip":
                removed = await self.strip_dangerous_roles(guild, member)
                return (f"stripped roles: {', '.join(removed) or 'none'}", True)
            return ("no action", True)
        except (discord.Forbidden, discord.HTTPException) as exc:
            return (f"failed: {exc}", False)

    async def revert_role_grant(self, guild: discord.Guild, member: discord.Member, roles: Iterable[discord.Role]) -> list[str]:
        removed: list[str] = []
        me = guild.me
        for role in roles:
            if role.managed or me.top_role <= role:
                continue
            try:
                await member.remove_roles(role, reason="HAVX+lo SECURTY: unauthorized role grant reverted")
                removed.append(role.name)
            except (discord.Forbidden, discord.HTTPException):
                continue
        return removed
