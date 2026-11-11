"""Server lockdown with a durable permission snapshot."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import discord

from database import Database
from logger import send_log

log = logging.getLogger("havx.lockdown")

LOCKED_KEYS = ("send_messages", "add_reactions", "create_public_threads", "create_private_threads", "send_messages_in_threads")


class LockdownManager:
    def __init__(self, bot: discord.Client, db: Database, engine):
        self.bot = bot
        self.db = db
        self.engine = engine

    async def _snapshot(self, guild: discord.Guild) -> dict:
        snap: dict[str, dict] = {}
        for channel in guild.channels:
            if not isinstance(channel, (discord.TextChannel, discord.ForumChannel, discord.VoiceChannel, discord.StageChannel)):
                continue
            ow = channel.overwrites_for(guild.default_role)
            snap[str(channel.id)] = {
                "allow": ow.pair()[0].value if ow.pair()[0].value else None,
                "deny": ow.pair()[1].value if ow.pair()[1].value else None,
            }
        return snap

    async def activate(self, guild: discord.Guild, actor: discord.abc.User, reason: str = "Manual lockdown") -> tuple[bool, str]:
        data = await self.engine.settings(guild)
        existing = await self.db.lockdown_load(guild.id)
        if existing or data.get("lockdown"):
            return False, "Server is already in lockdown."

        snap = await self._snapshot(guild)
        now = datetime.now(timezone.utc).isoformat()
        await self.db.lockdown_save(guild.id, snap, actor.id, now)
        data["lockdown"] = True
        await self.engine.save(guild, data)

        failed = 0
        for channel in guild.channels:
            if not isinstance(channel, (discord.TextChannel, discord.ForumChannel, discord.VoiceChannel, discord.StageChannel)):
                continue
            try:
                ow = channel.overwrites_for(guild.default_role)
                for key in LOCKED_KEYS:
                    setattr(ow, key, False)
                await channel.set_permissions(guild.default_role, overwrite=ow, reason=f"HAVX lockdown by {actor}")
            except (discord.Forbidden, discord.HTTPException):
                failed += 1

        await send_log(
            self.bot, guild,
            event="LOCKDOWN ACTIVATED",
            actor=f"{actor} ({actor.id})",
            target=guild.name,
            action="Locked all channels for @everyone",
            reason=reason,
            success=failed == 0,
            color="danger",
            extra={"Channels locked": len(snap) - failed, "Failures": failed},
            log_channel_id=data.get("log_channel"),
        )
        return True, f"Lockdown activated. Channels locked: {len(snap) - failed}, failures: {failed}."

    async def deactivate(self, guild: discord.Guild, actor: discord.abc.User, reason: str = "Manual unlock") -> tuple[bool, str]:
        data = await self.engine.settings(guild)
        record = await self.db.lockdown_load(guild.id)
        if not record and not data.get("lockdown"):
            return False, "Server is not in lockdown."

        snap = (record or {}).get("snapshot", {})
        restored = 0
        failed = 0
        for channel in guild.channels:
            if not isinstance(channel, (discord.TextChannel, discord.ForumChannel, discord.VoiceChannel, discord.StageChannel)):
                continue
            entry = snap.get(str(channel.id))
            if entry is None:
                continue
            try:
                allow = discord.Permissions(entry.get("allow") or 0)
                deny = discord.Permissions(entry.get("deny") or 0)
                if entry.get("allow") is None and entry.get("deny") is None:
                    await channel.set_permissions(guild.default_role, overwrite=None, reason=f"HAVX unlock by {actor}")
                else:
                    await channel.set_permissions(
                        guild.default_role,
                        overwrite=discord.PermissionOverwrite.from_pair(allow, deny),
                        reason=f"HAVX unlock by {actor}",
                    )
                restored += 1
            except (discord.Forbidden, discord.HTTPException):
                failed += 1

        await self.db.lockdown_delete(guild.id)
        data["lockdown"] = False
        await self.engine.save(guild, data)

        await send_log(
            self.bot, guild,
            event="LOCKDOWN LIFTED",
            actor=f"{actor} ({actor.id})",
            target=guild.name,
            action="Restored original channel permissions",
            reason=reason,
            success=failed == 0,
            color="success",
            extra={"Channels restored": restored, "Failures": failed},
            log_channel_id=data.get("log_channel"),
        )
        return True, f"Lockdown lifted. Channels restored: {restored}, failures: {failed}."

    async def restore_on_startup(self, guild: discord.Guild) -> None:
        """Re-assert lockdown after a restart if one was active."""
        record = await self.db.lockdown_load(guild.id)
        data = await self.engine.settings(guild)
        if not record:
            return
        data["lockdown"] = True
        await self.engine.save(guild, data)
        failed = 0
        for channel in guild.channels:
            if not isinstance(channel, (discord.TextChannel, discord.ForumChannel, discord.VoiceChannel, discord.StageChannel)):
                continue
            try:
                ow = channel.overwrites_for(guild.default_role)
                for key in LOCKED_KEYS:
                    setattr(ow, key, False)
                await channel.set_permissions(guild.default_role, overwrite=ow, reason="HAVX: re-applying lockdown after restart")
            except (discord.Forbidden, discord.HTTPException):
                failed += 1
        log.info("Re-applied lockdown in guild %s (failures=%s)", guild.id, failed)
