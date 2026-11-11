"""Anti-Nuke: audit-log driven protection against destructive admin actions."""
from __future__ import annotations

import logging
from typing import Optional

import discord

from logger import send_log

log = logging.getLogger("havx.antinuke")

ADMIN_KEYS = ("administrator", "manage_guild", "manage_roles", "manage_channels", "manage_webhooks", "ban_members", "kick_members")


class AntiNuke:
    def __init__(self, bot: discord.Client, engine):
        self.bot = bot
        self.engine = engine
        # (guild_id, channel_id) -> snapshot used to restore deleted channels
        self._channel_cache: dict[tuple[int, int], dict] = {}
        self._recent: set[tuple[int, int, str]] = set()

    # ---------------- channel cache ----------------
    @staticmethod
    def _snap(channel: discord.abc.GuildChannel) -> dict:
        return {
            "name": channel.name,
            "type": channel.type,
            "category_id": getattr(channel.category, "id", None) if getattr(channel, "category", None) else None,
            "position": getattr(channel, "position", 0),
            "topic": getattr(channel, "topic", None),
            "nsfw": getattr(channel, "nsfw", False),
            "overwrites": list(channel.overwrites),
            "slowmode": getattr(channel, "slowmode_delay", 0),
        }

    async def prime_cache(self, guild: discord.Guild) -> None:
        for channel in guild.channels:
            if isinstance(channel, (discord.TextChannel, discord.VoiceChannel, discord.CategoryChannel, discord.StageChannel, discord.ForumChannel)):
                self._channel_cache[(guild.id, channel.id)] = self._snap(channel)

    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel) -> None:
        if isinstance(channel, (discord.TextChannel, discord.VoiceChannel, discord.CategoryChannel, discord.StageChannel, discord.ForumChannel)):
            self._channel_cache[(channel.guild.id, channel.id)] = self._snap(channel)

    # ---------------- helpers ----------------
    def _dedupe(self, guild_id: int, target_id: int, tag: str) -> bool:
        key = (guild_id, target_id, tag)
        if key in self._recent:
            return False
        self._recent.add(key)
        if len(self._recent) > 2000:
            self._recent.clear()
        return True

    async def _punish_actor(self, guild, actor, data, event: str, target: str, reason: str) -> tuple[str, bool]:
        punishment = str(data.get("nuke_punishment", "strip")).lower()
        member = guild.get_member(actor.id) if actor else None
        if member is None and actor is not None:
            try:
                member = await guild.fetch_member(actor.id)
            except (discord.NotFound, discord.HTTPException):
                member = None
        desc, ok = await self.engine.punish(guild, member, punishment, reason=reason)
        await send_log(
            self.bot, guild,
            event=event,
            actor=f"{actor} ({actor.id})" if actor else "unknown (audit log)",
            target=target,
            action=f"punishment: {desc}",
            reason=reason,
            success=ok,
            color="danger",
            log_channel_id=data.get("log_channel"),
        )
        return desc, ok

    # ---------------- main dispatcher ----------------
    async def on_audit_log_entry_create(self, entry: discord.AuditLogEntry) -> None:
        guild = entry.guild
        actor = entry.user
        # ignore our own actions and trusted identities
        if actor is not None and actor.id == self.bot.user.id:
            return
        data = await self.engine.settings(guild)
        if actor is not None and await self.engine.is_trusted_actor(guild, actor):
            return

        action = entry.action
        A = discord.AuditLogAction

        if action == A.channel_delete and data.get("antinuke"):
            if not self._dedupe(guild.id, getattr(entry.target, "id", 0), "chdel"):
                return
            if data.get("antichanneldelete") and data.get("restore_channels", True):
                await self._restore_channel(guild, entry, data)
            await self._punish_actor(guild, actor, data, "ANTI-NUKE • CHANNEL DELETE",
                                     str(entry.target), f"Unauthorized channel delete: {entry.target}")

        elif action == A.role_delete and data.get("antinuke"):
            if not self._dedupe(guild.id, getattr(entry.target, "id", 0), "roledel"):
                return
            await self._punish_actor(guild, actor, data, "ANTI-NUKE • ROLE DELETE",
                                     str(entry.target), f"Unauthorized role delete: {entry.target}")

        elif action == A.channel_create and data.get("antinuke"):
            if self._channel_is_suspicious(entry):
                await self._punish_actor(guild, actor, data, "ANTI-NUKE • CHANNEL CREATE",
                                         str(entry.target), "Mass/suspicious channel creation")

        elif action == A.role_create and data.get("antinuke"):
            if self._role_is_dangerous(entry):
                await self._punish_actor(guild, actor, data, "ANTI-NUKE • DANGEROUS ROLE",
                                         str(entry.target), "Created role with dangerous permissions")

        elif action == A.member_role_update and data.get("antiroleabuse"):
            await self._handle_role_grant(guild, entry, actor, data)

        elif action in (A.ban_add, A.kick) and data.get("antinuke"):
            verb = "ban" if action == A.ban_add else "kick"
            if not self._dedupe(guild.id, getattr(entry.target, "id", 0), verb):
                return
            await self._punish_actor(guild, actor, data, f"ANTI-NUKE • MASS {verb.upper()}",
                                     str(entry.target), f"Unauthorized {verb} of {entry.target}")

        elif action in (A.message_delete, A.message_bulk_delete) and data.get("antinuke"):
            # message bulk delete is handled with its purge counter in main.py
            return

        elif action == A.guild_update and data.get("serverprotection"):
            await self._handle_server_update(guild, entry, actor, data)

    # ---------------- specific handlers ----------------
    def _channel_is_suspicious(self, entry: discord.AuditLogEntry) -> bool:
        name = getattr(entry.target, "name", "") or ""
        return name.lower() in {"nuked", "hacked", "raid", "bye", "owned", "fucked"} or name.startswith("!")

    def _role_is_dangerous(self, entry: discord.AuditLogEntry) -> bool:
        target = entry.target
        perms = getattr(target, "permissions", None)
        if perms is None:
            return False
        return getattr(perms, "administrator", False)

    async def _handle_role_grant(self, guild, entry: discord.AuditLogEntry, actor, data) -> None:
        member = entry.target
        if not isinstance(member, discord.Member):
            return
        before_ids = {r.id for r in getattr(entry.before, "roles", [])}
        after_roles = list(getattr(entry.after, "roles", []))
        added = [r for r in after_roles if r.id not in before_ids]
        dangerous = [r for r in added if any(getattr(r.permissions, k, False) for k in ADMIN_KEYS)]
        if not dangerous:
            return
        if not actor or not self._dedupe(guild.id, member.id, "rolegrant"):
            return
        removed = await self.engine.revert_role_grant(guild, member, dangerous)
        desc, ok = await self.engine.punish(
            guild, guild.get_member(actor.id), str(data.get("nuke_punishment", "strip")).lower(),
            reason="Anti-Role Abuse: unauthorized dangerous role grant",
        )
        await send_log(
            self.bot, guild,
            event="ANTI-ROLE ABUSE",
            actor=f"{actor} ({actor.id})",
            target=f"{member} ({member.id})",
            action=f"reverted roles: {', '.join(removed) or 'none'}; actor punishment: {desc}",
            reason=f"granted dangerous role(s): {', '.join(r.name for r in dangerous)}",
            success=bool(removed),
            color="danger",
            log_channel_id=data.get("log_channel"),
        )

    async def _handle_server_update(self, guild, entry: discord.AuditLogEntry, actor, data) -> None:
        changes = []
        if hasattr(entry, "changes"):
            for change in entry.changes:
                changes.append(change.attr if hasattr(change, "attr") else str(change))
        await send_log(
            self.bot, guild,
            event="SERVER PROTECTION • GUILD UPDATE",
            actor=f"{actor} ({actor.id})" if actor else "unknown",
            target=guild.name,
            action="logged; no automatic revert",
            reason=f"guild settings changed: {', '.join(changes) or 'unspecified'}",
            success=True,
            color="warn",
            log_channel_id=data.get("log_channel"),
        )

    async def _restore_channel(self, guild, entry: discord.AuditLogEntry, data) -> None:
        target = entry.target
        cid = getattr(target, "id", None)
        snap = self._channel_cache.get((guild.id, cid)) if cid else None
        name = (snap or {}).get("name") or getattr(target, "name", "restored-channel")
        ctype = (snap or {}).get("type") or getattr(target, "type", discord.ChannelType.text)
        category = guild.get_channel((snap or {}).get("category_id") or 0)
        try:
            if ctype == discord.ChannelType.voice:
                new = await guild.create_voice_channel(name=name, category=category, reason="HAVX: restore deleted channel")
            elif ctype == discord.ChannelType.stage_voice:
                new = await guild.create_stage_channel(name=name, category=category, reason="HAVX: restore deleted channel")
            elif ctype == discord.ChannelType.category:
                new = await guild.create_category(name=name, reason="HAVX: restore deleted category")
            elif ctype == discord.ChannelType.forum:
                new = await guild.create_forum(name=name, category=category, reason="HAVX: restore deleted forum")
            else:
                new = await guild.create_text_channel(
                    name=name, category=category, topic=(snap or {}).get("topic"),
                    nsfw=(snap or {}).get("nsfw", False),
                    slowmode_delay=(snap or {}).get("slowmode", 0) or 0,
                    reason="HAVX: restore deleted channel",
                )
            if snap and snap.get("overwrites"):
                for target_obj, ow in snap["overwrites"]:
                    try:
                        await new.set_permissions(target_obj, overwrite=ow, reason="HAVX: restore permissions")
                    except (discord.Forbidden, discord.HTTPException):
                        continue
            self._channel_cache[(guild.id, new.id)] = self._snap(new)
            await send_log(
                self.bot, guild,
                event="CHANNEL RESTORED",
                actor="HAVX+lo SECURTY",
                target=f"#{name}",
                action="recreated deleted channel with original settings",
                reason="Auto-restore after unauthorized deletion",
                success=True,
                color="success",
                log_channel_id=data.get("log_channel"),
            )
        except (discord.Forbidden, discord.HTTPException) as exc:
            await send_log(
                self.bot, guild,
                event="CHANNEL RESTORE FAILED",
                actor="HAVX+lo SECURTY",
                target=f"#{name}",
                action="recreation failed",
                reason=str(exc),
                success=False,
                color="danger",
                log_channel_id=data.get("log_channel"),
            )

    # ---------------- anti-bot ----------------
    async def on_bot_join(self, member: discord.Member) -> None:
        guild = member.guild
        data = await self.engine.settings(guild)
        if not data.get("antibot") or not member.bot:
            return
        if member.id == self.bot.user.id:
            return
        if await self.engine.is_trusted_bot(guild, member.id):
            return
        kicked = True
        try:
            await member.kick(reason="Anti-Bot: unauthorized bot")
        except (discord.Forbidden, discord.HTTPException):
            kicked = False
        await send_log(
            self.bot, guild,
            event="ANTI-BOT",
            actor="HAVX+lo SECURTY",
            target=f"{member} ({member.id})",
            action="bot kicked" if kicked else "kick failed",
            reason="Unauthorized bot added to server",
            success=kicked,
            color="danger",
            log_channel_id=data.get("log_channel"),
        )
