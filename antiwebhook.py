"""Anti-Webhook: remove webhooks created by unauthorized users."""
from __future__ import annotations

import logging

import discord

from logger import send_log

log = logging.getLogger("havx.antiwebhook")


class AntiWebhook:
    def __init__(self, bot: discord.Client, engine):
        self.bot = bot
        self.engine = engine

    async def on_audit_log_entry_create(self, entry: discord.AuditLogEntry) -> None:
        if entry.action != discord.AuditLogAction.webhook_create:
            return
        guild = entry.guild
        data = await self.engine.settings(guild)
        if not data.get("antiwebhook"):
            return
        actor = entry.user
        if actor is not None and (actor.id == self.bot.user.id or await self.engine.is_trusted_actor(guild, actor)):
            return

        deleted = 0
        failed = 0
        try:
            hooks = await guild.webhooks()
            for hook in hooks:
                if hook.user is not None and hook.user.id == self.bot.user.id:
                    continue
                if hook.id != getattr(entry.target, "id", None):
                    continue
                try:
                    await hook.delete(reason="Anti-Webhook: unauthorized webhook")
                    deleted += 1
                except (discord.Forbidden, discord.HTTPException):
                    failed += 1
        except (discord.Forbidden, discord.HTTPException) as exc:
            log.warning("webhooks fetch failed: %s", exc)

        if actor is not None:
            await self.engine.punish(
                guild, guild.get_member(actor.id), "strip",
                reason="Anti-Webhook: unauthorized webhook creation",
            )

        await send_log(
            self.bot, guild,
            event="ANTI-WEBHOOK",
            actor=f"{actor} ({actor.id})" if actor else "unknown (audit log)",
            target=f"webhook {getattr(entry.target, 'name', entry.target)}",
            action=f"deleted {deleted} webhook(s), {failed} failed",
            reason="Unauthorized webhook creation",
            success=failed == 0 and deleted > 0,
            color="danger",
            log_channel_id=data.get("log_channel"),
        )
