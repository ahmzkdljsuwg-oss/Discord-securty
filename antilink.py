"""Content filters: links, Discord invites, and mass mentions."""
from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

import discord

from config import LINK_RE, INVITE_RE
from logger import send_log

log = logging.getLogger("havx.antilink")

LINK_PATTERN = re.compile(LINK_RE, re.IGNORECASE)
INVITE_PATTERN = re.compile(INVITE_RE, re.IGNORECASE)


def _domain_allowed(url: str, allowed: list[str]) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return False
    return any(host == d or host.endswith("." + d) for d in (x.lower().strip() for x in allowed))


class ContentFilter:
    def __init__(self, bot: discord.Client, engine):
        self.bot = bot
        self.engine = engine

    async def on_message(self, message: discord.Message) -> bool:
        """Handle content rules. Returns True when the message was actioned."""
        if message.guild is None or message.author.bot or not message.content:
            return False
        guild = message.guild
        data = await self.engine.settings(guild)
        member = message.author
        if await self.engine.is_exempt(guild, member):
            return False

        content = message.content

        # mass mention
        if data.get("antimassmention"):
            limit = int(data.get("mention_limit", 5))
            mentions = len(message.mentions) + len(message.role_mentions)
            if mentions >= limit or message.mention_everyone:
                return await self._handle(
                    message, guild, data, member,
                    event="ANTI-MASS MENTION",
                    reason=f"{mentions} mentions (limit {limit})" + (" + @everyone" if message.mention_everyone else ""),
                )

        # invite links (checked before generic links)
        if data.get("antiinvite") and INVITE_PATTERN.search(content):
            return await self._handle(
                message, guild, data, member,
                event="ANTI-INVITE",
                reason="Discord invite link detected",
            )

        # generic links (allowed_domains always exempt, even when all links are blocked)
        if data.get("antilink"):
            urls = LINK_PATTERN.findall(content)
            if urls:
                allowed = data.get("allowed_domains", []) or []
                blocked = [u for u in urls if not _domain_allowed(u, allowed)]
                if blocked and data.get("block_links_all", True):
                    return await self._handle(
                        message, guild, data, member,
                        event="ANTI-LINK",
                        reason=f"blocked link(s): {', '.join(blocked)[:200]}",
                    )
        return False

    async def _handle(self, message, guild, data, member, *, event: str, reason: str) -> bool:
        deleted = True
        try:
            await message.delete()
        except (discord.Forbidden, discord.HTTPException):
            deleted = False
        desc, ok = await self.engine.punish(
            guild, member, "timeout", reason=f"{event}: {reason}", timeout_minutes=5
        )
        await send_log(
            self.bot, guild,
            event=event,
            actor=f"{member} ({member.id})",
            target=f"#{message.channel}" if getattr(message, "channel", None) else "—",
            action=f"message deleted ({'ok' if deleted else 'failed'}); {desc}",
            reason=reason,
            success=deleted,
            color="warn",
            log_channel_id=data.get("log_channel"),
        )
        return True
