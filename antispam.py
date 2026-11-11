"""Anti-Spam: repeated messages, message floods and duplicate content."""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque

import discord

from logger import send_log

log = logging.getLogger("havx.antispam")


class AntiSpam:
    def __init__(self, bot: discord.Client, engine):
        self.bot = bot
        self.engine = engine
        self._history: dict[tuple[int, int], deque] = defaultdict(deque)

    async def on_message(self, message: discord.Message) -> bool:
        if message.guild is None or message.author.bot or not message.content:
            return False
        guild = message.guild
        data = await self.engine.settings(guild)
        if not data.get("antispam"):
            return False
        member = message.author
        if await self.engine.is_exempt(guild, member):
            return False

        window = int(data.get("spam_seconds", 5))
        limit = int(data.get("spam_count", 5))
        now = time.monotonic()
        key = (guild.id, member.id)
        dq = self._history[key]
        dq.append((now, message.content.strip().lower()))
        while dq and now - dq[0][0] > window:
            dq.popleft()

        duplicate = sum(1 for _, text in dq if text == message.content.strip().lower())
        is_flood = len(dq) >= limit
        if not is_flood and duplicate < 3:
            return False

        punishment = str(data.get("spam_punishment", "timeout")).lower()
        timeout_minutes = int(data.get("spam_timeout_minutes", 10))

        delete_ok = True
        try:
            await message.delete()
        except (discord.Forbidden, discord.HTTPException):
            delete_ok = False

        # clear history so the next burst is measured fresh
        dq.clear()
        desc, ok = await self.engine.punish(
            guild, member, punishment,
            reason=f"Anti-Spam: {len(dq) or limit} messages / duplicate flood in {window}s",
            timeout_minutes=timeout_minutes,
        )
        await send_log(
            self.bot, guild,
            event="ANTI-SPAM",
            actor=f"{member} ({member.id})",
            target=f"#{message.channel}",
            action=f"message deleted ({'ok' if delete_ok else 'failed'}); punishment: {desc}",
            reason=f"flood/duplicate content ({duplicate} repeats, limit {limit}/{window}s)",
            success=ok and delete_ok,
            color="warn",
            log_channel_id=data.get("log_channel"),
        )
        return True
