"""Anti-Raid: detect join bursts and trigger lockdown + punishment."""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque

import discord

from logger import send_log

log = logging.getLogger("havx.antiraid")


class AntiRaid:
    def __init__(self, bot: discord.Client, engine, lockdown):
        self.bot = bot
        self.engine = engine
        self.lockdown = lockdown
        self._joins: dict[int, deque] = defaultdict(deque)
        self._handling: set[int] = set()

    async def on_member_join(self, member: discord.Member) -> None:
        guild = member.guild
        data = await self.engine.settings(guild)
        if not data.get("antiraid") or data.get("lockdown"):
            return
        if member.bot:
            return

        now = time.monotonic()
        window = int(data.get("raid_join_seconds", 10))
        dq = self._joins[guild.id]
        dq.append((now, member.id))
        while dq and now - dq[0][0] > window:
            dq.popleft()

        threshold = int(data.get("raid_join_count", 6))
        if len(dq) < threshold:
            return
        if guild.id in self._handling:
            return
        self._handling.add(guild.id)
        try:
            recent_ids = [uid for _, uid in dq]
            punishment = str(data.get("raid_punishment", "kick")).lower()
            punished = 0
            failed = 0
            for uid in recent_ids:
                target = guild.get_member(uid)
                if target is None:
                    continue
                if await self.engine.is_exempt(guild, target):
                    continue
                desc, ok = await self.engine.punish(
                    guild, target, punishment, reason=f"Anti-Raid: {len(recent_ids)} joins in {window}s"
                )
                if ok:
                    punished += 1
                else:
                    failed += 1

            ok_lock, lock_msg = await self.lockdown.activate(
                guild, self.bot.user, reason=f"Anti-Raid triggered: {len(recent_ids)} joins in {window}s"
            )

            await send_log(
                self.bot, guild,
                event="ANTI-RAID TRIGGERED",
                actor="mass join detection",
                target=f"{len(recent_ids)} new members",
                action=f"{punishment} applied to {punished} joined members; lockdown {'engaged' if ok_lock else 'failed'}",
                reason=f"{len(recent_ids)} joins within {window}s",
                success=ok_lock and failed == 0,
                color="danger",
                extra={"Punished": punished, "Failed": failed, "Lockdown": lock_msg},
                log_channel_id=data.get("log_channel"),
            )
        finally:
            self._handling.discard(guild.id)
