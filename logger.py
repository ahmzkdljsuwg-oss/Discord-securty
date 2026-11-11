"""Structured security logging to the configured log channel."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import discord

BASE_LOG = logging.getLogger("havx")

COLORS = {
    "info": 0x5865F2,
    "warn": 0xFAA61A,
    "danger": 0xED4245,
    "success": 0x57F287,
    "neutral": 0x99AAB5,
}


def ts(dt: Optional[datetime] = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def build_embed(
    *,
    event: str,
    actor: Optional[str],
    target: Optional[str],
    action: str,
    reason: str,
    success: bool,
    color: str = "info",
    extra: Optional[dict] = None,
) -> discord.Embed:
    embed = discord.Embed(
        title=f"🛡️ {event}",
        color=COLORS.get(color, COLORS["info"]),
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(name="Actor", value=actor or "Unknown", inline=True)
    embed.add_field(name="Target", value=target or "—", inline=True)
    embed.add_field(name="Time", value=ts(), inline=True)
    embed.add_field(name="Action", value=action or "—", inline=False)
    embed.add_field(name="Reason", value=reason or "—", inline=False)
    embed.add_field(
        name="Result",
        value="✅ Success" if success else "❌ Failed",
        inline=True,
    )
    if extra:
        for key, value in extra.items():
            embed.add_field(name=key, value=str(value)[:1000], inline=True)
    embed.set_footer(text="HAVX+lo SECURTY")
    return embed


async def _persist_event(
    bot: discord.Client,
    guild: Optional[discord.Guild],
    event: str,
    actor: Optional[str],
    target: Optional[str],
    action: str,
    reason: str,
    success: bool,
) -> None:
    """Store the event so /audit and /stats can read it back."""
    if guild is None:
        return
    engine = getattr(bot, "engine", None)
    if engine is None:
        return
    try:
        await engine.record_event(guild.id, event, actor, target, action, reason, success)
    except Exception as exc:  # persistence must never break logging
        BASE_LOG.debug("Could not persist event %s: %s", event, exc)


async def send_log(
    bot: discord.Client,
    guild: Optional[discord.Guild],
    *,
    event: str,
    actor: Optional[str] = None,
    target: Optional[str] = None,
    action: str = "—",
    reason: str = "—",
    success: bool = True,
    color: str = "info",
    extra: Optional[dict] = None,
    log_channel_id: Optional[int] = None,
) -> bool:
    """Send a structured log embed. Returns True when delivered."""
    embed = build_embed(
        event=event, actor=actor, target=target, action=action,
        reason=reason, success=success, color=color, extra=extra,
    )
    await _persist_event(bot, guild, event, actor, target, action, reason, success)
    channel = None
    if log_channel_id:
        channel = bot.get_channel(int(log_channel_id))
    if channel is None and guild is not None:
        from config import LOG_CHANNEL_ID, LOG_CHANNEL_FALLBACK
        channel = guild.get_channel(LOG_CHANNEL_ID) or bot.get_channel(LOG_CHANNEL_FALLBACK)
    if channel is None:
        BASE_LOG.warning("Log channel unavailable for event: %s", event)
        return False
    try:
        await channel.send(embed=embed)
        return True
    except (discord.Forbidden, discord.HTTPException) as exc:
        BASE_LOG.warning("Failed to deliver log (%s): %s", event, exc)
        return False


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )
    logging.getLogger("discord").setLevel(logging.WARNING)
