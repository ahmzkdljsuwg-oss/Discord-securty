"""HAVX+lo SECURTY — Discord protection bot entry point."""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys

import discord
from discord.ext import commands

import config
import commands as havx_commands
from antilink import ContentFilter
from antinuke import AntiNuke
from antiraid import AntiRaid
from antispam import AntiSpam
from antiwebhook import AntiWebhook
from database import Database
from lockdown import LockdownManager
from logger import send_log, setup_logging
from security import SecurityEngine
from whitelist import WhitelistManager

log = logging.getLogger("havx")


class HavxBot(commands.Bot):
    def __init__(self, intents: discord.Intents):
        super().__init__(
            command_prefix=config.PREFIX,
            intents=intents,
            help_command=None,
            case_insensitive=True,
            allowed_mentions=discord.AllowedMentions(everyone=False, roles=False),
        )
        self.db = Database(config.DATABASE_URL, config.SQLITE_PATH)
        self.engine = SecurityEngine(self, self.db)
        self.whitelist = WhitelistManager(self.db)
        self.lockdown: LockdownManager | None = None
        self.antiraid: AntiRaid | None = None
        self.antispam: AntiSpam | None = None
        self.content_filter: ContentFilter | None = None
        self.antinuke: AntiNuke | None = None
        self.antiwebhook: AntiWebhook | None = None

    async def setup_hook(self) -> None:
        self.lockdown = LockdownManager(self, self.db, self.engine)
        self.antiraid = AntiRaid(self, self.engine, self.lockdown)
        self.antispam = AntiSpam(self, self.engine)
        self.content_filter = ContentFilter(self, self.engine)
        self.antinuke = AntiNuke(self, self.engine)
        self.antiwebhook = AntiWebhook(self, self.engine)
        await havx_commands.setup(self)
        havx_commands.register_toggles(self)

    async def on_ready(self) -> None:
        log.info("Logged in as %s (%s) • guilds=%d", self.user, self.user.id, len(self.guilds))
        await self.change_presence(
            activity=discord.Activity(type=discord.ActivityType.watching, name="over the server • !help"),
            status=discord.Status.online,
        )
        for guild in self.guilds:
            await self.antinuke.prime_cache(guild)
            await self.lockdown.restore_on_startup(guild)
            data = await self.engine.settings(guild)
            if not data.get("log_channel"):
                data["log_channel"] = config.LOG_CHANNEL_ID
                await self.engine.save(guild, data)
        await send_log(
            self, None,
            event="BOT ONLINE",
            actor=f"{self.user} ({self.user.id})",
            target=f"{len(self.guilds)} server(s)",
            action="protection systems armed",
            reason="Startup complete",
            success=True,
            color="success",
            log_channel_id=config.LOG_CHANNEL_ID,
        )

    # ---------------- events ----------------
    async def on_message(self, message: discord.Message) -> None:
        if message.author.bot or message.guild is None:
            return
        try:
            if await self.content_filter.on_message(message):
                return
            if await self.antispam.on_message(message):
                return
        except Exception as exc:  # never let a guard crash the event loop
            log.exception("Message guard error: %s", exc)
        ctx = await self.get_context(message)
        if ctx.valid:
            await self.process_commands(message)

    async def on_member_join(self, member: discord.Member) -> None:
        try:
            if member.bot:
                await self.antinuke.on_bot_join(member)
            else:
                await self.antiraid.on_member_join(member)
        except Exception as exc:
            log.exception("member_join handler error: %s", exc)

    async def on_audit_log_entry_create(self, entry: discord.AuditLogEntry) -> None:
        try:
            await self.antinuke.on_audit_log_entry_create(entry)
            if entry.action in (
                discord.AuditLogAction.webhook_create,
                discord.AuditLogAction.webhook_update,
            ):
                await self.antiwebhook.on_audit_log_entry_create(entry)
        except Exception as exc:
            log.exception("audit handler error: %s", exc)

    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel) -> None:
        try:
            await self.antinuke.on_guild_channel_create(channel)
        except Exception as exc:
            log.exception("channel create handler error: %s", exc)

    async def on_guild_join(self, guild: discord.Guild) -> None:
        data = await self.engine.settings(guild)
        data["log_channel"] = config.LOG_CHANNEL_ID
        await self.engine.save(guild, data)
        await self.antinuke.prime_cache(guild)
        await send_log(
            self, guild,
            event="BOT JOINED SERVER",
            actor=f"{guild.owner} ({guild.owner_id})",
            target=guild.name,
            action="initialized default settings",
            reason="New guild",
            success=True,
            color="success",
            log_channel_id=config.LOG_CHANNEL_ID,
        )

    async def on_command_error(self, ctx: commands.Context, error: Exception) -> None:
        if isinstance(error, commands.CheckFailure):
            return  # owner_only already answered and logged
        if isinstance(error, commands.MissingRequiredArgument):
            await ctx.reply(f"⚠️ Missing argument: `{error.param.name}`", mention_author=False)
            return
        if isinstance(error, commands.BadArgument):
            await ctx.reply(f"⚠️ Invalid argument: {error}", mention_author=False)
            return
        log.exception("Command error: %s", error, exc_info=error)
        await ctx.reply("⚠️ An internal error occurred.", mention_author=False)


def build_intents() -> discord.Intents:
    intents = discord.Intents.default()
    intents.guilds = True
    intents.members = True
    intents.message_content = True
    intents.moderation = True
    return intents


async def amain() -> None:
    setup_logging()
    if not config.DISCORD_TOKEN:
        log.error("DISCORD_BOT_TOKEN is missing. Set it in Railway variables.")
        sys.exit(1)

    bot = HavxBot(build_intents())
    await bot.db.connect()
    if not await bot.db.acquire_instance_lock():
        log.error("Another instance is already running (DB advisory lock held). Exiting.")
        await bot.db.close()
        sys.exit(2)
    log.info("Database backend: %s", bot.db.kind)

    loop = asyncio.get_running_loop()

    async def shutdown() -> None:
        log.info("Shutting down…")
        try:
            await bot.close()
        finally:
            await bot.db.release_instance_lock()
            await bot.db.close()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown()))
        except NotImplementedError:  # pragma: no cover
            pass

    try:
        async with bot:
            await bot.start(config.DISCORD_TOKEN)
    finally:
        await bot.db.release_instance_lock()
        await bot.db.close()


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
