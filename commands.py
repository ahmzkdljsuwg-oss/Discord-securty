"""Prefix (!) commands for HAVX+lo SECURTY."""
from __future__ import annotations

import discord
from discord.ext import commands

import backup
from logger import send_log

PROTECTION_FLAGS = {
    "antiraid": "antiraid",
    "antinuke": "antinuke",
    "antispam": "antispam",
    "antiwebhook": "antiwebhook",
    "antibot": "antibot",
    "antilink": "antilink",
    "antiinvite": "antiinvite",
    "antimassmention": "antimassmention",
    "antiroleabuse": "antiroleabuse",
    "antichanneldelete": "antichanneldelete",
    "serverprotection": "serverprotection",
}


class OwnerOnlyError(commands.CheckFailure):
    pass


def owner_only():
    async def predicate(ctx: commands.Context) -> bool:
        if ctx.guild is None:
            await ctx.reply("This command must be used inside a server.", mention_author=False)
            return False
        if ctx.author.id == ctx.guild.owner_id:
            return True
        engine = ctx.bot.engine
        await send_log(
            ctx.bot, ctx.guild,
            event="UNAUTHORIZED COMMAND ATTEMPT",
            actor=f"{ctx.author} ({ctx.author.id})",
            target=ctx.command.qualified_name,
            action="request rejected, no change applied",
            reason="Protected command used by a non-owner",
            success=False,
            color="danger",
            log_channel_id=(await engine.settings(ctx.guild)).get("log_channel"),
        )
        try:
            await ctx.reply("❌ Owner-only command. This attempt has been logged.", mention_author=False)
        except discord.HTTPException:
            pass
        return False

    return commands.check(predicate)


class HavxCommands(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @property
    def engine(self):
        return self.bot.engine

    # ---------------- public ----------------
    @commands.command(name="help")
    async def help_cmd(self, ctx: commands.Context):
        embed = discord.Embed(
            title="🛡️ HAVX+lo SECURTY — Help",
            description="Owner-only commands are marked 🔒.",
            color=0x5865F2,
        )
        embed.add_field(
            name="General",
            value="`!help` `!ping` `!security` 🔒 `!backup` 🔒",
            inline=False,
        )
        embed.add_field(
            name="Lockdown",
            value="`!lockdown` 🔒 `!unlock` 🔒",
            inline=False,
        )
        embed.add_field(
            name="Whitelist",
            value="`!whitelist @user` 🔒\n`!unwhitelist @user` 🔒\n`!whitelist list` 🔒",
            inline=False,
        )
        embed.add_field(
            name="Protection toggles (owner)",
            value="`!antiraid` `!antinuke` `!antispam` `!antiwebhook` `!antilink` `!antiinvite`\n"
                  "`!antibot` `!antimassmention` `!antiroleabuse` `!antichanneldelete` `!serverprotection`\n"
                  "Add `on`/`off` to set explicitly.",
            inline=False,
        )
        embed.add_field(
            name="Trusted bots (owner)",
            value="`!trust @bot` 🔒 `!untrust @bot` 🔒 `!trusted` 🔒",
            inline=False,
        )
        embed.set_footer(text="HAVX+lo SECURTY • Owner is always the real guild owner")
        await ctx.reply(embed=embed, mention_author=False)

    @commands.command(name="ping")
    async def ping(self, ctx: commands.Context):
        db_kind = getattr(self.bot.db, "kind", "unknown")
        await ctx.reply(
            f"🏓 Pong! Gateway: **{round(self.bot.latency * 1000)}ms** • DB: **{db_kind}**",
            mention_author=False,
        )

    # ---------------- owner: status ----------------
    @commands.command(name="security")
    @owner_only()
    async def security(self, ctx: commands.Context):
        data = await self.engine.settings(ctx.guild)
        lines = []
        for flag in PROTECTION_FLAGS:
            state = "🟢 on" if data.get(flag) else "🔴 off"
            lines.append(f"`{flag}` — {state}")
        lockdown = await self.bot.db.lockdown_load(ctx.guild.id)
        embed = discord.Embed(title="🛡️ Security status", color=0x57F287)
        embed.add_field(name="Modules", value="\n".join(lines), inline=False)
        embed.add_field(name="Lockdown", value="🔒 ACTIVE" if lockdown else "🔓 inactive", inline=True)
        embed.add_field(name="Log channel", value=f"<#{data.get('log_channel')}>", inline=True)
        embed.add_field(name="Owner", value=f"<@{ctx.guild.owner_id}>", inline=True)
        await ctx.reply(embed=embed, mention_author=False)

    # ---------------- owner: lockdown ----------------
    @commands.command(name="lockdown")
    @owner_only()
    async def lockdown_cmd(self, ctx: commands.Context):
        ok, msg = await self.bot.lockdown.activate(ctx.guild, ctx.author, reason="Manual lockdown command")
        await ctx.reply(("🔒 " if ok else "⚠️ ") + msg, mention_author=False)

    @commands.command(name="unlock")
    @owner_only()
    async def unlock_cmd(self, ctx: commands.Context):
        ok, msg = await self.bot.lockdown.deactivate(ctx.guild, ctx.author, reason="Manual unlock command")
        await ctx.reply(("🔓 " if ok else "⚠️ ") + msg, mention_author=False)

    # ---------------- owner: whitelist ----------------
    @commands.group(name="whitelist", invoke_without_command=True)
    @owner_only()
    async def whitelist_group(self, ctx: commands.Context, member: discord.Member = None):
        if member is None:
            await ctx.reply("Usage: `!whitelist @user` or `!whitelist list`", mention_author=False)
            return
        if member.id == ctx.guild.owner_id:
            await ctx.reply("The owner is always trusted.", mention_author=False)
            return
        await self.bot.whitelist.add(ctx.guild.id, member.id, ctx.author.id)
        data = await self.engine.settings(ctx.guild)
        await send_log(
            self.bot, ctx.guild,
            event="WHITELIST ADDED",
            actor=f"{ctx.author} ({ctx.author.id})",
            target=f"{member} ({member.id})",
            action="added to whitelist",
            reason="Owner command",
            success=True,
            color="success",
            log_channel_id=data.get("log_channel"),
        )
        await ctx.reply(f"✅ {member.mention} added to the whitelist.", mention_author=False)

    @whitelist_group.command(name="list")
    @owner_only()
    async def whitelist_list(self, ctx: commands.Context):
        entries = await self.bot.whitelist.list(ctx.guild.id)
        if not entries:
            await ctx.reply("Whitelist is empty.", mention_author=False)
            return
        lines = []
        for user_id, added_by, added_at in entries:
            member = ctx.guild.get_member(user_id)
            name = str(member) if member else f"Unknown ({user_id})"
            lines.append(f"• {name} — added by <@{added_by}> at `{added_at[:19]}`")
        embed = discord.Embed(title="📋 Whitelist", description="\n".join(lines[:40]), color=0x5865F2)
        embed.set_footer(text=f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}")
        await ctx.reply(embed=embed, mention_author=False)

    @commands.command(name="unwhitelist")
    @owner_only()
    async def unwhitelist(self, ctx: commands.Context, member: discord.Member):
        removed = await self.bot.whitelist.remove(ctx.guild.id, member.id)
        data = await self.engine.settings(ctx.guild)
        await send_log(
            self.bot, ctx.guild,
            event="WHITELIST REMOVED",
            actor=f"{ctx.author} ({ctx.author.id})",
            target=f"{member} ({member.id})",
            action="removed from whitelist" if removed else "was not whitelisted",
            reason="Owner command",
            success=removed,
            color="warn",
            log_channel_id=data.get("log_channel"),
        )
        await ctx.reply(
            (f"✅ {member.mention} removed from the whitelist." if removed
             else f"⚠️ {member.mention} was not whitelisted."),
            mention_author=False,
        )

    # ---------------- owner: trusted bots ----------------
    @commands.command(name="trust")
    @owner_only()
    async def trust(self, ctx: commands.Context, bot_member: discord.Member):
        if not bot_member.bot:
            await ctx.reply("That member is not a bot.", mention_author=False)
            return
        await self.bot.whitelist.add_bot(ctx.guild.id, bot_member.id, ctx.author.id)
        await ctx.reply(f"✅ Trusted bot: {bot_member.mention}", mention_author=False)

    @commands.command(name="untrust")
    @owner_only()
    async def untrust(self, ctx: commands.Context, bot_member: discord.Member):
        removed = await self.bot.whitelist.remove_bot(ctx.guild.id, bot_member.id)
        await ctx.reply(
            (f"✅ Removed trusted bot {bot_member.mention}." if removed else "⚠️ Not in trusted bots."),
            mention_author=False,
        )

    @commands.command(name="trusted")
    @owner_only()
    async def trusted(self, ctx: commands.Context):
        ids = await self.bot.whitelist.list_bots(ctx.guild.id)
        await ctx.reply(
            "Trusted bots: " + (", ".join(f"<@{i}>" for i in ids) if ids else "none"),
            mention_author=False,
        )

    # ---------------- owner: toggles ----------------
    async def _toggle(self, ctx: commands.Context, key: str, value: str | None):
        data = await self.engine.settings(ctx.guild)
        if value is None:
            new = not bool(data.get(key))
        else:
            new = value.lower() in {"on", "true", "1", "yes", "enable", "enabled"}
        data[key] = new
        await self.engine.save(ctx.guild, data)
        await send_log(
            self.bot, ctx.guild,
            event=f"{key.upper()} {'ENABLED' if new else 'DISABLED'}",
            actor=f"{ctx.author} ({ctx.author.id})",
            target=key,
            action=f"set to {'on' if new else 'off'}",
            reason="Owner command",
            success=True,
            color="success" if new else "warn",
            log_channel_id=data.get("log_channel"),
        )
        await ctx.reply(f"`{key}` is now **{'ON' if new else 'OFF'}**.", mention_author=False)

    # ---------------- owner: backup ----------------
    @commands.command(name="backup")
    @owner_only()
    async def backup_cmd(self, ctx: commands.Context):
        file = backup.dump(ctx.guild)
        data = await self.engine.settings(ctx.guild)
        await ctx.reply("📦 Server structure backup attached.", file=file, mention_author=False)
        await send_log(
            self.bot, ctx.guild,
            event="BACKUP EXPORTED",
            actor=f"{ctx.author} ({ctx.author.id})",
            target=ctx.guild.name,
            action="structure exported to JSON",
            reason="Owner command",
            success=True,
            color="neutral",
            log_channel_id=data.get("log_channel"),
        )


async def setup(bot: commands.Bot):
    await bot.add_cog(HavxCommands(bot))


def register_toggles(bot: commands.Bot):
    """Register the per-system toggle commands directly on the bot guild-independently."""
    cog = bot.get_cog("HavxCommands")
    for name, key in PROTECTION_FLAGS.items():
        async def _toggle_cmd(ctx: commands.Context, value: str = None, _key: str = key):
            if ctx.guild is None:
                await ctx.reply("This command must be used inside a server.", mention_author=False)
                return
            if ctx.author.id != ctx.guild.owner_id:
                data = await cog.engine.settings(ctx.guild)
                await send_log(
                    cog.bot, ctx.guild,
                    event="UNAUTHORIZED COMMAND ATTEMPT",
                    actor=f"{ctx.author} ({ctx.author.id})",
                    target=_key,
                    action="request rejected, no change applied",
                    reason="Protected toggle used by a non-owner",
                    success=False, color="danger",
                    log_channel_id=data.get("log_channel"),
                )
                await ctx.reply("❌ Owner-only command. This attempt has been logged.", mention_author=False)
                return
            await cog._toggle(ctx, _key, value)

        _toggle_cmd.__name__ = f"toggle_{name}"
        bot.add_command(commands.command(name=name, help=f"Toggle {key} protection (owner only)")(_toggle_cmd))
