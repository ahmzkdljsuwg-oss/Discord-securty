"""Discord slash commands for HAVX+lo SECURTY.

Every command is owner-only (checked against guild.owner_id) and calls the same
live protection engine used by the prefix commands — no stubs.
"""
from __future__ import annotations

import discord
from discord import app_commands
from discord.ext import commands

import backup
from commands import PROTECTION_FLAGS
from logger import send_log

EMPTY = "\u200b"


class SlashCommands(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self.tree = bot.tree

    # ---------------- helpers ----------------
    @property
    def engine(self):
        return self.bot.engine

    async def _guard(self, interaction: discord.Interaction) -> bool:
        if interaction.guild is None:
            await interaction.response.send_message(
                "This command must be used inside a server.", ephemeral=True
            )
            return False
        if interaction.user.id == interaction.guild.owner_id:
            return True
        data = await self.engine.settings(interaction.guild)
        await send_log(
            self.bot, interaction.guild,
            event="UNAUTHORIZED COMMAND ATTEMPT",
            actor=f"{interaction.user} ({interaction.user.id})",
            target=f"/{interaction.command.name if interaction.command else 'unknown'}",
            action="request rejected, no change applied",
            reason="Slash command used by a non-owner",
            success=False,
            color="danger",
            log_channel_id=data.get("log_channel"),
        )
        await interaction.response.send_message(
            "❌ Owner-only command. This attempt has been logged.", ephemeral=True
        )
        return False

    async def _toggle(self, interaction: discord.Interaction, key: str, enabled: bool | None):
        data = await self.engine.settings(interaction.guild)
        new = (not bool(data.get(key))) if enabled is None else enabled
        data[key] = new
        await self.engine.save(interaction.guild, data)
        await send_log(
            self.bot, interaction.guild,
            event=f"{key.upper()} {'ENABLED' if new else 'DISABLED'}",
            actor=f"{interaction.user} ({interaction.user.id})",
            target=key,
            action=f"set to {'on' if new else 'off'} via slash command",
            reason="Owner slash command",
            success=True,
            color="success" if new else "warn",
            log_channel_id=data.get("log_channel"),
        )
        await interaction.response.send_message(
            f"`{key}` is now **{'ON' if new else 'OFF'}**.", ephemeral=True
        )

    async def _status(self, guild: discord.Guild) -> discord.Embed:
        data = await self.engine.settings(guild)
        lines = [f"`{flag}` — {'🟢 on' if data.get(flag) else '🔴 off'}" for flag in PROTECTION_FLAGS]
        lockdown = await self.bot.db.lockdown_load(guild.id)
        embed = discord.Embed(title="🛡️ Security status", color=0x57F287)
        embed.add_field(name="Modules", value="\n".join(lines), inline=False)
        embed.add_field(name="Lockdown", value="🔒 ACTIVE" if lockdown else "🔓 inactive", inline=True)
        embed.add_field(name="Panic mode", value="🚨 ON" if data.get("panic") else "off", inline=True)
        embed.add_field(name="Log channel", value=f"<#{data.get('log_channel')}>", inline=True)
        embed.add_field(name="Owner", value=f"<@{guild.owner_id}>", inline=True)
        return embed

    # ---------------- whitelist ----------------
    @app_commands.command(name="havx", description="Add a member to the whitelist (owner only)")
    @app_commands.describe(member="Member to add to the whitelist")
    async def havx(self, interaction: discord.Interaction, member: discord.Member):
        if not await self._guard(interaction):
            return
        if member.id == interaction.guild.owner_id:
            await interaction.response.send_message("The owner is always trusted.", ephemeral=True)
            return
        if member.bot:
            await interaction.response.send_message(
                "Use `!trust @bot` for bots — whitelisting a bot would not protect it.",
                ephemeral=True,
            )
            return
        await self.bot.whitelist.add(interaction.guild.id, member.id, interaction.user.id)
        data = await self.engine.settings(interaction.guild)
        await send_log(
            self.bot, interaction.guild,
            event="WHITELIST ADDED",
            actor=f"{interaction.user} ({interaction.user.id})",
            target=f"{member} ({member.id})",
            action="added to whitelist via /havx",
            reason="Owner slash command",
            success=True,
            color="success",
            log_channel_id=data.get("log_channel"),
        )
        await interaction.response.send_message(
            f"✅ {member.mention} added to the whitelist.", ephemeral=True
        )

    @app_commands.command(name="abdo", description="Remove a member from the whitelist (owner only)")
    @app_commands.describe(member="Member to remove from the whitelist")
    async def abdo(self, interaction: discord.Interaction, member: discord.Member):
        if not await self._guard(interaction):
            return
        removed = await self.bot.whitelist.remove(interaction.guild.id, member.id)
        data = await self.engine.settings(interaction.guild)
        await send_log(
            self.bot, interaction.guild,
            event="WHITELIST REMOVED",
            actor=f"{interaction.user} ({interaction.user.id})",
            target=f"{member} ({member.id})",
            action="removed from whitelist via /abdo" if removed else "was not whitelisted",
            reason="Owner slash command",
            success=removed,
            color="warn",
            log_channel_id=data.get("log_channel"),
        )
        await interaction.response.send_message(
            (f"✅ {member.mention} removed from the whitelist." if removed
             else f"⚠️ {member.mention} was not whitelisted."),
            ephemeral=True,
        )

    @app_commands.command(name="whitelist", description="Show the whitelist (owner only)")
    async def whitelist_cmd(self, interaction: discord.Interaction):
        if not await self._guard(interaction):
            return
        entries = await self.bot.whitelist.list(interaction.guild.id)
        if not entries:
            await interaction.response.send_message("Whitelist is empty.", ephemeral=True)
            return
        lines = []
        for user_id, added_by, added_at in entries[:40]:
            member = interaction.guild.get_member(user_id)
            name = str(member) if member else f"Unknown ({user_id})"
            lines.append(f"• {name} — added by <@{added_by}> at `{added_at[:19]}`")
        embed = discord.Embed(title="📋 Whitelist", description="\n".join(lines), color=0x5865F2)
        embed.set_footer(text=f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # ---------------- status / lockdown ----------------
    @app_commands.command(name="security", description="Show protection status (owner only)")
    async def security(self, interaction: discord.Interaction):
        if not await self._guard(interaction):
            return
        await interaction.response.send_message(embed=await self._status(interaction.guild), ephemeral=True)

    @app_commands.command(name="lockdown", description="Lock the server down (owner only)")
    async def lockdown(self, interaction: discord.Interaction):
        if not await self._guard(interaction):
            return
        await interaction.response.defer(ephemeral=True)
        ok, msg = await self.bot.lockdown.activate(
            interaction.guild, interaction.user, reason="Slash lockdown command"
        )
        await interaction.followup.send(("🔒 " if ok else "⚠️ ") + msg, ephemeral=True)

    @app_commands.command(name="unlock", description="Lift the lockdown (owner only)")
    async def unlock(self, interaction: discord.Interaction):
        if not await self._guard(interaction):
            return
        await interaction.response.defer(ephemeral=True)
        ok, msg = await self.bot.lockdown.deactivate(
            interaction.guild, interaction.user, reason="Slash unlock command"
        )
        await interaction.followup.send(("🔓 " if ok else "⚠️ ") + msg, ephemeral=True)

    @app_commands.command(name="panic", description="Toggle emergency mode: all protections + lockdown (owner only)")
    async def panic(self, interaction: discord.Interaction):
        if not await self._guard(interaction):
            return
        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        data = await self.engine.settings(guild)
        if data.get("panic"):
            ok, msg = await self.engine.restore_settings(guild, label="panic-before")
            data = await self.engine.settings(guild)
            data["panic"] = False
            await self.engine.save(guild, data)
            await self.bot.db.backup_delete_label(guild.id, "panic-before")
            unlocked = ""
            if await self.bot.db.lockdown_load(guild.id):
                _, unlocked = await self.bot.lockdown.deactivate(
                    guild, interaction.user, reason="Panic mode stood down"
                )
            await send_log(
                self.bot, guild,
                event="PANIC MODE DEACTIVATED",
                actor=f"{interaction.user} ({interaction.user.id})",
                target=guild.name,
                action=f"settings restored; lockdown: {unlocked or 'not active'}",
                reason="Owner stood down emergency mode",
                success=ok,
                color="success" if ok else "warn",
                log_channel_id=data.get("log_channel"),
            )
            await interaction.followup.send(
                ("🚨 Panic mode OFF. " + msg) if ok else ("⚠️ Panic mode off but restore failed: " + msg),
                ephemeral=True,
            )
            return

        await self.engine.snapshot_settings(guild, interaction.user.id, label="panic-before")
        data = await self.engine.settings(guild)
        for flag in PROTECTION_FLAGS:
            data[flag] = True
        data["panic"] = True
        await self.engine.save(guild, data)
        ok, msg = await self.bot.lockdown.activate(
            guild, interaction.user, reason="Panic mode activated"
        )
        await send_log(
            self.bot, guild,
            event="PANIC MODE ACTIVATED",
            actor=f"{interaction.user} ({interaction.user.id})",
            target=guild.name,
            action=f"all protections enabled; lockdown: {msg}",
            reason="Owner emergency mode",
            success=ok,
            color="danger",
            log_channel_id=data.get("log_channel"),
        )
        await interaction.followup.send(
            f"🚨 Panic mode ON — all protections enabled, lockdown: {msg}", ephemeral=True
        )

    # ---------------- toggles ----------------
    @app_commands.command(name="antinuke", description="Toggle anti-nuke protection (owner only)")
    @app_commands.describe(enabled="on / off — leave empty to flip")
    async def antinuke(self, interaction: discord.Interaction, enabled: bool | None = None):
        if not await self._guard(interaction):
            return
        await self._toggle(interaction, "antinuke", enabled)

    @app_commands.command(name="antiraid", description="Toggle anti-raid protection (owner only)")
    @app_commands.describe(enabled="on / off — leave empty to flip")
    async def antiraid(self, interaction: discord.Interaction, enabled: bool | None = None):
        if not await self._guard(interaction):
            return
        await self._toggle(interaction, "antiraid", enabled)

    @app_commands.command(name="antispam", description="Toggle anti-spam protection (owner only)")
    @app_commands.describe(enabled="on / off — leave empty to flip")
    async def antispam(self, interaction: discord.Interaction, enabled: bool | None = None):
        if not await self._guard(interaction):
            return
        await self._toggle(interaction, "antispam", enabled)

    @app_commands.command(name="antiwebhook", description="Toggle anti-webhook protection (owner only)")
    @app_commands.describe(enabled="on / off — leave empty to flip")
    async def antiwebhook(self, interaction: discord.Interaction, enabled: bool | None = None):
        if not await self._guard(interaction):
            return
        await self._toggle(interaction, "antiwebhook", enabled)

    @app_commands.command(name="antibot", description="Toggle anti-bot protection (owner only)")
    @app_commands.describe(enabled="on / off — leave empty to flip")
    async def antibot(self, interaction: discord.Interaction, enabled: bool | None = None):
        if not await self._guard(interaction):
            return
        await self._toggle(interaction, "antibot", enabled)

    @app_commands.command(name="antilink", description="Toggle link filtering (owner only)")
    @app_commands.describe(enabled="on / off — leave empty to flip")
    async def antilink(self, interaction: discord.Interaction, enabled: bool | None = None):
        if not await self._guard(interaction):
            return
        await self._toggle(interaction, "antilink", enabled)

    # ---------------- backup / restore ----------------
    @app_commands.command(name="backup", description="Save a server settings backup (owner only)")
    async def backup_cmd(self, interaction: discord.Interaction):
        if not await self._guard(interaction):
            return
        await interaction.response.defer(ephemeral=True)
        backup_id = await self.engine.snapshot_settings(interaction.guild, interaction.user.id, label="manual")
        file = backup.dump(interaction.guild)
        data = await self.engine.settings(interaction.guild)
        await send_log(
            self.bot, interaction.guild,
            event="BACKUP CREATED",
            actor=f"{interaction.user} ({interaction.user.id})",
            target=interaction.guild.name,
            action=f"settings + whitelist saved as `{backup_id}`; structure exported",
            reason="Owner slash command",
            success=True,
            color="neutral",
            log_channel_id=data.get("log_channel"),
        )
        await interaction.followup.send(
            f"📦 Backup `{backup_id}` saved.\nStructure export attached.",
            file=file, ephemeral=True,
        )

    @app_commands.command(name="restore", description="Restore the latest saved backup (owner only)")
    async def restore(self, interaction: discord.Interaction):
        if not await self._guard(interaction):
            return
        await interaction.response.defer(ephemeral=True)
        ok, msg = await self.engine.restore_settings(interaction.guild)
        data = await self.engine.settings(interaction.guild)
        await send_log(
            self.bot, interaction.guild,
            event="BACKUP RESTORED",
            actor=f"{interaction.user} ({interaction.user.id})",
            target=interaction.guild.name,
            action=msg,
            reason="Owner slash command",
            success=ok,
            color="success" if ok else "warn",
            log_channel_id=data.get("log_channel"),
        )
        await interaction.followup.send(("✅ " if ok else "⚠️ ") + msg, ephemeral=True)

    # ---------------- audit / stats ----------------
    @app_commands.command(name="audit", description="Show recent suspicious events (owner only)")
    async def audit(self, interaction: discord.Interaction):
        if not await self._guard(interaction):
            return
        events = await self.bot.db.event_list(interaction.guild.id, limit=15)
        if not events:
            await interaction.response.send_message("No events recorded yet.", ephemeral=True)
            return
        embed = discord.Embed(title="🔎 Recent security events", color=0xFAA61A)
        for ev in events:
            embed.add_field(
                name=f"{'✅' if ev['success'] else '❌'} {ev['event']} • {ev['created_at']}",
                value=f"Actor: {ev['actor']}\nTarget: {ev['target']}\nAction: {ev['action']}",
                inline=False,
            )
        embed.set_footer(text="HAVX+lo SECURTY — last 15 events")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @app_commands.command(name="stats", description="Show protection statistics (owner only)")
    async def stats(self, interaction: discord.Interaction):
        if not await self._guard(interaction):
            return
        guild = interaction.guild
        counts = await self.bot.db.event_counts(guild.id)
        total = sum(n for _, n in counts)
        whitelist = await self.bot.db.whitelist_list(guild.id)
        trusted = await self.bot.db.trust_list(guild.id)
        lockdown = await self.bot.db.lockdown_load(guild.id)
        data = await self.engine.settings(guild)
        active = sum(1 for flag in PROTECTION_FLAGS if data.get(flag))
        top = "\n".join(f"`{name}` — {n}" for name, n in counts[:8]) or "no events yet"
        embed = discord.Embed(title="📊 HAVX+lo SECURTY stats", color=0x5865F2)
        embed.add_field(name="Protected servers", value=str(len(self.bot.guilds)), inline=True)
        embed.add_field(name="Active modules", value=f"{active}/{len(PROTECTION_FLAGS)}", inline=True)
        embed.add_field(name="Lockdown", value="🔒 ON" if lockdown else "🔓 off", inline=True)
        embed.add_field(name="Recorded events", value=str(total), inline=True)
        embed.add_field(name="Whitelisted members", value=str(len(whitelist)), inline=True)
        embed.add_field(name="Trusted bots", value=str(len(trusted)), inline=True)
        embed.add_field(name="Top events", value=top, inline=False)
        embed.set_footer(text=f"Database: {getattr(self.bot.db, 'kind', 'unknown')}")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # ---------------- help ----------------
    @app_commands.command(name="help", description="List every HAVX+lo SECURTY command")
    async def help_cmd(self, interaction: discord.Interaction):
        embed = discord.Embed(
            title="🛡️ HAVX+lo SECURTY — commands",
            description="All commands below are **owner-only** and verified against `guild.owner_id`.",
            color=0x5865F2,
        )
        embed.add_field(
            name="Whitelist",
            value="`/havx` add member • `/abdo` remove member • `/whitelist` list",
            inline=False,
        )
        embed.add_field(
            name="Control",
            value="`/security` `/lockdown` `/unlock` `/panic` `/backup` `/restore`",
            inline=False,
        )
        embed.add_field(
            name="Protection toggles",
            value="`/antinuke` `/antiraid` `/antispam` `/antiwebhook` `/antibot` `/antilink`",
            inline=False,
        )
        embed.add_field(
            name="Awareness",
            value="`/audit` suspicious events • `/stats` statistics • `/help`",
            inline=False,
        )
        embed.set_footer(text="Prefix commands (!) remain available for the same features")
        await interaction.response.send_message(embed=embed, ephemeral=True)


async def setup(bot: commands.Bot):
    await bot.add_cog(SlashCommands(bot))
