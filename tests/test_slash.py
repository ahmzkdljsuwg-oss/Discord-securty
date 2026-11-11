"""Tests for the slash command layer (offline, no Discord connection)."""
import asyncio
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import discord  # noqa: E402

import slash  # noqa: E402
from database import Database  # noqa: E402
from lockdown import LockdownManager  # noqa: E402
from security import SecurityEngine  # noqa: E402
from test_core import FakeBot, FakeGuild, FakeMember, FakeUser  # noqa: E402
from whitelist import WhitelistManager  # noqa: E402

_LOOP = asyncio.new_event_loop()


def run(coro):
    return _LOOP.run_until_complete(coro)


class FakeResponse:
    def __init__(self):
        self.messages = []
        self.deferred = False

    def is_done(self):
        return self.deferred or bool(self.messages)

    async def send_message(self, content=None, **kwargs):
        self.messages.append(("send", content, kwargs))

    async def defer(self, ephemeral=False):
        self.deferred = True


class FakeFollowup:
    def __init__(self):
        self.messages = []

    async def send(self, content=None, **kwargs):
        self.messages.append((content, kwargs))


class FakeInteraction:
    def __init__(self, guild, user, command_name="test"):
        self.guild = guild
        self.user = user
        self.response = FakeResponse()
        self.followup = FakeFollowup()
        self.command = type("C", (), {"name": command_name})()

    def all_text(self):
        parts = [str(m[1]) for m in self.response.messages]
        parts += [str(m[0]) for m in self.followup.messages]
        return " | ".join(parts)


class SlashTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = Database("", os.path.join(self.tmp, "s.sqlite3"))
        run(self.db.connect())
        self.bot = FakeBot()
        self.bot.db = self.db
        self.bot.guilds = []
        self.bot.engine = SecurityEngine(self.bot, self.db)
        self.bot.whitelist = WhitelistManager(self.db)
        self.bot.lockdown = LockdownManager(self.bot, self.db, self.bot.engine)
        self.bot.tree = type("Tree", (), {"error": lambda self, fn: None})()
        self.cog = slash.SlashCommands(self.bot)
        self.guild = FakeGuild(gid=1, owner_id=100)
        self.guild.roles = []
        self.guild.categories = []
        self.owner = FakeUser(100)
        self.intruder = FakeUser(200)
        self.member = FakeMember(300)
        self.guild._members[300] = self.member

    def tearDown(self):
        run(self.db.close())

    def _interaction(self, user):
        return FakeInteraction(self.guild, user)

    # ---------------- registration ----------------
    # ---------------- owner gate ----------------
    def test_non_owner_blocked_and_logged(self):
        async def scenario():
            inter = self._interaction(self.intruder)
            await self.cog.havx.callback(self.cog, inter, self.member)
            self.assertFalse(await self.db.is_whitelisted(1, 300))
            self.assertIn("Owner-only command", inter.all_text())
            events = await self.db.event_list(1, limit=5)
            self.assertTrue(any(e["event"] == "UNAUTHORIZED COMMAND ATTEMPT" for e in events))

        run(scenario())

    def test_non_owner_cannot_lockdown(self):
        async def scenario():
            inter = self._interaction(self.intruder)
            await self.cog.lockdown.callback(self.cog, inter)
            self.assertIsNone(await self.db.lockdown_load(1))
            self.assertIn("Owner-only command", inter.all_text())

        run(scenario())

    # ---------------- whitelist ----------------
    def test_owner_add_and_remove_whitelist(self):
        async def scenario():
            inter = self._interaction(self.owner)
            await self.cog.havx.callback(self.cog, inter, self.member)
            self.assertTrue(await self.db.is_whitelisted(1, 300))
            self.assertIn("added to the whitelist", inter.all_text())

            inter2 = self._interaction(self.owner)
            await self.cog.abdo.callback(self.cog, inter2, self.member)
            self.assertFalse(await self.db.is_whitelisted(1, 300))
            self.assertIn("removed from the whitelist", inter2.all_text())

            events = [e["event"] for e in await self.db.event_list(1, limit=10)]
            self.assertIn("WHITELIST ADDED", events)
            self.assertIn("WHITELIST REMOVED", events)

        run(scenario())

    def test_whitelist_list_shows_entries(self):
        async def scenario():
            await self.cog.havx.callback(self.cog, self._interaction(self.owner), self.member)
            inter = self._interaction(self.owner)
            await self.cog.whitelist_cmd.callback(self.cog, inter)
            embed = inter.response.messages[0][2].get("embed")
            self.assertIsNotNone(embed)
            self.assertIn("300", embed.description)

        run(scenario())

    def test_owner_add_is_logged_with_identity(self):
        async def scenario():
            await self.cog.havx.callback(self.cog, self._interaction(self.owner), self.member)
            events = await self.db.event_list(1, limit=5)
            added = [e for e in events if e["event"] == "WHITELIST ADDED"][0]
            self.assertIn("100", added["actor"])
            self.assertIn("300", added["target"])

        run(scenario())

    # ---------------- panic ----------------
    def test_panic_toggles_all_protections_and_lockdown(self):
        async def scenario():
            data = await self.bot.engine.settings(self.guild)
            data["antiraid"] = False
            await self.bot.engine.save(self.guild, data)

            inter = self._interaction(self.owner)
            await self.cog.panic.callback(self.cog, inter)
            data = await self.bot.engine.settings(self.guild)
            self.assertTrue(data["panic"])
            self.assertTrue(data["antiraid"])
            self.assertIsNotNone(await self.db.lockdown_load(1))

            inter2 = self._interaction(self.owner)
            await self.cog.panic.callback(self.cog, inter2)
            data = await self.bot.engine.settings(self.guild)
            self.assertFalse(data["panic"])
            self.assertFalse(data["antiraid"])  # pre-panic state restored
            self.assertIsNone(await self.db.lockdown_load(1))

        run(scenario())

    # ---------------- backup / restore ----------------
    def test_backup_then_restore_roundtrip(self):
        async def scenario():
            data = await self.bot.engine.settings(self.guild)
            data["antispam"] = False
            data["spam_count"] = 11
            await self.bot.engine.save(self.guild, data)
            await self.db.whitelist_add(1, 300, 100, "2026-01-01T00:00:00")

            inter = self._interaction(self.owner)
            await self.cog.backup_cmd.callback(self.cog, inter)
            self.assertIn("Backup", inter.all_text())

            data = await self.bot.engine.settings(self.guild)
            data["antispam"] = True
            data["spam_count"] = 3
            await self.bot.engine.save(self.guild, data)
            await self.db.whitelist_remove(1, 300)

            inter2 = self._interaction(self.owner)
            await self.cog.restore.callback(self.cog, inter2)
            data = await self.bot.engine.settings(self.guild)
            self.assertFalse(data["antispam"])
            self.assertEqual(data["spam_count"], 11)
            self.assertTrue(await self.db.is_whitelisted(1, 300))
            self.assertIn("Restored backup", inter2.all_text())

        run(scenario())

    def test_restore_without_backup_warns(self):
        async def scenario():
            inter = self._interaction(self.owner)
            await self.cog.restore.callback(self.cog, inter)
            self.assertIn("No saved backup", inter.all_text())

        run(scenario())

    # ---------------- audit / stats ----------------
    def test_audit_and_stats_use_recorded_events(self):
        async def scenario():
            await self.cog.havx.callback(self.cog, self._interaction(self.owner), self.member)

            audit = self._interaction(self.owner)
            await self.cog.audit.callback(self.cog, audit)
            embed = audit.response.messages[0][2].get("embed")
            self.assertIsNotNone(embed)
            self.assertTrue(any("WHITELIST ADDED" in f.name for f in embed.fields))

            stats = self._interaction(self.owner)
            await self.cog.stats.callback(self.cog, stats)
            sembed = stats.response.messages[0][2].get("embed")
            names = [f.name for f in sembed.fields]
            self.assertIn("Recorded events", names)
            self.assertIn("Whitelisted members", names)

        run(scenario())

    def test_toggle_slash_changes_setting(self):
        async def scenario():
            await self.cog.antispam.callback(self.cog, self._interaction(self.owner), False)
            data = await self.bot.engine.settings(self.guild)
            self.assertFalse(data["antispam"])
            await self.cog.antispam.callback(self.cog, self._interaction(self.owner), None)
            data = await self.bot.engine.settings(self.guild)
            self.assertTrue(data["antispam"])

        run(scenario())

    def test_non_owner_cannot_toggle(self):
        async def scenario():
            inter = self._interaction(self.intruder)
            await self.cog.antinuke.callback(self.cog, inter, False)
            data = await self.bot.engine.settings(self.guild)
            self.assertTrue(data["antinuke"])

        run(scenario())


class SlashTreeTests(unittest.TestCase):
    def test_tree_exposes_eighteen_commands(self):
        async def scenario():
            from main import HavxBot  # noqa: WPS433
            intents = discord.Intents.none()
            bot = HavxBot(intents)
            await bot.setup_hook()
            names = {c.name for c in bot.tree.get_commands()}
            expected = {
                "havx", "abdo", "whitelist", "security", "lockdown", "unlock", "panic",
                "antinuke", "antiraid", "antispam", "antiwebhook", "antibot", "antilink",
                "backup", "restore", "audit", "stats", "help",
            }
            self.assertEqual(names, expected)
            # every slash command carries a description Discord can display
            for cmd in bot.tree.get_commands():
                self.assertTrue(cmd.description)
            await bot.db.close()

        run(scenario())


if __name__ == "__main__":
    unittest.main()
