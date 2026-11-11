"""Offline unit tests for HAVX+lo SECURTY (no real Discord connection)."""
import asyncio
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402
from antilink import ContentFilter  # noqa: E402
from antiraid import AntiRaid  # noqa: E402
from antispam import AntiSpam  # noqa: E402
from database import Database  # noqa: E402
from lockdown import LockdownManager  # noqa: E402
from security import SecurityEngine  # noqa: E402


class FakeUser:
    def __init__(self, uid, bot=False):
        self.id = uid
        self.bot = bot

    def __str__(self):
        return f"user-{self.id}"


class FakeRole:
    def __init__(self, rid, name, perms=None):
        self.id = rid
        self.name = name
        self.managed = False
        self.permissions = types.SimpleNamespace(
            administrator=bool(perms),
            **{k: bool(perms) for k in (
                "manage_guild", "manage_roles", "manage_channels",
                "manage_webhooks", "ban_members", "kick_members")},
        )

    def is_default(self):
        return False

    def __le__(self, other):
        return False

    def __lt__(self, other):
        return False


class FakeMember(FakeUser):
    def __init__(self, uid, bot=False, roles=None):
        super().__init__(uid, bot)
        self.roles = roles or []
        self.top_role = FakeRole(9999, "bot-highest")
        self.timed_out = None
        self.kicked = False
        self.banned = False
        self.removed = []

    async def timeout(self, until, reason=None):
        self.timed_out = until

    async def kick(self, reason=None):
        self.kicked = True

    async def ban(self, reason=None, delete_message_days=0):
        self.banned = True

    async def remove_roles(self, role, reason=None):
        self.removed.append(role.name)
        if role in self.roles:
            self.roles.remove(role)


class FakeChannel:
    def __init__(self, cid, name="general"):
        self.id = cid
        self.name = name
        self.sent = []

    def overwrites_for(self, role):
        return FakeOverwrite()

    async def set_permissions(self, target, overwrite=None, reason=None):
        return None

    async def send(self, *args, **kwargs):
        self.sent.append((args, kwargs))


class FakeOverwrite:
    def pair(self):
        return (types.SimpleNamespace(value=0), types.SimpleNamespace(value=0))


class FakeGuild:
    def __init__(self, gid=1, owner_id=100):
        self.id = gid
        self.owner_id = owner_id
        self.name = "TestGuild"
        self.channels = []
        self.members = []
        self.default_role = FakeRole(0, "@everyone")
        self.me = FakeMember(999, bot=True)
        self._members = {}

    def get_member(self, uid):
        return self._members.get(uid)

    def get_channel(self, cid):
        return None

    def get_role(self, rid):
        return None


class FakeBot:
    def __init__(self):
        self.user = FakeUser(999, bot=True)

    def get_channel(self, cid):
        return None


_LOOP = asyncio.new_event_loop()


def run(coro):
    # one shared loop so aiosqlite connections created in setUp stay usable
    return _LOOP.run_until_complete(coro)


def _close_loop():
    try:
        _LOOP.close()
    except Exception:
        pass


import atexit  # noqa: E402

atexit.register(_close_loop)


class FakeMessage:
    def __init__(self, guild, author, content):
        self.guild = guild
        self.author = author
        self.content = content
        self.mentions = []
        self.role_mentions = []
        self.mention_everyone = False
        self.channel = FakeChannel(5, "general")
        self.deleted = False

    async def delete(self):
        self.deleted = True


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "test.sqlite3")

    def test_settings_roundtrip_and_persistence(self):
        async def scenario():
            db = Database("", self.path)
            await db.connect()
            data = await db.get_settings(1, config.DEFAULT_SETTINGS)
            self.assertTrue(data["antiraid"])
            data["antiraid"] = False
            data["spam_count"] = 9
            await db.save_settings(1, data)
            await db.close()

            db2 = Database("", self.path)
            await db2.connect()
            again = await db2.get_settings(1, config.DEFAULT_SETTINGS)
            await db2.close()
            self.assertFalse(again["antiraid"])
            self.assertEqual(again["spam_count"], 9)
            self.assertTrue(again["antinuke"])

        run(scenario())

    def test_whitelist_crud(self):
        async def scenario():
            db = Database("", self.path)
            await db.connect()
            self.assertFalse(await db.is_whitelisted(1, 42))
            await db.whitelist_add(1, 42, 100, "2026-01-01T00:00:00")
            self.assertTrue(await db.is_whitelisted(1, 42))
            rows = await db.whitelist_list(1)
            self.assertEqual(rows[0][0], 42)
            self.assertTrue(await db.whitelist_remove(1, 42))
            self.assertFalse(await db.is_whitelisted(1, 42))
            self.assertFalse(await db.whitelist_remove(1, 42))
            await db.close()

        run(scenario())

    def test_trusted_bots_and_lockdown(self):
        async def scenario():
            db = Database("", self.path)
            await db.connect()
            await db.trust_add(1, 777, 100, "now")
            self.assertTrue(await db.is_trusted_bot(1, 777))
            self.assertEqual(await db.trust_list(1), [777])
            self.assertTrue(await db.trust_remove(1, 777))

            await db.lockdown_save(1, {"10": {"allow": 2048, "deny": 0}}, 100, "now")
            rec = await db.lockdown_load(1)
            self.assertEqual(rec["activated_by"], 100)
            self.assertEqual(rec["snapshot"]["10"]["allow"], 2048)
            await db.lockdown_delete(1)
            self.assertIsNone(await db.lockdown_load(1))
            await db.close()

        run(scenario())


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = Database("", os.path.join(self.tmp, "e.sqlite3"))
        run(self.db.connect())
        self.bot = FakeBot()
        self.engine = SecurityEngine(self.bot, self.db)
        self.guild = FakeGuild()

    def tearDown(self):
        run(self.db.close())


    def test_owner_check(self):
        self.assertTrue(self.engine.is_owner(self.guild, FakeUser(100)))
        self.assertFalse(self.engine.is_owner(self.guild, FakeUser(101)))

    def test_whitelist_exempts_member(self):
        async def scenario():
            admin = FakeMember(200)
            self.assertFalse(await self.engine.is_exempt(self.guild, admin))
            self.guild._members[200] = admin
            await self.db.whitelist_add(self.guild.id, 200, 100, "now")
            self.assertTrue(await self.engine.is_exempt(self.guild, admin))
            admin.roles = [FakeRole(3, "Admin", perms=True)]
            self.assertTrue(await self.engine.is_exempt(self.guild, admin))
            await self.db.whitelist_remove(self.guild.id, 200)
            self.assertFalse(await self.engine.is_exempt(self.guild, admin))
            self.assertTrue(await self.engine.is_exempt(self.guild, FakeMember(100)))

        run(scenario())

    def test_punish_timeout_and_strip(self):
        async def scenario():
            m = FakeMember(300, roles=[FakeRole(4, "Admin", perms=True)])
            desc, ok = await self.engine.punish(self.guild, m, "timeout", "test", timeout_minutes=5)
            self.assertTrue(ok)
            self.assertIsNotNone(m.timed_out)
            desc, ok = await self.engine.punish(self.guild, m, "strip", "test")
            self.assertTrue(ok)
            self.assertIn("Admin", m.removed)

        run(scenario())


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = Database("", os.path.join(self.tmp, "f.sqlite3"))
        run(self.db.connect())
        self.bot = FakeBot()
        self.engine = SecurityEngine(self.bot, self.db)
        self.guild = FakeGuild()
        self.cf = ContentFilter(self.bot, self.engine)
        self.spam = AntiSpam(self.bot, self.engine)

    def tearDown(self):
        run(self.db.close())


    def test_invite_blocked(self):
        async def scenario():
            msg = FakeMessage(self.guild, FakeMember(500), "join discord.gg/abc123")
            self.assertTrue(await self.cf.on_message(msg))
            self.assertTrue(msg.deleted)

        run(scenario())

    def test_link_allowed_domain(self):
        async def scenario():
            data = await self.engine.settings(self.guild)
            data["allowed_domains"] = ["example.com"]
            await self.engine.save(self.guild, data)
            msg = FakeMessage(self.guild, FakeMember(501), "see https://example.com/page")
            self.assertFalse(await self.cf.on_message(msg))
            self.assertFalse(msg.deleted)
            msg2 = FakeMessage(self.guild, FakeMember(501), "see https://evil.test/page")
            self.assertTrue(await self.cf.on_message(msg2))

        run(scenario())

    def test_mass_mention_blocked(self):
        async def scenario():
            msg = FakeMessage(self.guild, FakeMember(502), "hi")
            msg.mentions = [FakeUser(i) for i in range(10)]
            self.assertTrue(await self.cf.on_message(msg))

        run(scenario())

    def test_whitelisted_user_skips_filters(self):
        async def scenario():
            await self.db.whitelist_add(self.guild.id, 503, 100, "now")
            msg = FakeMessage(self.guild, FakeMember(503), "discord.gg/raid")
            self.assertFalse(await self.cf.on_message(msg))

        run(scenario())

    def test_spam_flood(self):
        async def scenario():
            author = FakeMember(504)
            triggered = False
            for _ in range(6):
                msg = FakeMessage(self.guild, author, "SPAM SPAM")
                triggered = await self.spam.on_message(msg)
                if triggered:
                    break
            self.assertTrue(triggered)

        run(scenario())


class RaidAndLockdownTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = Database("", os.path.join(self.tmp, "r.sqlite3"))
        run(self.db.connect())
        self.bot = FakeBot()
        self.engine = SecurityEngine(self.bot, self.db)
        self.guild = FakeGuild()
        self.lockdown = LockdownManager(self.bot, self.db, self.engine)
        self.raid = AntiRaid(self.bot, self.engine, self.lockdown)
        self.guild.channels = [FakeChannel(11, "general"), FakeChannel(12, "chat")]

    def tearDown(self):
        run(self.db.close())


    def test_raid_triggers_lockdown_and_punishes(self):
        async def scenario():
            data = await self.engine.settings(self.guild)
            data["raid_join_count"] = 3
            await self.engine.save(self.guild, data)
            for i in range(3):
                m = FakeMember(600 + i)
                m.guild = self.guild
                self.guild._members[m.id] = m
                await self.raid.on_member_join(m)
            rec = await self.db.lockdown_load(self.guild.id)
            self.assertIsNotNone(rec)
            self.assertTrue(all(self.guild._members[600 + i].kicked for i in range(3)))

        run(scenario())

    def test_lockdown_activate_and_unlock(self):
        async def scenario():
            ok, msg = await self.lockdown.activate(self.guild, FakeUser(100))
            self.assertTrue(ok)
            self.assertIsNotNone(await self.db.lockdown_load(self.guild.id))
            ok2, _ = await self.lockdown.activate(self.guild, FakeUser(100))
            self.assertFalse(ok2)
            ok3, _ = await self.lockdown.deactivate(self.guild, FakeUser(100))
            self.assertTrue(ok3)
            self.assertIsNone(await self.db.lockdown_load(self.guild.id))

        run(scenario())


class CommandRegistrationTests(unittest.TestCase):
    def test_commands_registered_and_toggle_owner_gated(self):
        async def scenario():
            from main import HavxBot, build_intents
            bot = HavxBot(build_intents())
            bot.db = Database("", os.path.join(tempfile.mkdtemp(), "c.sqlite3"))
            await bot.db.connect()
            bot.engine = SecurityEngine(bot, bot.db)
            await bot.setup_hook()
            names = {c.name for c in bot.commands}
            expected = {
                "help", "ping", "security", "lockdown", "unlock", "whitelist",
                "unwhitelist", "antiraid", "antinuke", "antispam", "antiwebhook",
                "antilink", "antiinvite", "backup", "trust", "untrust", "trusted",
            }
            self.assertTrue(expected.issubset(names), f"missing: {expected - names}")
            self.assertEqual(bot.command_prefix, "!")

            guild = FakeGuild(owner_id=100)
            replies = []

            class Ctx:
                def __init__(self, author):
                    self.guild = guild
                    self.author = author
                    self.command = types.SimpleNamespace(qualified_name="antiraid")

                async def reply(self, *a, **k):
                    replies.append(a[0] if a else "")

            cmd = bot.get_command("antiraid")
            await cmd.callback(Ctx(FakeMember(201)), None)
            data = await bot.engine.settings(guild)
            self.assertTrue(data["antiraid"])
            self.assertTrue(any("Owner-only" in str(r) for r in replies))

            await cmd.callback(Ctx(FakeMember(100)), None)
            data = await bot.engine.settings(guild)
            self.assertFalse(data["antiraid"])

            await bot.db.close()

        run(scenario())


if __name__ == "__main__":
    unittest.main()
