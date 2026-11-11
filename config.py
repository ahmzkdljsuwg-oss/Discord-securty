"""Central configuration for HAVX+lo SECURTY."""
import os

BOT_NAME = "HAVX+lo SECURTY"
PREFIX = "!"
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID", "1557374637015437332"))
LOG_CHANNEL_FALLBACK = 1557374637015437332
OWNER_ONLY_BY_DISCORD = True  # owner determined via guild.owner_id

DISCORD_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
DATA_DIR = os.getenv("DATA_DIR", "data")
SQLITE_PATH = os.path.join(DATA_DIR, "havx.sqlite3")
LOCK_SCOPE = os.getenv("RAILWAY_PROJECT_ID", "") + ":" + os.getenv("RAILWAY_SERVICE_ID", "")

# Default per-guild settings. Stored as JSON in the database.
DEFAULT_SETTINGS = {
    "antiraid": True,
    "antinuke": True,
    "antispam": True,
    "antiwebhook": True,
    "antibot": True,
    "antilink": True,
    "antiinvite": True,
    "antimassmention": True,
    "antiroleabuse": True,
    "antichanneldelete": True,
    "serverprotection": True,
    "log_channel": LOG_CHANNEL_ID,
    "lockdown": False,
    # thresholds
    "raid_join_count": 6,
    "raid_join_seconds": 10,
    "raid_punishment": "kick",      # kick | ban | none
    "spam_count": 5,
    "spam_seconds": 5,
    "spam_punishment": "timeout",   # timeout | kick | ban | none
    "spam_timeout_minutes": 10,
    "mention_limit": 5,
    "nuke_punishment": "strip",     # strip | kick | ban | none
    "punish_whitelisted": False,
    "restore_channels": True,
    "restore_roles": True,
    "block_links_all": True,
    "allowed_domains": [],
    "mod_roles": [],
    "immune_roles": [],
    "trusted_bots": [],
}

# Audit-log action -> settings key used by the anti-nuke engine.
DANGEROUS_ACTIONS = {
    "channel_delete": ("antinuke", "antichanneldelete"),
    "channel_create": ("antinuke",),
    "role_delete": ("antinuke",),
    "role_create": ("antinuke",),
    "member_role_update": ("antiroleabuse",),
    "ban_add": ("antinuke",),
    "kick": ("antinuke",),
    "guild_update": ("serverprotection",),
    "webhook_create": ("antiwebhook",),
    "webhook_update": ("antiwebhook",),
    "webhook_delete": ("antiwebhook",),
    "message_delete": ("antinuke",),
    "message_bulk_delete": ("antinuke",),
}

LINK_RE = r"(?:https?://|www\.)[^\s<>]+"
INVITE_RE = r"(?:discord\.gg/|discord(?:app)?\.com/invite/|discord\.me/)[A-Za-z0-9\-_]+"
