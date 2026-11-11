# HAVX+lo SECURTY 🛡️

Professional Discord protection bot — anti-raid, anti-nuke, anti-spam, anti-webhook,
anti-bot, anti-link/invite, anti-mass-mention, anti-role-abuse, channel restore,
server protection, lockdown, owner-only whitelist and a full security log.

- **Language:** Python 3.12
- **Library:** discord.py 2.x (prefix `!`)
- **Hosting:** Railway (24/7, restart on failure)
- **Log channel:** `1557374637015437332`

## Quick start (local)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export DISCORD_BOT_TOKEN="your-token"
python main.py
```

Without `DATABASE_URL` the bot stores state in `data/havx.sqlite3` (set `DATA_DIR`
to a persistent path when using a volume).

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `DISCORD_BOT_TOKEN` | yes | Bot token from the Discord Developer Portal |
| `DATABASE_URL` | recommended | PostgreSQL URL (Railway Postgres plugin). Enables durable storage + single-instance lock |
| `DATA_DIR` | optional | SQLite directory when no `DATABASE_URL` is set; mount a Railway volume here |
| `LOG_CHANNEL_ID` | optional | Overrides the default log channel id |

## Required Discord settings

Developer Portal → Bot:
- **Server Members Intent** ✅
- **Message Content Intent** ✅
- Presence intent is **not** required.

Bot permissions:
View Channels, Send Messages, Read Message History, View Audit Log,
Manage Channels, Manage Roles, Manage Webhooks, Moderate Members,
Ban Members, Manage Messages, Kick Members.

## Commands

| Command | Access |
|---|---|
| `!help` `!ping` | everyone |
| `!security` | owner |
| `!lockdown` `!unlock` | owner |
| `!whitelist @user` `!unwhitelist @user` `!whitelist list` | owner |
| `!antiraid` `!antinuke` `!antispam` `!antiwebhook` `!antilink` `!antiinvite` | owner |
| `!antibot` `!antimassmention` `!antiroleabuse` `!antichanneldelete` `!serverprotection` | owner |
| `!trust @bot` `!untrust @bot` `!trusted` | owner |
| `!backup` | owner |

Toggles accept `on` / `off`; without an argument they flip the current state.
Owner identity is always `guild.owner_id` — roles named “Owner” or Administrator
permission grant nothing.

## Architecture

| File | Purpose |
|---|---|
| `main.py` | Bot client, event routing, instance lock, startup restore |
| `config.py` | Constants, defaults, regexes |
| `database.py` | PostgreSQL / SQLite storage + advisory instance lock |
| `security.py` | Settings cache, identity checks, audit lookup, punishments |
| `antinuke.py` | Audit-log destructive action detection, channel restore, anti-bot |
| `antiraid.py` | Join-burst detection → punishment + lockdown |
| `antispam.py` | Flood / duplicate message detection |
| `antilink.py` | Link, invite and mass-mention filters |
| `antiwebhook.py` | Unauthorized webhook deletion |
| `lockdown.py` | Snapshot & restore channel permissions |
| `whitelist.py` | Durable whitelist / trusted-bot management |
| `logger.py` | Structured embeds to the log channel |
| `backup.py` | JSON server-structure export |
| `commands.py` | Prefix commands + owner-only guard |

## Railway deployment

1. Create a project + service from this repository. The build uses the `Dockerfile`
   (`python:3.12-slim`); `nixpacks.toml` is kept as a working fallback.
2. Add variables: `DISCORD_BOT_TOKEN`, and `DATABASE_URL` from a Postgres plugin.
3. Start command: `python main.py` (also set in `railway.json`).
4. Restart policy: on failure (configured in `railway.json`).
5. Keep replicas at **1** — the PostgreSQL advisory lock refuses a second instance.

## Tests

```bash
python -m unittest discover -s tests -v
```

Offline tests cover storage persistence, whitelist CRUD, owner/whitelist exemption,
punishments, link/invite/mention filters, spam detection, raid→lockdown flow,
lockdown snapshot restore, and command registration/owner gating.
