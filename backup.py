"""Server structure export used by the !backup command."""
from __future__ import annotations

import io
import json
from datetime import datetime, timezone

import discord


def export_guild(guild: discord.Guild) -> dict:
    roles = []
    for role in guild.roles:
        if role.is_default() or role.managed:
            continue
        roles.append({
            "name": role.name,
            "id": role.id,
            "color": role.color.value,
            "permissions": role.permissions.value,
            "position": role.position,
            "hoist": role.hoist,
            "mentionable": role.mentionable,
        })
    categories = []
    for cat in guild.categories:
        categories.append({
            "name": cat.name,
            "id": cat.id,
            "position": cat.position,
            "channels": [
                {
                    "name": ch.name,
                    "id": ch.id,
                    "type": str(ch.type),
                    "position": getattr(ch, "position", 0),
                    "topic": getattr(ch, "topic", None),
                }
                for ch in cat.channels
            ],
        })
    uncategorized = [
        {"name": ch.name, "id": ch.id, "type": str(ch.type), "position": getattr(ch, "position", 0)}
        for ch in guild.channels
        if getattr(ch, "category", None) is None
    ]
    return {
        "guild": {"id": guild.id, "name": guild.name, "owner_id": guild.owner_id},
        "created_at": datetime.now(timezone.utc).isoformat(),
        "roles": roles,
        "categories": categories,
        "uncategorized": uncategorized,
    }


def dump(guild: discord.Guild) -> discord.File:
    payload = json.dumps(export_guild(guild), ensure_ascii=False, indent=2)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return discord.File(
        fp=io.BytesIO(payload.encode("utf-8")),
        filename=f"havx-backup-{guild.id}-{stamp}.json",
    )
