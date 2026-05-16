"""Curated catalog of common apps that the dashboard knows how to block.

Each entry maps a familiar app name to the DNS domains the app uses. The UI
shows these as toggles in a "block apps" picker and the catalog drives both:

- The "Block apps" toggle inside profiles -- every selected app's domains get
  appended to the profile's blocked-list at apply time.
- The activity sampler's "what app did this device use today" attribution
  (best-effort; many domains serve multiple apps).

Adding an app is just appending an entry. Each domain is matched as both an
exact name and a wildcard for subdomains; see ``profiles._domains_to_block``
for how the rule generator expands them.

Caveats every parent should know:
- DNS-blocking apps that have hardcoded IPs (some games, some chat clients)
  WILL leak past us. We can't fix that from the DNS layer.
- The catalog is conservative -- we err towards "miss a CDN" rather than
  "block a sibling Google service" because false positives are very visible
  to kids ("dad, the printer stopped working").
"""
from __future__ import annotations

from typing import Any


# Categories used by the picker UI (group apps under a heading).
CATEGORIES = [
    {"id": "social",    "label": "Social",     "emoji": "💬"},
    {"id": "video",     "label": "Video",      "emoji": "📺"},
    {"id": "music",     "label": "Music",      "emoji": "🎵"},
    {"id": "gaming",    "label": "Games",      "emoji": "🎮"},
    {"id": "shopping",  "label": "Shopping",   "emoji": "🛒"},
    {"id": "messaging", "label": "Chat",       "emoji": "📩"},
    {"id": "ai",        "label": "AI",         "emoji": "🤖"},
    {"id": "adult",     "label": "Adult",      "emoji": "🔞"},
]


APPS: list[dict[str, Any]] = [
    # social
    {"id": "tiktok",    "name": "TikTok",      "emoji": "🎵", "category": "social",
     "domains": ["tiktok.com", "tiktokcdn.com", "tiktokv.com", "musical.ly", "byteoversea.com",
                 "byteoversea.net", "ibyteimg.com", "muscdn.com", "tiktokcdn-us.com"]},
    {"id": "instagram", "name": "Instagram",   "emoji": "📷", "category": "social",
     "domains": ["instagram.com", "cdninstagram.com", "instagramstatic-a.akamaihd.net"]},
    {"id": "snapchat",  "name": "Snapchat",    "emoji": "👻", "category": "social",
     "domains": ["snapchat.com", "sc-cdn.net", "snap-dev.net", "snap.research"]},
    {"id": "facebook",  "name": "Facebook",    "emoji": "📘", "category": "social",
     "domains": ["facebook.com", "fbcdn.net", "fbsbx.com", "fb.com", "fb.me"]},
    {"id": "twitter",   "name": "X / Twitter", "emoji": "✖️", "category": "social",
     "domains": ["twitter.com", "x.com", "twimg.com", "t.co"]},
    {"id": "reddit",    "name": "Reddit",      "emoji": "🤖", "category": "social",
     "domains": ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"]},
    {"id": "bereal",    "name": "BeReal",      "emoji": "📸", "category": "social",
     "domains": ["bereal.com", "bereal.network"]},

    # video
    {"id": "youtube",   "name": "YouTube",     "emoji": "▶️", "category": "video",
     "domains": ["youtube.com", "youtu.be", "ytimg.com", "googlevideo.com",
                 "youtubekids.com", "music.youtube.com", "tv.youtube.com",
                 "youtubei.googleapis.com", "yt3.ggpht.com"]},
    {"id": "netflix",   "name": "Netflix",     "emoji": "🎬", "category": "video",
     "domains": ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net"]},
    {"id": "disneyplus","name": "Disney+",     "emoji": "🏰", "category": "video",
     "domains": ["disneyplus.com", "disney-plus.net", "bamgrid.com"]},
    {"id": "hulu",      "name": "Hulu",        "emoji": "📺", "category": "video",
     "domains": ["hulu.com", "hulustream.com"]},
    {"id": "primevideo","name": "Prime Video", "emoji": "🎟️", "category": "video",
     "domains": ["primevideo.com", "aiv-cdn.net", "aiv-delivery.net"]},
    {"id": "twitch",    "name": "Twitch",      "emoji": "🟣", "category": "video",
     "domains": ["twitch.tv", "ttvnw.net", "jtvnw.net"]},
    {"id": "stan",      "name": "Stan",        "emoji": "🎥", "category": "video",
     "domains": ["stan.com.au", "stan-cdn.com"]},
    {"id": "binge",     "name": "Binge",       "emoji": "🎥", "category": "video",
     "domains": ["binge.com.au"]},
    {"id": "kayo",      "name": "Kayo",        "emoji": "🏉", "category": "video",
     "domains": ["kayosports.com.au"]},

    # music
    {"id": "spotify",   "name": "Spotify",     "emoji": "🎧", "category": "music",
     "domains": ["spotify.com", "scdn.co", "spotifycdn.com", "spotifycharts.com"]},
    {"id": "applemusic","name": "Apple Music", "emoji": "🎼", "category": "music",
     "domains": ["music.apple.com", "itunes.apple.com", "mzstatic.com"]},

    # gaming
    {"id": "roblox",    "name": "Roblox",      "emoji": "🟥", "category": "gaming",
     "domains": ["roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com"]},
    {"id": "fortnite",  "name": "Fortnite",    "emoji": "🛡️", "category": "gaming",
     "domains": ["epicgames.com", "ol.epicgames.com", "unrealengine.com",
                 "fortnite.com", "easyanticheat.net"]},
    {"id": "minecraft", "name": "Minecraft",   "emoji": "🟩", "category": "gaming",
     "domains": ["minecraft.net", "mojang.com", "xboxlive.com"]},
    {"id": "steam",     "name": "Steam",       "emoji": "🎮", "category": "gaming",
     "domains": ["steampowered.com", "steamcontent.com", "steamcommunity.com",
                 "steamstatic.com", "steamserver.net"]},
    {"id": "playstation","name": "PlayStation","emoji": "🎮", "category": "gaming",
     "domains": ["playstation.net", "playstation.com", "sonyentertainmentnetwork.com"]},
    {"id": "xbox",      "name": "Xbox",        "emoji": "🟢", "category": "gaming",
     "domains": ["xboxlive.com", "xbox.com", "live.com"]},
    {"id": "nintendo",  "name": "Nintendo",    "emoji": "🎮", "category": "gaming",
     "domains": ["nintendo.net", "nintendo.com", "nintendo-europe.com"]},

    # shopping
    {"id": "amazon",    "name": "Amazon",      "emoji": "📦", "category": "shopping",
     "domains": ["amazon.com", "amazon.com.au", "ssl-images-amazon.com",
                 "media-amazon.com", "amazonpay.com"]},
    {"id": "ebay",      "name": "eBay",        "emoji": "🛍️", "category": "shopping",
     "domains": ["ebay.com", "ebayimg.com", "ebaystatic.com"]},
    {"id": "shein",     "name": "SHEIN",       "emoji": "👗", "category": "shopping",
     "domains": ["shein.com", "sheincdn.com", "ltwebstatic.com"]},
    {"id": "temu",      "name": "Temu",        "emoji": "🛒", "category": "shopping",
     "domains": ["temu.com", "kwcdn.com"]},

    # messaging
    {"id": "discord",   "name": "Discord",     "emoji": "💬", "category": "messaging",
     "domains": ["discord.com", "discord.gg", "discordapp.com", "discordapp.net",
                 "discord.media"]},
    {"id": "whatsapp",  "name": "WhatsApp",    "emoji": "💚", "category": "messaging",
     "domains": ["whatsapp.com", "whatsapp.net", "wa.me"]},
    {"id": "telegram",  "name": "Telegram",    "emoji": "✈️", "category": "messaging",
     "domains": ["telegram.org", "t.me", "telegram-cdn.org", "tdesktop.com"]},
    {"id": "messenger", "name": "Messenger",   "emoji": "💬", "category": "messaging",
     "domains": ["messenger.com"]},

    # ai
    {"id": "chatgpt",   "name": "ChatGPT",     "emoji": "🤖", "category": "ai",
     "domains": ["chatgpt.com", "openai.com", "oaistatic.com"]},
    {"id": "claude",    "name": "Claude",      "emoji": "🧠", "category": "ai",
     "domains": ["claude.ai", "anthropic.com"]},
    {"id": "characterai","name": "Character.ai","emoji": "🎭", "category": "ai",
     "domains": ["character.ai", "characterai.io"]},

    # adult
    {"id": "pornhub",   "name": "Pornhub",     "emoji": "🔞", "category": "adult",
     "domains": ["pornhub.com", "phncdn.com"]},
    {"id": "onlyfans",  "name": "OnlyFans",    "emoji": "🔞", "category": "adult",
     "domains": ["onlyfans.com"]},
]


APPS_BY_ID = {a["id"]: a for a in APPS}


def domains_for_apps(app_ids: list[str]) -> list[str]:
    """Flatten the union of every selected app's domains."""
    out: list[str] = []
    seen: set[str] = set()
    for app_id in app_ids:
        a = APPS_BY_ID.get(app_id)
        if not a:
            continue
        for d in a["domains"]:
            if d not in seen:
                seen.add(d)
                out.append(d)
    return out


def catalog_summary() -> dict[str, Any]:
    """Frontend-friendly catalog payload."""
    return {
        "categories": CATEGORIES,
        "apps": [
            {"id": a["id"], "name": a["name"], "emoji": a["emoji"],
             "category": a["category"]}
            for a in APPS
        ],
    }
