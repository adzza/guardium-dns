"""Built-in parental control profiles.

Each profile maps to a *group* in the Technitium "Advanced Blocking" app. The
dashboard owns these by name -- it only ever overwrites groups whose names are
listed in :data:`MANAGED_GROUP_NAMES`. User-created groups in Technitium are
left untouched.
"""
from __future__ import annotations

from typing import Any

DEFAULT_GROUP = "default"
KILL_SWITCH_GROUP = "internet-off"
UNRESTRICTED_GROUP = "unrestricted"


def _empty_group(
    name: str,
    *,
    enable_blocking: bool = True,
    block_lists: list[str] | None = None,
    blocked_regex: list[str] | None = None,
    blocked: list[str] | None = None,
) -> dict[str, Any]:
    # We sinkhole blocked queries to 0.0.0.0 / :: instead of NXDOMAIN. Two
    # reasons:
    # 1. Defense-in-depth against DoH bootstrap. A client trying to connect to
    #    `dns.google` for DoH that gets 0.0.0.0 attempts the connection and
    #    fails immediately, with no opportunity to retry a secondary resolver
    #    on a "not found" error.
    # 2. Some Smart-TV / IoT clients fall back to a hardcoded DNS server on
    #    NXDOMAIN. Returning a (broken) IP looks like a successful resolution
    #    to those clients and tends to keep them stuck on us.
    # Non-A/AAAA queries (TXT/MX/SRV/CAA/etc.) still return NXDOMAIN because
    # an IP doesn't make sense as an answer for those record types.
    return {
        "name": name,
        "enableBlocking": enable_blocking,
        "allowTxtBlockingReport": True,
        "blockAsNxDomain": False,
        "blockingAddresses": ["0.0.0.0", "::"],
        "allowed": [],
        "blocked": blocked or [],
        "allowListUrls": [],
        "blockListUrls": block_lists or [],
        "allowedRegex": [],
        "blockedRegex": blocked_regex or [],
        "regexAllowListUrls": [],
        "regexBlockListUrls": [],
        "adblockListUrls": [],
    }


# -- Block list URL inventory --------------------------------------------------
# These are well-known, free, community-maintained block lists. The dashboard
# only references URLs by string; Technitium handles the actual fetching and
# refresh on its configured schedule.

ADS_TRACKERS = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]
ADULT = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
]
SOCIAL = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts",
]
GAMBLING = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",
]
FAKE_NEWS = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-only/hosts",
]

# Streaming / Gaming / YouTube domains are explicitly listed (no good
# consolidated host files exist that don't also block adjacent legitimate
# services).
#
# NOTE: Technitium's Advanced Blocking app matches the exact domain AND any
# subdomain. So `youtube.com` covers `www.youtube.com`, `m.youtube.com`,
# `studio.youtube.com`, etc. -- you don't need to list every subdomain.

YOUTUBE_DOMAINS = [
    "youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "youtubekids.com",
    "googlevideo.com",        # CDN that streams the actual video bytes
    "ytimg.com",              # thumbnails / static assets
    "ggpht.com",              # avatars / channel art
    "youtubei.googleapis.com",
    "yt3.googleusercontent.com",
    "yt4.googleusercontent.com",
    "tv.youtube.com",
    "music.youtube.com",
    "studio.youtube.com",
]

# DNS-over-HTTPS / DNS-over-TLS providers and Apple iCloud Private Relay
# bootstrap domains. Blocking these at the DNS layer prevents DoH from
# *activating* in the first place, so subsequent traffic is forced to use the
# system resolver (= Technitium) -- where our profiles take effect.
#
# This is not bullet-proof. Devices with hardcoded resolver IPs (Chrome's
# baked-in DoH, dig @1.1.1.1 etc.) can still bypass us; for those you need a
# firewall rule on the gateway. But blocking the bootstrap domains stops every
# OS-level "Private DNS" / "Encrypted DNS" feature on Apple, Android, Chrome,
# Firefox, Edge, etc. from kicking in.
DOH_BOOTSTRAP_DOMAINS = [
    # Apple iCloud Private Relay
    "mask.icloud.com",
    "mask-h2.icloud.com",
    "mask-api.icloud.com",
    "mask-api.fe.apple-dns.net",
    # Cloudflare 1.1.1.1
    "cloudflare-dns.com",
    "one.one.one.one",
    "mozilla.cloudflare-dns.com",
    "chrome.cloudflare-dns.com",
    "1dot1dot1dot1.cloudflare-dns.com",
    # Google Public DNS
    "dns.google",
    "dns.google.com",
    # Quad9
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    # NextDNS
    "dns.nextdns.io",
    # OpenDNS / Cisco Umbrella
    "doh.opendns.com",
    "doh.familyshield.opendns.com",
    "doh.cleanbrowsing.org",
    # AdGuard
    "dns.adguard.com",
    "dns-family.adguard.com",
    # Mullvad / others
    "doh.mullvad.net",
    "dns.mullvad.net",
    "dns.controld.com",
    # Microsoft / Office 365 Private Resolver bootstrap
    "doh.microsoft-dns.com",
]

STREAMING_DOMAINS = [
    "netflix.com",
    "nflxvideo.net",
    "nflximg.net",
    # YouTube domains are added separately via YOUTUBE_DOMAINS
    "disneyplus.com",
    "disney-plus.net",
    "bamgrid.com",
    "hulu.com",
    "hulustream.com",
    "primevideo.com",
    "aiv-cdn.net",
    "twitch.tv",
    "ttvnw.net",
    "tiktok.com",
    "tiktokcdn.com",
    "spotify.com",
    "scdn.co",
    "stan.com.au",
    "binge.com.au",
    "kayosports.com.au",
    "9now.com.au",
    "10play.com.au",
    "7plus.com.au",
    "iview.abc.net.au",
    "sbs.com.au",
]
GAMING_DOMAINS = [
    "steampowered.com",
    "steamcommunity.com",
    "steamserver.net",
    "steamcontent.com",
    "epicgames.com",
    "ol.epicgames.com",
    "fortnite.com",
    "xboxlive.com",
    "xbox.com",
    "playstation.com",
    "playstation.net",
    "sonyentertainmentnetwork.com",
    "nintendo.net",
    "nintendo.com",
    "roblox.com",
    "rbxcdn.com",
    "minecraft.net",
    "mojang.com",
    "ea.com",
    "easports.com",
    "battle.net",
    "blizzard.com",
    "riotgames.com",
    "leagueoflegends.com",
    "ubisoft.com",
    "ubi.com",
    "discord.com",
    "discord.gg",
    "discordapp.com",
]


# -- Profile definitions -------------------------------------------------------

PROFILES: dict[str, dict[str, Any]] = {
    "unrestricted": {
        "label": "Unrestricted",
        "short": "Open",
        "emoji": "🌐",
        "tagline": "No blocking. Use for trusted devices.",
        "description": "No DNS-level blocking from this profile. Use for trusted devices.",
        "icon": "shield-off",
        "color": "slate",
        "group": _empty_group("unrestricted", enable_blocking=False),
    },
    "default": {
        "label": "Default",
        "short": "Default",
        "emoji": "🛡️",
        "tagline": "Ads, trackers and DoH bypass blocked. Recommended baseline.",
        "description": "Blocks ads, trackers, malicious domains, and DoH/Private Relay bootstrap. Recommended baseline.",
        "icon": "shield-check",
        "color": "blue",
        "group": _empty_group(
            "default",
            block_lists=ADS_TRACKERS,
            blocked=DOH_BOOTSTRAP_DOMAINS,
        ),
    },
    "kids": {
        "label": "Kids (child-safe)",
        "short": "Kids",
        "emoji": "🧒",
        "tagline": "Adult content, social media, gambling, fake-news and YouTube blocked.",
        "description": "Default + adult content, social media, gambling, fake-news, YouTube, and Apple Private Relay / DoH bootstrap.",
        "icon": "heart",
        "color": "pink",
        "group": _empty_group(
            "kids",
            block_lists=ADS_TRACKERS + ADULT + SOCIAL + GAMBLING + FAKE_NEWS,
            blocked=DOH_BOOTSTRAP_DOMAINS + YOUTUBE_DOMAINS,
        ),
    },
    "no-youtube": {
        "label": "No YouTube",
        "short": "No YT",
        "emoji": "📵",
        "tagline": "YouTube, YT Kids and YT Music blocked. Everything else works.",
        "description": "Blocks YouTube, YouTube Kids, YouTube Music, googlevideo.com, ytimg.com and all related Google video CDNs. Default ad/tracker blocking and DoH bootstrap also applied so YouTube apps can't bypass via encrypted DNS.",
        "icon": "youtube-off",
        "color": "rose",
        "group": _empty_group(
            "no-youtube",
            block_lists=ADS_TRACKERS,
            blocked=YOUTUBE_DOMAINS + DOH_BOOTSTRAP_DOMAINS,
        ),
    },
    "no-streaming": {
        "label": "No streaming",
        "short": "No stream",
        "emoji": "📺",
        "tagline": "Netflix, YouTube, Disney+, Twitch, Spotify and friends blocked.",
        "description": "Default + Netflix, YouTube, Disney+, Hulu, Twitch, Spotify, Stan, Binge, Kayo, etc. Also blocks DoH bootstrap so streaming apps can't bypass.",
        "icon": "tv-off",
        "color": "purple",
        "group": _empty_group(
            "no-streaming",
            block_lists=ADS_TRACKERS,
            blocked=STREAMING_DOMAINS + YOUTUBE_DOMAINS + DOH_BOOTSTRAP_DOMAINS,
        ),
    },
    "no-gaming": {
        "label": "No gaming",
        "short": "No game",
        "emoji": "🎮",
        "tagline": "Steam, Epic, Xbox Live, PSN, Roblox and Discord blocked.",
        "description": "Default + Steam, Epic, Xbox Live, PSN, Roblox, Discord, Battle.net. Also blocks DoH bootstrap.",
        "icon": "gamepad-2",
        "color": "amber",
        "group": _empty_group(
            "no-gaming",
            block_lists=ADS_TRACKERS,
            blocked=GAMING_DOMAINS + DOH_BOOTSTRAP_DOMAINS,
        ),
    },
    "internet-off": {
        "label": "Internet off",
        "short": "OFF",
        "emoji": "⛔",
        "tagline": "Kill switch. Blocks every DNS lookup. Wi-Fi toggle helps it kick in.",
        "description": "Kill switch. Blocks every DNS lookup for this device, including Apple Private Relay and DoH bootstrap so encrypted DNS can't bypass it. Tip: toggle Wi-Fi on the device to clear its DNS cache and drop persistent connections.",
        "icon": "power",
        "color": "red",
        "group": _empty_group(
            "internet-off",
            blocked_regex=[".*"],
            blocked=DOH_BOOTSTRAP_DOMAINS,
        ),
    },
}

MANAGED_GROUP_NAMES = {p["group"]["name"] for p in PROFILES.values()}


# A list of domain *substrings* that we'd expect to see blocked when a profile
# is applied to a device. Used by the /diagnose endpoint to assess whether a
# device's profile is actually firing in practice.
EXPECTED_BLOCK_PATTERNS: dict[str, list[str]] = {
    "no-youtube":   ["youtube", "googlevideo", "ytimg", "ggpht"],
    "no-streaming": ["youtube", "googlevideo", "netflix", "nflx", "disney",
                      "twitch", "ttvnw", "tiktok", "spotify", "scdn"],
    "no-gaming":    ["steam", "epicgames", "xboxlive", "playstation",
                      "roblox", "rbxcdn", "discord", "battle.net"],
    "kids":         ["youtube", "googlevideo", "ytimg"],
    "default":      [],
    "unrestricted": [],
    "internet-off": [],
}


def profile_summary() -> list[dict[str, Any]]:
    """Frontend-friendly list of profiles (no group config payload)."""
    return [
        {
            "id": pid,
            "label": p["label"],
            "short": p.get("short", p["label"]),
            "emoji": p.get("emoji", "•"),
            "tagline": p.get("tagline", p["description"]),
            "description": p["description"],
            "icon": p["icon"],
            "color": p["color"],
            "groupName": p["group"]["name"],
        }
        for pid, p in PROFILES.items()
    ]
