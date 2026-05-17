"""DPI discovery: find the UniFi application IDs for DoH / DoT.

UniFi's Simple App Blocking takes a list of application IDs from the
controller's DPI catalogue and tells the gateway to drop matching
flows. The catalogue is curated by Ubiquiti and the IDs are stable
*within* a firmware version but not necessarily across them, so we
discover at runtime rather than hard-coding.

Discovery strategy::

    1. Try the public ``/integration/v1/dpi/applications`` endpoint if
       the user supplied an API key.
    2. Fall back to a hard-coded last-known-good list if discovery
       fails for any reason (no key, public API not available on
       legacy standalones, network error, etc.).
    3. Cache the discovered list to a settings key so we don't repeat
       the round-trip on every tick.

We match by case-insensitive substring against the application's
``name`` (and a couple of common aliases) so the list is robust to
small label changes between firmware versions.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from .public_api import UnifiPublicApi, UnifiPublicApiError


log = logging.getLogger("dns-dashboard.routers.unifi.doh")


SETTING_KEY = "router.unifi.doh_app_ids"


# Substrings (lower-case) that identify the DoH / DoT signatures in the
# DPI catalogue. We block both -- a TV that's defeated for DoH will
# happily fall back to DoT if we let it.
_MATCH_TERMS: tuple[str, ...] = (
    "dns over https",
    "doh",
    "dns over tls",
    "dot ",        # "DoT " with trailing space -- avoids matching "robot" etc.
    " dot",        # leading-space variant
)


# Best-effort fallback. These IDs are from controllers running
# Network Application 8.x and the UDM/UDM-Pro/UCG firmware as of
# 2025; they may not match older or much newer firmware. The
# discovery path above is preferred; this list only kicks in when
# discovery fails AND the user hasn't already accepted a discovered
# list previously cached in the store.
_FALLBACK_APP_IDS: tuple[str, ...] = (
    "551",   # "DNS over HTTPS" (observed on 8.x UDM-Pro)
    "552",   # "DNS over TLS"   (observed on 8.x UDM-Pro)
)


def _matches(name: str) -> bool:
    n = name.lower()
    return any(term in n for term in _MATCH_TERMS)


async def discover_doh_app_ids(public: UnifiPublicApi) -> list[str]:
    """Hit the public API and return DPI application IDs that match
    the DoH / DoT signatures.

    Raises :class:`UnifiPublicApiError` on hard failure so the caller
    can decide whether to fall back to the cached or hard-coded list.
    """
    apps = await public.list_dpi_applications()
    ids: list[str] = []
    seen: set[str] = set()
    for app in apps:
        name = str(app.get("name") or "")
        if not _matches(name):
            continue
        app_id = app.get("id") or app.get("appId") or app.get("application_id")
        if app_id is None:
            continue
        sid = str(app_id)
        if sid in seen:
            continue
        seen.add(sid)
        ids.append(sid)
        log.info("UniFi DPI: matched DoH/DoT app id=%s name=%r", sid, name)
    if not ids:
        log.warning(
            "UniFi DPI discovery returned no DoH/DoT app matches; "
            "falling back to hard-coded IDs %s", _FALLBACK_APP_IDS,
        )
        ids = list(_FALLBACK_APP_IDS)
    return ids


def load_cached_app_ids(store: Any) -> list[str] | None:
    raw = store.get_setting(SETTING_KEY)
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, list) or not all(isinstance(x, (str, int)) for x in parsed):
        return None
    return [str(x) for x in parsed]


def save_cached_app_ids(store: Any, ids: list[str]) -> None:
    store.set_setting(SETTING_KEY, json.dumps([str(x) for x in ids]))


def fallback_app_ids() -> list[str]:
    """Best-effort hard-coded list. Use only when both discovery and
    the cache are unavailable.
    """
    return list(_FALLBACK_APP_IDS)
