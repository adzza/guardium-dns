"""Single factory the rest of the dashboard uses to obtain a router adapter.

The active vendor is selected by the ``router.vendor`` setting
(``"asus"`` | ``"unifi"`` | unset). For legacy installs the first call
auto-detects ``"asus"`` if the user already has ``router.asus.host``
saved, so no manual migration is required.

UniFi support is opt-in alpha until verified on real hardware: the
``GUARDIUM_ENABLE_UNIFI_ALPHA`` environment variable must be set to
``"1"`` for the registry to even consider the UniFi vendor. See
:doc:`README` for the rollout plan.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from .base import RouterAdapter


log = logging.getLogger("dns-dashboard.routers")


VENDOR_SETTING_KEY = "router.vendor"

_VALID_VENDORS = {"asus", "unifi"}


def _resolve_vendor(store: Any) -> str | None:
    """Return the active vendor id, honouring the legacy auto-detect.

    The ``"none"`` value is treated as an explicit opt-out and is NOT
    overridden by the legacy auto-detect, so a user who deliberately
    picked "None" in Settings keeps that choice even if they still
    have stale ASUS credentials saved.

    Side effect: when no value is saved at all and ``router.asus.host``
    is, persists ``router.vendor = "asus"`` so subsequent reads are
    explicit.
    """
    vendor = (store.get_setting(VENDOR_SETTING_KEY) or "").strip().lower()
    if vendor in _VALID_VENDORS:
        return vendor
    if vendor == "none":
        return None
    if not vendor and store.get_setting("router.asus.host"):
        store.set_setting(VENDOR_SETTING_KEY, "asus")
        log.info("router vendor auto-migrated to 'asus' (legacy install)")
        return "asus"
    return None


def _unifi_alpha_enabled() -> bool:
    return os.environ.get("GUARDIUM_ENABLE_UNIFI_ALPHA", "").strip() == "1"


def get_adapter(store: Any, secrets: Any) -> RouterAdapter | None:
    """Build the configured router adapter, or ``None`` if not yet set up.

    The reconciler calls this once per tick.
    """
    vendor = _resolve_vendor(store)
    if vendor is None:
        return None

    if vendor == "asus":
        from .asus import AsusAdapter
        return AsusAdapter.from_store(store, secrets)

    if vendor == "unifi":
        if not _unifi_alpha_enabled():
            log.warning(
                "router.vendor=unifi but GUARDIUM_ENABLE_UNIFI_ALPHA is not "
                "set; refusing to load the alpha UniFi adapter."
            )
            return None
        # Imported lazily so the rest of the dashboard keeps working
        # even if the UniFi adapter ever fails to import (missing dep
        # in a stripped-down build, etc.).
        try:
            from .unifi import UnifiAdapter
        except ImportError:
            log.exception("UniFi adapter import failed; treating as not configured")
            return None
        return UnifiAdapter.from_store(store, secrets)

    return None
