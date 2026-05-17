"""UniFi RouterAdapter (alpha).

Gated behind ``GUARDIUM_ENABLE_UNIFI_ALPHA=1`` until verified on real
hardware. See :mod:`server.routers.registry` for the gate logic.

Phase 2 scope (this commit): scaffolding only.

- Auth + read paths work (the legacy cookie+CSRF client logs in and
  can read sites + clients + Traffic Rules; the public API-key
  client, if configured, can also pull DPI categories and gateway
  model info for the readiness probe).
- :meth:`UnifiAdapter.list_clients` works and is wired into the
  reconciler's IP<->MAC discovery + MAC-anchored device migration.
- :meth:`apply_kill_switch` and :meth:`apply_doh_block` raise
  :class:`NotImplementedError`; they're implemented in Phase 3 / 4.
- :meth:`apply_dns_director` is a permanent no-op for this vendor --
  UniFi has no native per-MAC DNS redirect primitive; the adapter's
  capability flag is ``supports_dns_director=False`` so the reconciler
  skips this stage entirely on UniFi installs.
"""
from __future__ import annotations

import logging
from typing import Any, Mapping

from ..base import Capabilities, RouterAdapter, RouterClient
from .doh_apps import (
    discover_doh_app_ids,
    fallback_app_ids,
    load_cached_app_ids,
    save_cached_app_ids,
)
from .legacy_api import UnifiAuthError, UnifiError, UnifiLegacyApi
from .public_api import UnifiPublicApi, UnifiPublicApiError


log = logging.getLogger("dns-dashboard.routers.unifi")


# Settings key namespace. New install: user populates these via the
# Settings page. Migration from legacy ASUS installs is a no-op --
# their existing ``router.asus.*`` keys are untouched and the
# registry keeps using the ASUS adapter unless ``router.vendor`` is
# changed explicitly.
UNIFI_KEYS = {
    "host":             "router.unifi.host",
    "site":             "router.unifi.site",
    "username":         "router.unifi.username",
    "password":         "router.unifi.password",     # encrypted via SecretStore
    "api_key":          "router.unifi.api_key",      # encrypted via SecretStore
    "verify_tls":       "router.unifi.verify_tls",
    "doh_block_enabled": "router.unifi.doh_block_enabled",
    # Cached rule ids so we idempotently PUT instead of churning the
    # rule list every tick.
    "kill_switch_rule_id": "router.unifi.kill_switch_rule_id",
    "doh_block_rule_id":   "router.unifi.doh_block_rule_id",
    # What we put on the rule last tick.
    "managed_kill_macs": "router.unifi.managed_kill_macs",
    "managed_doh_macs":  "router.unifi.managed_doh_macs",
}


UNIFI_CAPABILITIES = Capabilities(
    supports_kill_switch=True,
    supports_dns_director=False,   # no native primitive on UniFi
    supports_doh_blocking=True,
    needs_ssh_for_doh=False,       # native Simple App Blocking, no SSH
)


class UnifiAdapter(RouterAdapter):
    vendor = "unifi"
    capabilities = UNIFI_CAPABILITIES

    def __init__(
        self,
        *,
        store: Any,
        secrets: Any,
        legacy: UnifiLegacyApi,
        public: UnifiPublicApi | None,
        site: str,
    ) -> None:
        self._store = store
        self._secrets = secrets
        self._legacy = legacy
        self._public = public
        self.site = site
        self._legacy_entered = False
        self._public_entered = False

    # ---- construction --------------------------------------------------

    @classmethod
    def from_store(cls, store: Any, secrets: Any) -> "UnifiAdapter | None":
        host = store.get_setting(UNIFI_KEYS["host"])
        username = store.get_setting(UNIFI_KEYS["username"])
        password = secrets.get(UNIFI_KEYS["password"])
        if not (host and username and password):
            return None
        site = store.get_setting(UNIFI_KEYS["site"]) or "default"
        verify_tls = store.get_setting(UNIFI_KEYS["verify_tls"]) == "1"
        api_key = secrets.get(UNIFI_KEYS["api_key"]) or None

        legacy = UnifiLegacyApi(
            host=host,
            username=username,
            password=password,
            site=site,
            verify_tls=verify_tls,
        )
        public = None
        if api_key:
            public = UnifiPublicApi(
                host=host,
                api_key=api_key,
                verify_tls=verify_tls,
            )

        return cls(
            store=store,
            secrets=secrets,
            legacy=legacy,
            public=public,
            site=site,
        )

    # ---- context manager ----------------------------------------------

    async def __aenter__(self) -> "UnifiAdapter":
        await self._legacy.__aenter__()
        self._legacy_entered = True
        if self._public is not None:
            try:
                await self._public.__aenter__()
                self._public_entered = True
            except Exception:  # noqa: BLE001
                log.warning("UniFi public API failed to open; continuing "
                            "without it (DPI discovery + gateway probe disabled)")
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._public_entered and self._public is not None:
            try:
                await self._public.__aexit__(exc_type, exc, tb)
            finally:
                self._public_entered = False
        if self._legacy_entered:
            try:
                await self._legacy.__aexit__(exc_type, exc, tb)
            finally:
                self._legacy_entered = False

    # ---- discovery -----------------------------------------------------

    async def list_clients(self) -> list[RouterClient]:
        try:
            raw = await self._legacy.list_clients()
        except UnifiError as exc:
            log.warning("UniFi list_clients failed: %s", exc)
            return []
        return [_to_router_client(c) for c in raw if c.get("mac")]

    async def list_sites(self) -> list[dict[str, Any]]:
        """Convenience for the Settings UI / probe script."""
        return await self._legacy.list_sites()

    async def list_traffic_rules(self) -> list[dict[str, Any]]:
        return await self._legacy.list_traffic_rules()

    async def probe_gateway(self) -> dict[str, Any]:
        """Return the controller's gateway model (best-effort).

        Used by the probe script and (eventually) the Settings UI to
        warn the user if their gateway can't run Simple App Blocking.
        Requires an API key; returns ``{"available": False, ...}`` if
        the public API isn't usable on this controller.
        """
        if self._public is None or not self._public_entered:
            return {
                "available": False,
                "reason": "no API key configured (public API unavailable)",
            }
        try:
            sites = await self._public.list_sites()
        except UnifiPublicApiError as exc:
            return {"available": False, "reason": str(exc)}
        if not sites:
            return {"available": False, "reason": "no sites returned"}
        # Pick the site whose human name matches our configured slug;
        # fall back to the first site so the probe still works on the
        # default-site case.
        chosen = next(
            (s for s in sites if s.get("name") == self.site or s.get("internalReference") == self.site),
            sites[0],
        )
        site_id = chosen.get("id") or chosen.get("siteId")
        if not site_id:
            return {"available": False, "reason": "site missing id field"}
        try:
            devices = await self._public.list_devices(site_id)
        except UnifiPublicApiError as exc:
            return {"available": False, "reason": str(exc)}
        gateways = [d for d in devices if _looks_like_gateway(d)]
        return {
            "available": True,
            "siteId": site_id,
            "siteName": chosen.get("name"),
            "gatewayCount": len(gateways),
            "gateways": [
                {"model": d.get("model"), "name": d.get("name"), "version": d.get("version")}
                for d in gateways
            ],
        }

    async def get_doh_app_ids(self) -> list[str]:
        """Discover (or read from cache) the DoH/DoT DPI app IDs.

        Tries discovery first (preferred -- IDs vary by firmware), then
        the cached list, then the hard-coded fallback. The result is
        cached so subsequent calls within the same tick (or across
        ticks) avoid a redundant network round-trip.
        """
        if self._public is not None and self._public_entered:
            try:
                ids = await discover_doh_app_ids(self._public)
                save_cached_app_ids(self._store, ids)
                return ids
            except UnifiPublicApiError as exc:
                log.warning("UniFi DPI discovery failed: %s", exc)
        cached = load_cached_app_ids(self._store)
        if cached:
            return cached
        return fallback_app_ids()

    # ---- stage application (Phase 3 / 4) ------------------------------

    async def apply_kill_switch(
        self,
        desired_macs: list[str],
        *,
        names: Mapping[str, str],
    ) -> dict[str, Any]:
        # Implemented in Phase 3.
        raise NotImplementedError(
            "UniFi Stage 1 (kill switch) is not implemented yet "
            "(coming in Phase 3 of the integration)."
        )

    async def apply_dns_director(
        self,
        desired_macs: list[str],
        *,
        names: Mapping[str, str],
    ) -> dict[str, Any]:
        # Permanent no-op on UniFi: no native per-MAC DNS redirect.
        # The capability flag should already cause the reconciler to
        # skip this call, but we return the unsupported sentinel as a
        # belt-and-braces measure if someone calls it directly.
        return {"enabled": False, "supported": False}

    async def apply_doh_block(
        self,
        desired_macs: list[str],
        *,
        names: Mapping[str, str],
    ) -> dict[str, Any]:
        # Implemented in Phase 4.
        raise NotImplementedError(
            "UniFi Stage 3 (DoH block) is not implemented yet "
            "(coming in Phase 4 of the integration)."
        )


def _to_router_client(raw: dict[str, Any]) -> RouterClient:
    """Normalise a UniFi ``stat/sta`` row into our vendor-agnostic
    :class:`RouterClient`.

    Hostname source preference (UniFi keeps several copies for backwards
    compatibility, not all populated): ``name`` > ``hostname`` >
    ``oui`` (vendor as last-resort label).
    """
    mac = str(raw.get("mac") or "").lower()
    ip = raw.get("ip") or raw.get("last_ip") or None
    name = raw.get("name") or raw.get("hostname") or None
    online = bool(raw.get("is_wired") or raw.get("uptime"))
    return RouterClient(
        mac=mac,
        ip=str(ip) if ip else None,
        name=str(name) if name else None,
        online=online,
        raw=raw,
    )


def _looks_like_gateway(device: dict[str, Any]) -> bool:
    """Best-effort gateway detection from the public ``/v1/sites/.../devices``
    response. The integration API doesn't surface a stable "role" field
    so we sniff the model + name.
    """
    model = str(device.get("model") or "").upper()
    name = str(device.get("name") or "").upper()
    # Known gateway-family model prefixes. Extend if a tester finds a
    # model that's missed by this list.
    gw_prefixes = (
        "UDM", "UDR", "UCG", "UXG", "USG", "EFG", "UGW", "CK-",
    )
    if any(model.startswith(p) for p in gw_prefixes):
        return True
    if "GATEWAY" in name or "ROUTER" in name:
        return True
    return False


__all__ = [
    "UNIFI_KEYS",
    "UNIFI_CAPABILITIES",
    "UnifiAdapter",
    "UnifiAuthError",
    "UnifiError",
    "UnifiPublicApi",
    "UnifiPublicApiError",
]
