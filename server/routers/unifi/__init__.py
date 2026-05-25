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

import hashlib
import json
import logging
from typing import Any, Mapping

from ..base import Capabilities, RouterAdapter, RouterClient
from .doh_apps import (
    discover_doh_app_ids,
    fallback_app_ids,
    load_cached_app_ids,
    save_cached_app_ids,
)
from .legacy_api import (
    UnifiAuthError,
    UnifiError,
    UnifiLegacyApi,
    UnifiNotFound,
)
from .public_api import UnifiPublicApi, UnifiPublicApiError
from . import traffic_rule as tr


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
    # Body-hash signatures so we can detect non-MAC field changes
    # (e.g. firmware-updated DPI app IDs in the DoH rule) and re-push.
    "kill_switch_body_hash": "router.unifi.kill_switch_body_hash",
    "doh_block_body_hash":   "router.unifi.doh_block_body_hash",
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
        """Stage 1 on UniFi: single managed Traffic Rule blocking the
        Internet for every MAC in ``desired_macs``.

        Idempotent: PUT-updates the cached row when possible, falls
        back to discovery-by-name, then to creation. Persists
        ``router.unifi.kill_switch_rule_id`` and
        ``router.unifi.managed_kill_macs`` so subsequent ticks know
        what we last pushed.
        """
        return await self._apply_managed_rule(
            stage="kill",
            desired_macs=desired_macs,
            body_builder=tr.build_kill_switch_rule,
            managed_name=tr.KILL_SWITCH_NAME,
            id_setting=UNIFI_KEYS["kill_switch_rule_id"],
            macs_setting=UNIFI_KEYS["managed_kill_macs"],
            body_hash_setting=UNIFI_KEYS["kill_switch_body_hash"],
            extra_status={"matching_target": "INTERNET"},
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
        """Stage 3 on UniFi: a single managed Traffic Rule that drops
        traffic from ``desired_macs`` to the controller's DoH / DoT
        application signatures (matching_target=APP).

        Requires the ``router.unifi.doh_block_enabled`` toggle to be on.
        When it's off, any previously-managed rule is *deleted* (not
        just disabled) so the user's controller UI is left clean. The
        cached rule id is cleared so re-enabling creates a fresh row.
        """
        enabled = self._store.get_setting(
            UNIFI_KEYS["doh_block_enabled"]
        ) == "1"
        cached_id = (
            self._store.get_setting(UNIFI_KEYS["doh_block_rule_id"]) or ""
        ).strip() or None
        prev_macs = self._load_managed(UNIFI_KEYS["managed_doh_macs"])

        if not enabled:
            return await self._teardown_doh_block(
                cached_id=cached_id,
                prev_macs=prev_macs,
            )

        # Push path: needs app IDs.
        try:
            app_ids = await self.get_doh_app_ids()
        except Exception as exc:  # noqa: BLE001
            log.warning("UniFi DoH app discovery failed: %s", exc)
            return {
                "enabled": True, "stage": "doh",
                "error": f"DoH app discovery failed: {exc}",
            }
        if not app_ids:
            return {
                "enabled": True, "stage": "doh",
                "error": "no DoH/DoT app IDs available "
                         "(DPI discovery and the hard-coded fallback both came up empty)",
            }

        def body_builder(macs: list[str]) -> dict[str, Any]:
            return tr.build_doh_block_rule(macs, app_ids)

        result = await self._apply_managed_rule(
            stage="doh",
            desired_macs=desired_macs,
            body_builder=body_builder,
            managed_name=tr.DOH_BLOCK_NAME,
            id_setting=UNIFI_KEYS["doh_block_rule_id"],
            macs_setting=UNIFI_KEYS["managed_doh_macs"],
            body_hash_setting=UNIFI_KEYS["doh_block_body_hash"],
            extra_status={
                "matching_target": "APP",
                "appIds": list(app_ids),
            },
        )
        return result

    async def _teardown_doh_block(
        self,
        *,
        cached_id: str | None,
        prev_macs: list[str],
    ) -> dict[str, Any]:
        """Stage-3 OFF: if we left a managed rule on the controller,
        delete it. Idempotent -- safe to call when there's nothing to
        do.
        """
        if not (cached_id or prev_macs):
            return {"enabled": False, "stage": "doh"}

        deleted = False
        if cached_id:
            try:
                await self._legacy.delete_traffic_rule(cached_id)
                deleted = True
            except UnifiError as exc:
                log.warning("UniFi DoH rule delete failed: %s", exc)
                return {
                    "enabled": False, "stage": "doh",
                    "torn_down": False, "error": str(exc),
                }
            else:
                log.info("UniFi DoH rule %s deleted (tear-down)", cached_id)

        self._store.set_setting(UNIFI_KEYS["doh_block_rule_id"], None)
        self._store.set_setting(UNIFI_KEYS["managed_doh_macs"], "[]")
        self._store.set_setting(UNIFI_KEYS["doh_block_body_hash"], None)
        return {
            "enabled": False, "stage": "doh",
            "torn_down": True,
            "deletedRuleId": cached_id if deleted else None,
        }

    # ---- shared rule plumbing -----------------------------------------

    async def _apply_managed_rule(
        self,
        *,
        stage: str,
        desired_macs: list[str],
        body_builder,
        managed_name: str,
        id_setting: str,
        macs_setting: str,
        body_hash_setting: str | None = None,
        extra_status: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Idempotently push a single managed Traffic Rule.

        Shared between Stage 1 (kill switch) and Stage 3 (DoH block).
        Lifecycle:

        1. Normalise + sort ``desired_macs``.
        2. Build the desired rule body via ``body_builder(macs)`` and
           hash it (stable JSON serialisation). Stage 3 needs the
           full-body hash because the rule body's ``app_ids`` can
           change between ticks if the controller's DPI catalogue is
           updated; Stage 1's body depends only on MACs so the hash
           is equivalent to the MAC-set diff.
        3. Resolve the rule's ``_id``: prefer the cached setting; fall
           back to scanning existing rules for one with our managed
           name (so a process restart doesn't lose track of the row);
           else None (will create).
        4. Short-circuit if the body hash matches what we last pushed
           AND we already have a cached ``_id``.
        5. PUT to update, or POST to create. PUT that comes back 404
           is treated as "the user deleted our row" and falls through
           to a fresh POST.
        6. Persist the new ``_id``, MAC set and body hash so the next
           tick can short-circuit if nothing's changed.

        Exceptions never propagate; failures are returned as an error
        field in the status dict so the reconciler can keep ticking.
        """
        desired_sorted = sorted({
            n for n in (_normalize_mac(m) for m in desired_macs) if n
        })
        prev_macs = self._load_managed(macs_setting)
        cached_id = (self._store.get_setting(id_setting) or "").strip() or None

        body = body_builder(desired_sorted)
        body_hash = _hash_body(body)
        prev_hash = (
            self._store.get_setting(body_hash_setting) or ""
            if body_hash_setting else ""
        )

        if cached_id and body_hash == prev_hash and desired_sorted == prev_macs:
            status: dict[str, Any] = {
                "enabled": True,
                "stage": stage,
                "macs": desired_sorted,
                "ruleId": cached_id,
                "skipped": "no-change",
            }
            if extra_status:
                status.update(extra_status)
            return status

        # If we don't have a cached id, scan existing rules for one we
        # apparently own. Cheap insurance against losing the cached id
        # (e.g. data/ wiped, user restored from old backup).
        if cached_id is None:
            try:
                cached_id = await self._discover_managed_rule_id(managed_name)
            except UnifiError as exc:
                log.warning("UniFi list_traffic_rules failed: %s", exc)
                return {
                    "enabled": True, "stage": stage,
                    "error": f"could not list rules: {exc}",
                }

        rule_id = cached_id
        action_taken = "noop"

        try:
            if rule_id:
                try:
                    await self._legacy.update_traffic_rule(rule_id, body)
                    action_taken = "updated"
                except UnifiNotFound:
                    log.info("UniFi managed rule %s gone; recreating", rule_id)
                    rule_id = None  # fall through to create
            if rule_id is None:
                created = await self._legacy.create_traffic_rule(body)
                rule_id = str(created.get("_id") or created.get("id") or "")
                if not rule_id:
                    return {
                        "enabled": True, "stage": stage,
                        "error": "controller did not return _id for new rule",
                    }
                action_taken = "created"
        except UnifiError as exc:
            log.warning("UniFi %s rule push failed: %s", stage, exc)
            return {"enabled": True, "stage": stage, "error": str(exc)}

        # Persist.
        self._store.set_setting(id_setting, rule_id)
        self._store.set_setting(macs_setting, json.dumps(desired_sorted))
        if body_hash_setting:
            self._store.set_setting(body_hash_setting, body_hash)

        log.info(
            "UniFi %s rule %s (%s): %d MAC(s)",
            stage, rule_id, action_taken, len(desired_sorted),
        )

        status = {
            "enabled": True,
            "stage": stage,
            "macs": desired_sorted,
            "ruleId": rule_id,
            "action": action_taken,
            "ruleEnabled": bool(body.get("enabled")),
        }
        if extra_status:
            status.update(extra_status)
        return status

    async def _discover_managed_rule_id(self, managed_name: str) -> str | None:
        """Find an existing rule with the given managed name, if any."""
        rules = await self._legacy.list_traffic_rules()
        for r in rules:
            if str(r.get("name") or "") == managed_name:
                rid = r.get("_id") or r.get("id")
                if rid:
                    return str(rid)
        return None

    def _load_managed(self, setting_key: str) -> list[str]:
        raw = self._store.get_setting(setting_key) or "[]"
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return [str(x) for x in parsed] if isinstance(parsed, list) else []


def _hash_body(body: dict[str, Any]) -> str:
    """Stable hash of a rule body, used for the skip-if-same check.

    The body dict is JSON-serialised with ``sort_keys`` so identical
    semantics produce the same hash regardless of dict iteration
    order. We use SHA-256 over the encoded bytes -- overkill
    cryptographically but cheap and free of collision worries.
    """
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _normalize_mac(raw: str | None) -> str | None:
    """Return ``aa:bb:cc:dd:ee:ff`` form, or ``None`` if not a MAC.

    Tolerates dash-separated, mixed-case, and surrounding whitespace.
    """
    if not raw:
        return None
    m = raw.replace("-", ":").strip().lower()
    if m.count(":") != 5:
        return None
    return m


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
