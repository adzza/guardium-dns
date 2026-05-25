"""ASUS RouterAdapter implementation.

Wraps :mod:`.http_client` and :mod:`.ssh_client` (which are unchanged
from when they lived directly under ``server/``) in the vendor-agnostic
:class:`server.routers.base.RouterAdapter` contract.

The adapter owns:
- the HTTP session lifecycle (a fresh login per tick, same as before),
- the SSH session lifecycle (opened on-demand inside
  :meth:`AsusAdapter.apply_doh_block`),
- vendor-namespaced persistence of "what we pushed last time" (under
  ``router.asus.managed_kill_macs`` / ``managed_dns_macs`` /
  ``managed_doh_macs``).

Behaviour is byte-identical to the pre-refactor implementation in
:mod:`server.reconciler` -- this module exists to relocate that logic,
not to change it.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Mapping

from ..base import Capabilities, RouterAdapter, RouterClient
from .http_client import (
    AsusRouterClient,
    AsusRouterError,
    detect_router_endpoint,
)
from .ssh_client import AsusSshClient, AsusSshError, SshConfig


log = logging.getLogger("dns-dashboard.routers.asus")


# Settings key namespace. The first three are the existing keys from the
# original reconciler -- preserved verbatim so installed dashboards
# pick up their existing state without any migration.
ASUS_KEYS = {
    "host":     "router.asus.host",
    "username": "router.asus.username",
    "password": "router.asus.password",  # encrypted via SecretStore
    "scheme":   "router.asus.scheme",
    "port":     "router.asus.port",
    "enabled":  "router.asus.enabled",
    "dns_director_enabled": "router.asus.dns_director_enabled",
    "dns_director_ip":      "router.asus.dns_director_ip",
    "ssh_enabled":          "router.asus.ssh_enabled",
    "ssh_port":             "router.asus.ssh_port",
    "ssh_password":         "router.asus.ssh_password",  # encrypted
    "doh_block_enabled":    "router.asus.doh_block_enabled",
    # Reconciliation state: what we *pushed* last time. Used to merge
    # cleanly with rules the user added by hand in the router web UI.
    "managed_kill_macs":    "router.asus.managed_macs",        # legacy key
    "managed_dns_macs":     "router.asus.managed_dns_macs",
    "managed_doh_macs":     "router.asus.managed_doh_macs",
}


ASUS_CAPABILITIES = Capabilities(
    supports_kill_switch=True,
    supports_dns_director=True,
    supports_doh_blocking=True,
    needs_ssh_for_doh=True,
)


def _load_managed(store: Any, key: str) -> list[str]:
    raw = store.get_setting(key) or "[]"
    try:
        v = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [str(x) for x in v] if isinstance(v, list) else []


class AsusAdapter(RouterAdapter):
    vendor = "asus"
    capabilities = ASUS_CAPABILITIES

    def __init__(
        self,
        store: Any,
        secrets: Any,
        *,
        http: AsusRouterClient,
        ssh_host: str,
        ssh_username: str,
        ssh_password: str | None,
        ssh_port: int,
    ) -> None:
        self._store = store
        self._secrets = secrets
        self._http = http
        self._http_entered = False
        self._ssh_host = ssh_host
        self._ssh_username = ssh_username
        self._ssh_password = ssh_password
        self._ssh_port = ssh_port
        # In-memory skip-if-same caches survive across calls *within* a
        # single tick. Adapters are rebuilt every tick by the registry,
        # so these are effectively per-tick caches -- the underlying
        # apply paths still diff against persisted state for correctness.
        self._last_kill_push: tuple[str, ...] | None = None
        self._last_doh_push:  tuple[str, ...] | None = None

    # ---- construction --------------------------------------------------

    @classmethod
    def from_store(cls, store: Any, secrets: Any) -> "AsusAdapter | None":
        """Build an adapter from saved settings, or ``None`` if the
        user hasn't completed the router configuration yet.
        """
        host = store.get_setting(ASUS_KEYS["host"])
        username = store.get_setting(ASUS_KEYS["username"])
        password = secrets.get(ASUS_KEYS["password"])
        enabled = store.get_setting(ASUS_KEYS["enabled"]) == "1"
        if not (enabled and host and username and password):
            return None
        scheme = store.get_setting(ASUS_KEYS["scheme"]) or "http"
        port_raw = store.get_setting(ASUS_KEYS["port"])
        port = int(port_raw) if port_raw and port_raw.isdigit() else None
        http = AsusRouterClient(
            host=host,
            username=username,
            password=password,
            scheme=scheme,
            port=port,
        )
        ssh_port_raw = store.get_setting(ASUS_KEYS["ssh_port"])
        ssh_port = int(ssh_port_raw) if ssh_port_raw and ssh_port_raw.isdigit() else 2222
        ssh_password = (
            secrets.get(ASUS_KEYS["ssh_password"])
            or secrets.get(ASUS_KEYS["password"])
        )
        return cls(
            store=store,
            secrets=secrets,
            http=http,
            ssh_host=host,
            ssh_username=username,
            ssh_password=ssh_password,
            ssh_port=ssh_port,
        )

    # ---- context manager ----------------------------------------------

    async def __aenter__(self) -> "AsusAdapter":
        await self._http.__aenter__()
        self._http_entered = True
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._http_entered:
            await self._http.__aexit__(exc_type, exc, tb)
            self._http_entered = False

    # ---- discovery -----------------------------------------------------

    async def list_clients(self) -> list[RouterClient]:
        clients = await self._http.list_clients()
        return [
            RouterClient(
                mac=c.mac,
                ip=c.ip,
                name=c.name,
                online=c.online,
                raw=c.raw,
            )
            for c in clients
        ]

    # ---- Stage 1: kill switch -----------------------------------------

    async def apply_kill_switch(
        self,
        desired_macs: list[str],
        *,
        names: Mapping[str, str],
    ) -> dict[str, Any]:
        desired_sorted = sorted(desired_macs)
        desired_tuple = tuple(desired_sorted)
        previously_managed = _load_managed(self._store, ASUS_KEYS["managed_kill_macs"])

        # Skip-if-same within a single adapter lifetime.
        if (self._last_kill_push is not None
                and desired_tuple == self._last_kill_push):
            return {
                "enabled": True,
                "blocked": list(desired_tuple),
                "changed": False,
                "skipped": "no-change",
            }

        try:
            report = await self._http.apply_managed_blocked_macs(
                desired_macs,
                previously_managed=previously_managed,
                names=dict(names),
            )
        except AsusRouterError as exc:
            log.warning("ASUS kill-switch apply failed: %s", exc)
            return {"enabled": True, "blocked": list(desired_tuple), "error": str(exc)}

        self._store.set_setting(ASUS_KEYS["managed_kill_macs"], json.dumps(desired_sorted))
        self._last_kill_push = desired_tuple
        log.info(
            "ASUS kill-switch: pushed block list (ours=%d, preserved-user=%d)",
            len(desired_sorted),
            len(report.get("preserved_user_rules") or []),
        )
        return {
            "enabled": True,
            "blocked": list(desired_tuple),
            "changed": True,
            "report": report,
            "preservedUserRules": report.get("preserved_user_rules") or [],
        }

    # ---- Stage 2: DNS Director -----------------------------------------

    async def apply_dns_director(
        self,
        desired_macs: list[str],
        *,
        names: Mapping[str, str],
    ) -> dict[str, Any]:
        enabled = self._store.get_setting(ASUS_KEYS["dns_director_enabled"]) == "1"
        prev_dnsd = _load_managed(self._store, ASUS_KEYS["managed_dns_macs"])
        custom_dns_ip = self._store.get_setting(ASUS_KEYS["dns_director_ip"]) or ""

        if not enabled:
            # Feature off: if we'd previously pushed rules, do a single
            # tear-down so the router doesn't keep redirecting devices'
            # DNS to a server the user has now opted out of.
            if not prev_dnsd:
                return {"enabled": False}
            try:
                report = await self._http.apply_managed_dns_director(
                    [],
                    custom_dns_ip=custom_dns_ip or "0.0.0.0",
                    previously_managed=prev_dnsd,
                )
            except AsusRouterError as exc:
                log.warning("ASUS DNS Director tear-down failed: %s", exc)
                return {"enabled": False, "error": str(exc)}
            self._store.set_setting(ASUS_KEYS["managed_dns_macs"], "[]")
            log.info("ASUS DNS Director disabled: cleared %d rule(s)", len(prev_dnsd))
            return {"enabled": False, "torn_down": True, **report}

        if not custom_dns_ip:
            return {"enabled": True, "error": "dns_director_ip not configured"}

        # Build (display-name, mac) pairs in the shape the underlying
        # client wants. Order MUST match the reconciler's desired_macs
        # so labels line up.
        desired_pairs: list[tuple[str, str]] = []
        seen: set[str] = set()
        for mac in desired_macs:
            m = mac.lower() if mac else ""
            if not m or m in seen:
                continue
            seen.add(m)
            label = names.get(mac) or names.get(m) or m.upper()
            label = label.replace("<", "").replace(">", "")[:32] or m.upper()
            desired_pairs.append((label, m))

        try:
            report = await self._http.apply_managed_dns_director(
                desired_pairs,
                custom_dns_ip=custom_dns_ip,
                previously_managed=prev_dnsd,
            )
        except AsusRouterError as exc:
            log.warning("ASUS DNS Director apply failed: %s", exc)
            return {"enabled": True, "error": str(exc)}

        managed_macs = [m for _, m in desired_pairs]
        self._store.set_setting(ASUS_KEYS["managed_dns_macs"], json.dumps(managed_macs))
        log.info(
            "ASUS DNS Director: pushed %d rule(s), preserved %d user rule(s)",
            len(desired_pairs),
            len(report.get("preserved_user_rules") or []),
        )
        return {
            "enabled": True,
            "customIp": custom_dns_ip,
            "redirected": managed_macs,
            "preservedUserRules": report.get("preserved_user_rules") or [],
        }

    # ---- Stage 3: DoH IP blocklist via SSH -----------------------------

    async def apply_doh_block(
        self,
        desired_macs: list[str],
        *,
        names: Mapping[str, str],
    ) -> dict[str, Any]:
        ssh_enabled = self._store.get_setting(ASUS_KEYS["ssh_enabled"]) == "1"
        doh_enabled = self._store.get_setting(ASUS_KEYS["doh_block_enabled"]) == "1"
        prev_doh = _load_managed(self._store, ASUS_KEYS["managed_doh_macs"])

        # Tear-down path: feature off but state left behind.
        if not (ssh_enabled and doh_enabled):
            if not prev_doh:
                return {"enabled": False}
            cfg = self._build_ssh_config(ignore_enabled=True)
            if cfg is None:
                self._store.set_setting(ASUS_KEYS["managed_doh_macs"], "[]")
                self._last_doh_push = ()
                return {
                    "enabled": False,
                    "torn_down": False,
                    "error": "ssh credentials not set; tear-down skipped",
                }
            try:
                async with AsusSshClient(cfg) as ssh:
                    report = await ssh.apply_doh_blocklist([])
            except AsusSshError as exc:
                log.warning("ASUS DoH blocklist tear-down failed: %s", exc)
                return {"enabled": False, "error": str(exc)}
            self._store.set_setting(ASUS_KEYS["managed_doh_macs"], "[]")
            self._last_doh_push = ()
            log.info(
                "ASUS DoH blocklist disabled: torn down %d rule(s)",
                report.get("removed", 0),
            )
            return {"enabled": False, "torn_down": True, **report}

        # Push path.
        cfg = self._build_ssh_config()
        if cfg is None:
            return {"enabled": True, "error": "ssh credentials not set"}

        desired_lower = sorted({m.lower() for m in desired_macs if m and ":" in m})
        desired_tuple = tuple(desired_lower)
        # Skip-if-same: both the in-memory cache *and* persisted state
        # must agree before we skip, mirroring the pre-refactor reconciler.
        same = (
            desired_tuple == self._last_doh_push
            and set(prev_doh) == set(desired_lower)
        )
        if same and self._last_doh_push is not None:
            return {
                "enabled": True,
                "macs": list(desired_tuple),
                "skipped": "no-change",
            }

        try:
            async with AsusSshClient(cfg) as ssh:
                report = await ssh.apply_doh_blocklist(desired_lower)
        except AsusSshError as exc:
            log.warning("ASUS DoH blocklist apply failed: %s", exc)
            return {"enabled": True, "error": str(exc)}

        self._store.set_setting(ASUS_KEYS["managed_doh_macs"], json.dumps(desired_lower))
        self._last_doh_push = desired_tuple
        log.info(
            "ASUS DoH blocklist: %d MACs, +%d/-%d rules",
            len(desired_lower),
            report.get("added", 0),
            report.get("removed", 0),
        )
        return {"enabled": True, **report}

    # ---- helpers -------------------------------------------------------

    def _build_ssh_config(self, *, ignore_enabled: bool = False) -> SshConfig | None:
        if not self._ssh_password:
            return None
        if not (self._ssh_host and self._ssh_username):
            return None
        if not ignore_enabled:
            if self._store.get_setting(ASUS_KEYS["ssh_enabled"]) != "1":
                return None
        return SshConfig(
            host=self._ssh_host,
            port=self._ssh_port,
            username=self._ssh_username,
            password=self._ssh_password,
        )


__all__ = [
    "ASUS_KEYS",
    "ASUS_CAPABILITIES",
    "AsusAdapter",
    "AsusRouterClient",
    "AsusRouterError",
    "AsusSshClient",
    "AsusSshError",
    "SshConfig",
    "detect_router_endpoint",
]
