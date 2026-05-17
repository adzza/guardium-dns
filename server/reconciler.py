"""Background reconciler.

Once a minute, computes each device's effective profile (using the override
engine) and reconciles Technitium's networkGroupMap to match. Single-writer:
the reconciler is the *only* code path that calls ``setNetworkGroupMap``
during normal operation. All other modules (HTTP handlers, sampler) update
the local SQLite state and let the reconciler push the delta.

The reconciler also:
- Records *new* schedule and quota overrides into ``device_overrides`` when
  they fire, so the UI can show "internet-off until 06:00" without recomputing.
- Garbage-collects expired overrides.
- Mirrors Stage 1 / Stage 2 / Stage 3 state into whichever router the user
  has configured, via the vendor-agnostic :mod:`server.routers` adapter.

Service token requirement: the reconciler talks to Technitium with a
"service" token (configured via ``TECHNITIUM_SERVICE_TOKEN`` in the env
file). If no service token is configured, the reconciler logs a warning
once and shuts down -- in that mode the dashboard falls back to direct
``setNetworkGroupMap`` calls from request handlers (legacy behaviour).
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Callable

from . import fingerprint as fp
from . import oui
from . import overrides as ov
from . import profiles as prof
from .routers.base import RouterAdapter
from .store import Store
from .technitium import TechnitiumClient, TechnitiumError


# Profiles that DON'T need DNS Director or DoH block:
#   - unrestricted: nothing to enforce.
#   - internet-off: the MAC is fully blocked at L2 already.
#   - None / no profile: no override required.
_DNSD_SKIP_PROFILES = {None, "unrestricted", "internet-off"}


log = logging.getLogger("dns-dashboard.reconciler")

RECONCILE_INTERVAL_SECONDS = 60
ADVANCED_BLOCKING_APP = "Advanced Blocking"

# How often each device gets re-fingerprinted (vendor doesn't change,
# but the domain-pattern hint can drift as the device's app mix
# changes). Once per day is plenty.
FINGERPRINT_MAX_AGE_S = 24 * 60 * 60
# Soft cap on identifies per tick so we don't pummel Technitium right
# after a fresh start.
FINGERPRINT_PER_TICK = 5

# Profile ids that are managed -- if a device's effective profile is in this
# set, the reconciler will write the matching group name into the network
# group map. Any group name *not* matching one of these is left alone (a user
# may have hand-added groups via the Technitium console).
_PROFILE_TO_GROUP = {pid: p["group"]["name"] for pid, p in prof.PROFILES.items()}
_GROUP_TO_PROFILE = {v: k for k, v in _PROFILE_TO_GROUP.items()}


class Reconciler:
    def __init__(
        self,
        store: Store,
        client: TechnitiumClient,
        *,
        adapter_factory: Callable[[], RouterAdapter | None] | None = None,
    ) -> None:
        self.store = store
        self.client = client
        self._adapter_factory = adapter_factory
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._last_status: dict[str, Any] = {"runs": 0}

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="reconciler")
        log.info("Reconciler started (interval=%ds)", RECONCILE_INTERVAL_SECONDS)

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._task, timeout=5)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            self._task.cancel()
        self._task = None

    @property
    def status(self) -> dict[str, Any]:
        return dict(self._last_status)

    async def _run(self) -> None:
        # First tick happens immediately so a fresh service starts coherent.
        try:
            await self.tick()
        except Exception:  # noqa: BLE001
            log.exception("reconciler initial tick failed")
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=RECONCILE_INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                pass
            if self._stop.is_set():
                break
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("reconciler tick failed")

    async def tick(self) -> dict[str, Any]:
        """One reconciliation pass. Returns a status dict for diagnostics."""
        import time as _time
        from contextlib import AsyncExitStack

        now_local = datetime.now()
        now_utc = int(_time.time())

        # 1. Garbage-collect expired overrides.
        self.store.purge_expired_overrides(now_utc)

        # 2. Open a router session ONCE per tick (if configured) so we can
        #    fetch the live MAC<->IP map BEFORE the override engine runs.
        #    The same session is reused by all router stages later in the
        #    tick, so we make exactly one login round-trip per minute.
        adapter: RouterAdapter | None = (
            self._adapter_factory() if self._adapter_factory is not None else None
        )
        ip_to_mac: dict[str, str] = {}
        mac_to_name: dict[str, str] = {}
        migrations: list[dict[str, Any]] = []
        router_open_error: str | None = None

        async with AsyncExitStack() as stack:
            if adapter is not None:
                try:
                    await stack.enter_async_context(adapter)
                except Exception as exc:  # noqa: BLE001
                    log.warning("reconciler: cannot open router session: %s", exc)
                    router_open_error = str(exc)
                    adapter = None

            if adapter is not None:
                try:
                    clients = await adapter.list_clients()
                    for c in clients:
                        if c.ip:
                            ip_to_mac[c.ip] = c.mac
                        if c.name:
                            mac_to_name[c.mac] = c.name
                except Exception as exc:  # noqa: BLE001
                    log.warning("reconciler: list_clients failed: %s", exc)

            # 3. Follow MAC across DHCP changes. This rewrites device-row
            #    IPs (and migrates all per-device overrides/schedules/
            #    quotas/usage) so the rest of the pipeline sees the live
            #    IP for every known MAC.
            if ip_to_mac:
                migrations = self._reconcile_device_macs(ip_to_mac)

            return await self._tick_inner(
                now_local=now_local,
                now_utc=now_utc,
                adapter=adapter,
                ip_to_mac=ip_to_mac,
                mac_to_name=mac_to_name,
                migrations=migrations,
                router_open_error=router_open_error,
            )

    async def _tick_inner(
        self,
        *,
        now_local: datetime,
        now_utc: int,
        adapter: RouterAdapter | None,
        ip_to_mac: dict[str, str],
        mac_to_name: dict[str, str],
        migrations: list[dict[str, Any]],
        router_open_error: str | None,
    ) -> dict[str, Any]:
        # Snapshot inputs (post-migration).
        people = self.store.all_people()
        people_by_id = {p["id"]: p for p in people}
        schedules = self.store.all_schedules()
        quotas = self.store.all_quotas()
        actives = self.store.active_overrides(now_utc)
        usage = self.store.get_daily_usages(ov.local_today(now_local))
        devices = self.store.all_devices()

        # Group inputs by target.
        scheds_by_target: dict[tuple[str, str], list[dict]] = {}
        for s in schedules:
            key = (s["target_kind"], s["target_id"] or "*")
            scheds_by_target.setdefault(key, []).append(s)

        quotas_by_target: dict[tuple[str, str], list[dict]] = {}
        for q in quotas:
            quotas_by_target.setdefault((q["target_kind"], q["target_id"]), []).append(q)

        ovs_by_target: dict[tuple[str, str], list[dict]] = {}
        for o in actives:
            ovs_by_target.setdefault((o["target_kind"], o["target_id"]), []).append(o)

        # 3. Resolve each person.
        person_traces: dict[int, ov.OverrideTrace] = {}
        for person in people:
            pid = person["id"]
            state = ov.TargetState(
                base_profile_id=person["base_profile_id"],
                schedules=scheds_by_target.get(("person", str(pid)), [])
                          + scheds_by_target.get(("all", "*"), []),
                quotas=quotas_by_target.get(("person", str(pid)), []),
                overrides=ovs_by_target.get(("person", str(pid)), []),
                daily_usage_minutes=usage.get(("person", str(pid)), 0),
            )
            person_traces[pid] = ov.resolve_target(
                state, now_local=now_local, now_utc=now_utc, person_id=pid,
            )

        # 4. Resolve each device, then merge with person.
        effective: dict[str, ov.OverrideTrace] = {}
        for d in devices:
            ip = d["ip"]
            state = ov.TargetState(
                base_profile_id=d.get("base_profile_id"),
                schedules=scheds_by_target.get(("device", ip), [])
                          + scheds_by_target.get(("all", "*"), []),
                quotas=quotas_by_target.get(("device", ip), []),
                overrides=ovs_by_target.get(("device", ip), []),
                daily_usage_minutes=usage.get(("device", ip), 0),
            )
            dev_trace = ov.resolve_target(state, now_local=now_local, now_utc=now_utc)
            person_id = d.get("person_id")
            if person_id and person_id in person_traces:
                dev_trace = ov.merge_person_into_device(dev_trace, person_traces[person_id])
            effective[ip] = dev_trace

        # 5. Diff against Technitium and push (with stale-IP cleanup).
        try:
            applied = await self._apply(effective)
        except Exception:  # noqa: BLE001
            log.exception("apply step failed")
            applied = {"changed": 0, "error": True}

        # 6. Mirror state into the router (if configured). Failures are
        #    non-fatal -- DNS-level enforcement already ran above.
        try:
            router_status = await self._apply_router(
                effective, devices, adapter=adapter,
                ip_to_mac=ip_to_mac, mac_to_name=mac_to_name,
            )
        except Exception:  # noqa: BLE001
            log.exception("router apply step failed")
            router_status = {"enabled": True, "error": True}

        if router_open_error and isinstance(router_status, dict):
            router_status.setdefault("openError", router_open_error)
        if migrations and isinstance(router_status, dict):
            router_status["migrations"] = migrations

        # 7. Identify devices we haven't fingerprinted recently. Cheap
        # OUI lookups happen during MAC reconciliation above; this step
        # is the slower domain-pattern pass which queries Technitium
        # logs once per device.
        try:
            fingerprinted = await self._refresh_fingerprints(devices)
        except Exception:  # noqa: BLE001
            log.exception("fingerprint step failed")
            fingerprinted = 0

        self._last_status = {
            "runs": self._last_status.get("runs", 0) + 1,
            "ts": now_utc,
            "devices": len(devices),
            "people": len(people),
            "active_overrides": len(actives),
            "applied": applied,
            "router": router_status,
            "migrations": migrations,
            "fingerprinted": fingerprinted,
        }
        return self._last_status

    def _reconcile_device_macs(self, ip_to_mac: dict[str, str]) -> list[dict[str, Any]]:
        """For each ``(ip, mac)`` the router currently knows about:

        - If we have a device row anchored to this MAC at a *different*
          IP, migrate the row (and all its overrides/schedules/quotas/
          usage) to ``ip``. This is what makes profile assignments
          follow a device across DHCP-lease changes.
        - Otherwise, just (re)record the MAC against the row at ``ip``
          so a future tick can recognise it.

        Pure book-keeping: no router or Technitium calls happen here.
        """
        migrations: list[dict[str, Any]] = []
        for ip, mac in ip_to_mac.items():
            if not mac or "/" in ip:
                continue
            try:
                report = self.store.follow_device_to_new_ip(mac, ip)
            except Exception:  # noqa: BLE001
                log.exception("follow_device_to_new_ip failed for %s -> %s", mac, ip)
                continue
            if report.get("migrated"):
                log.info(
                    "device followed: mac=%s %s -> %s%s",
                    mac, report["old_ip"], ip,
                    " (merged blank sampler row)" if report.get("merged_blank_new") else "",
                )
                migrations.append(report)
            else:
                # MAC unknown to the dashboard, or already living at ``ip``.
                # Make sure the row at ``ip`` carries the MAC.
                self.store.set_device_mac(ip, mac)
            # Refresh the cheap OUI vendor lookup whenever we touch a
            # MAC. The full fingerprint refresh (which costs a query
            # to Technitium) is on a slower cadence -- see
            # _refresh_fingerprints.
            vendor = oui.vendor_for(mac)
            if vendor:
                row = self.store.get_device(ip)
                if row and row.get("vendor") != vendor:
                    self.store.set_device_fingerprint(ip, vendor=vendor,
                                                      hint=row.get("fingerprint_hint"))
        return migrations

    async def _refresh_fingerprints(self, devices: list[dict]) -> int:
        """Re-fingerprint at most ``FINGERPRINT_PER_TICK`` devices per
        tick. Skips anything refreshed in the last
        ``FINGERPRINT_MAX_AGE_S`` seconds.

        Skips loopback and the router's own gateway IP -- the gateway
        sees DNS queries forwarded from many different real devices,
        so a single inferred "device type" would be misleading.
        """
        now = int(__import__("time").time())
        cutoff = now - FINGERPRINT_MAX_AGE_S
        gateway_ip = self.store.get_setting("router.asus.host") or ""
        skip_ips = {"127.0.0.1", "::1", gateway_ip}
        # Pick the oldest-fingerprinted devices first.
        candidates: list[dict] = []
        for d in devices:
            ts = d.get("fingerprint_inferred_at") or 0
            if ts >= cutoff:
                continue
            if "/" in d["ip"]:                # CIDR aggregates: nothing to identify.
                continue
            if d["ip"] in skip_ips:
                continue
            candidates.append(d)
        if not candidates:
            return 0
        candidates.sort(key=lambda d: d.get("fingerprint_inferred_at") or 0)
        refreshed = 0
        for d in candidates[:FINGERPRINT_PER_TICK]:
            try:
                result = await fp.identify_device(
                    d["ip"], mac=d.get("mac_address"),
                    technitium=self.client,
                )
            except Exception:  # noqa: BLE001
                log.exception("fingerprint refresh failed for %s", d["ip"])
                continue
            self.store.set_device_fingerprint(
                d["ip"],
                vendor=result.get("vendor"),
                hint=result.get("hint"),
            )
            refreshed += 1
        if refreshed:
            log.info("fingerprint refresh: %d device(s) updated", refreshed)
        return refreshed

    async def _apply(self, effective: dict[str, ov.OverrideTrace]) -> dict[str, Any]:
        """Push a minimal diff into Technitium's networkGroupMap."""
        # Try to fetch current config; if Technitium is unreachable just skip.
        try:
            config = await self.client.get_app_config(ADVANCED_BLOCKING_APP)
        except TechnitiumError as exc:
            log.warning("reconciler: cannot read AB config: %s", exc)
            return {"changed": 0, "error": True}

        network_map: dict[str, str] = dict(config.get("networkGroupMap") or {})
        original = dict(network_map)
        changed = 0
        for ip, trace in effective.items():
            desired_group = self._desired_group_for(trace)
            current = network_map.get(ip)
            if desired_group is None:
                if current is not None and current in _GROUP_TO_PROFILE:
                    # Only delete entries we manage; leave hand-curated mappings alone.
                    network_map.pop(ip, None)
                    changed += 1
                continue
            if current != desired_group:
                network_map[ip] = desired_group
                changed += 1

        # Orphan-cleanup pass: drop any *managed-group* entries that
        # point at IPs we no longer know about. This is what keeps the
        # map consistent after a device follows its MAC to a new lease
        # (the old IP is now stale) or after a device row is deleted.
        effective_keys = set(effective.keys())
        for stale_ip in list(network_map.keys()):
            grp = network_map.get(stale_ip)
            if grp in _GROUP_TO_PROFILE and stale_ip not in effective_keys:
                network_map.pop(stale_ip, None)
                changed += 1

        # Don't write back if nothing changed.
        if network_map == original:
            return {"changed": 0}
        config["networkGroupMap"] = network_map
        try:
            await self.client.set_app_config(ADVANCED_BLOCKING_APP, config)
        except TechnitiumError as exc:
            log.warning("reconciler: failed to write AB config: %s", exc)
            return {"changed": 0, "error": True}
        log.info("reconciler: pushed %d networkGroupMap deltas", changed)
        return {"changed": changed}

    async def _apply_router(
        self,
        effective: dict[str, ov.OverrideTrace],
        devices: list[dict],
        *,
        adapter: RouterAdapter | None = None,
        ip_to_mac: dict[str, str] | None = None,
        mac_to_name: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Mirror dashboard state into the router (Stages 1/2/3).

        The adapter session and the live MAC<->IP snapshot are taken
        once per tick by :meth:`tick` and threaded through here. The
        adapter owns vendor-specific mechanics (which NVRAM variables
        to twiddle, which controller API to call, etc.); the reconciler
        only computes *desired* state per stage.
        """
        if adapter is None:
            return {"enabled": False}

        ip_to_mac = ip_to_mac or {}
        mac_to_name = mac_to_name or {}

        # Pre-compute helper structures we use across stages.
        ip_by_mac = {v: k for k, v in ip_to_mac.items()}
        dev_by_ip = {d["ip"]: d for d in devices}
        dev_mac_by_ip = {d["ip"]: d.get("mac_address") for d in devices}

        def _resolve_mac(ip: str) -> str | None:
            mac = ip_to_mac.get(ip)
            if mac:
                return mac
            return dev_mac_by_ip.get(ip)

        def _label_for(mac: str, ip_hint: str | None = None) -> str:
            """Best-available friendly name for ``mac``.

            Preference order: router-reported hostname > device-row
            label at the live IP > device-row label at ``ip_hint``
            (the IP we resolved the MAC from, which matters when the
            router isn't currently surfacing the device) > MAC string.
            """
            label = mac_to_name.get(mac)
            if label:
                return label
            ip = ip_by_mac.get(mac) or ip_hint
            if ip:
                d = dev_by_ip.get(ip)
                if d and d.get("label"):
                    return d["label"]
            return mac

        # ---- Stage 1: kill-switch (internet-off) -----------------------
        kill_pairs: list[tuple[str, str]] = []  # (mac, ip_hint)
        kill_seen: set[str] = set()
        missing_internet_off: list[str] = []
        for ip, trace in effective.items():
            if trace.profile_id != "internet-off" or "/" in ip:
                continue
            mac = _resolve_mac(ip)
            if not mac:
                missing_internet_off.append(ip)
                continue
            if mac in kill_seen:
                continue
            kill_seen.add(mac)
            kill_pairs.append((mac, ip))

        kill_macs = [m for m, _ in kill_pairs]
        names_kill = {m: _label_for(m, ip_hint=ip) for m, ip in kill_pairs}

        # ---- Stage 2 / Stage 3 desired sets ----------------------------
        # Every device on a managed profile (other than internet-off /
        # unrestricted) needs DNS Director + DoH block enforcement.
        protect_pairs: list[tuple[str, str]] = []  # (mac, ip_hint)
        protect_seen: set[str] = set()
        for ip, trace in effective.items():
            if trace.profile_id in _DNSD_SKIP_PROFILES or "/" in ip:
                continue
            mac = _resolve_mac(ip)
            if not mac or mac.lower() in protect_seen:
                continue
            protect_seen.add(mac.lower())
            protect_pairs.append((mac, ip))

        protect_macs = [m for m, _ in protect_pairs]
        names_protect = {m: _label_for(m, ip_hint=ip) for m, ip in protect_pairs}

        # ---- Dispatch -------------------------------------------------
        caps = adapter.capabilities
        results: dict[str, Any] = {"enabled": True, "vendor": adapter.vendor}

        if caps.supports_kill_switch:
            try:
                kill_report = await adapter.apply_kill_switch(
                    kill_macs, names=names_kill,
                )
            except Exception as exc:  # noqa: BLE001
                log.exception("kill-switch apply crashed")
                kill_report = {"enabled": True, "error": str(exc)}
            # Hoist the most-asked-about fields onto the top-level dict
            # so the existing UI/API consumers keep working.
            results["blocked"] = kill_report.get("blocked") or []
            results["missing"] = missing_internet_off
            results["changed"] = bool(kill_report.get("changed"))
            results["report"] = kill_report.get("report") or {}
            results["killSwitch"] = kill_report
        else:
            results["killSwitch"] = {"enabled": False, "supported": False}

        if caps.supports_dns_director:
            try:
                dns_report = await adapter.apply_dns_director(
                    protect_macs, names=names_protect,
                )
            except Exception as exc:  # noqa: BLE001
                log.exception("DNS Director apply crashed")
                dns_report = {"enabled": True, "error": str(exc)}
            results["dnsDirector"] = dns_report
        else:
            results["dnsDirector"] = {"enabled": False, "supported": False}

        if caps.supports_doh_blocking:
            try:
                doh_report = await adapter.apply_doh_block(
                    protect_macs, names=names_protect,
                )
            except Exception as exc:  # noqa: BLE001
                log.exception("DoH block apply crashed")
                doh_report = {"enabled": True, "error": str(exc)}
            results["dohBlock"] = doh_report
        else:
            results["dohBlock"] = {"enabled": False, "supported": False}

        return results

    @staticmethod
    def _desired_group_for(trace: ov.OverrideTrace) -> str | None:
        """Map an OverrideTrace to a Technitium group name.

        Returns ``None`` if there should be no explicit mapping (i.e. the device
        falls through to the catch-all)."""
        if trace.profile_id is None:
            return None
        return _PROFILE_TO_GROUP.get(trace.profile_id)


def trace_to_dict(trace: ov.OverrideTrace) -> dict[str, Any]:
    return {
        "profileId": trace.profile_id,
        "source": trace.source,
        "detail": trace.detail,
        "expiresAt": trace.expires_at,
        "personId": trace.person_id,
    }
