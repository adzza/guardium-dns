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

Service token requirement: the reconciler talks to Technitium with a
"service" token (configured via ``TECHNITIUM_SERVICE_TOKEN`` in the env
file). If no service token is configured, the reconciler logs a warning
once and shuts down -- in that mode the dashboard falls back to direct
``setNetworkGroupMap`` calls from request handlers (legacy behaviour).
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Callable

from . import fingerprint as fp
from . import oui
from . import overrides as ov
from . import profiles as prof
from .router_asus import AsusRouterClient, AsusRouterError
from .router_ssh import AsusSshClient, AsusSshError, SshConfig
from .store import Store
from .technitium import TechnitiumClient, TechnitiumError


# Settings keys where we remember exactly what we last asked the router
# to do, so we can remove just our own entries without touching anything
# the user added by hand in the router web UI.
MANAGED_MACS_KEY = "router.asus.managed_macs"
MANAGED_DNS_KEY  = "router.asus.managed_dns_macs"
MANAGED_DOH_KEY  = "router.asus.managed_doh_macs"

# Profiles that DON'T need DNS Director:
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
        router_factory: Callable[[], AsusRouterClient | None] | None = None,
        ssh_factory: Callable[..., SshConfig | None] | None = None,
    ) -> None:
        self.store = store
        self.client = client
        self._router_factory = router_factory
        self._ssh_factory = ssh_factory
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._last_status: dict[str, Any] = {"runs": 0}
        # Set of MACs we last asked the router to block. Used to skip
        # redundant pushes if nothing changed.
        self._last_router_pushed: tuple[str, ...] | None = None
        self._last_doh_pushed: tuple[str, ...] | None = None

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
        router: AsusRouterClient | None = (
            self._router_factory() if self._router_factory is not None else None
        )
        ip_to_mac: dict[str, str] = {}
        mac_to_name: dict[str, str] = {}
        migrations: list[dict[str, Any]] = []
        router_open_error: str | None = None

        async with AsyncExitStack() as stack:
            if router is not None:
                try:
                    await stack.enter_async_context(router)
                except Exception as exc:  # noqa: BLE001
                    log.warning("reconciler: cannot open router session: %s", exc)
                    router_open_error = str(exc)
                    router = None

            if router is not None:
                try:
                    clients = await router.list_clients()
                    for c in clients:
                        if c.ip:
                            ip_to_mac[c.ip] = c.mac
                        if c.name:
                            mac_to_name[c.mac] = c.name
                except AsusRouterError as exc:
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
                router=router,
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
        router: AsusRouterClient | None,
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

        # 6. Mirror state into the router firewall (if configured).
        # Failures are non-fatal -- DNS-level enforcement already ran above.
        try:
            router_status = await self._apply_router(
                effective, devices, router=router,
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
        router: AsusRouterClient | None = None,
        ip_to_mac: dict[str, str] | None = None,
        mac_to_name: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Mirror dashboard state into the router (Stages 1/2/3).

        The router session and the live MAC<->IP snapshot are taken
        once per tick by :meth:`tick` and threaded through here, so
        every stage sees a consistent view of the network.
        """
        if router is None:
            # Router not configured / not reachable this tick; skip
            # gracefully. (MAC reconciliation also gets skipped, which
            # is fine -- we'll catch up on the next successful tick.)
            return {"enabled": False}

        ip_to_mac = ip_to_mac or {}
        mac_to_name = mac_to_name or {}

        try:
            # Compute desired block set (Stage 1: MAC-based "Internet Off").
            desired_macs: list[str] = []
            seen: set[str] = set()
            missing_internet_off: list[str] = []
            for ip, trace in effective.items():
                if trace.profile_id != "internet-off":
                    continue
                if "/" in ip:
                    continue
                mac = ip_to_mac.get(ip)
                if not mac:
                    # Fall back to whatever we previously persisted on
                    # the device row.
                    for d in devices:
                        if d["ip"] == ip:
                            if d.get("mac_address"):
                                mac = d["mac_address"]
                            break
                if not mac:
                    missing_internet_off.append(ip)
                    continue
                if mac in seen:
                    continue
                seen.add(mac)
                desired_macs.append(mac)

            desired_tuple = tuple(sorted(desired_macs))

            # Friendly names for the router UI.
            names: dict[str, str] = {}
            ip_by_mac = {v: k for k, v in ip_to_mac.items()}
            for mac in desired_macs:
                label = mac_to_name.get(mac)
                if not label:
                    ip = ip_by_mac.get(mac)
                    if ip:
                        for d in devices:
                            if d["ip"] == ip and d.get("label"):
                                label = d["label"]
                                break
                names[mac] = label or mac

            # Load the set of MACs we put in the router LAST tick.
            prev_raw = self.store.get_setting(MANAGED_MACS_KEY) or "[]"
            try:
                previously_managed = list(json.loads(prev_raw))
            except json.JSONDecodeError:
                previously_managed = []

            report: dict[str, Any] = {}
            block_list_changed = desired_tuple != self._last_router_pushed
            if block_list_changed:
                report = await router.apply_managed_blocked_macs(
                    desired_macs,
                    previously_managed=previously_managed,
                    names=names,
                )
                self.store.set_setting(MANAGED_MACS_KEY, json.dumps(desired_macs))
                self._last_router_pushed = desired_tuple
                log.info(
                    "router: pushed block list (ours=%d, preserved-user=%d, missing-mac=%d)",
                    len(desired_macs),
                    len(report.get("preserved_user_rules") or []),
                    len(missing_internet_off),
                )

            # ---- Stage 2: DNS Director (per-MAC DNS redirect) ----
            dns_status = await self._apply_router_dns_director(
                router, effective, devices, ip_to_mac, mac_to_name,
            )

            # ---- Stage 3: DoH IP blocklist via SSH ----
            doh_status = await self._apply_doh_blocklist(
                effective, devices, ip_to_mac,
            )

            return {
                "enabled": True,
                "blocked": list(desired_tuple),
                "missing": missing_internet_off,
                "changed": block_list_changed,
                "report": report,
                "dnsDirector": dns_status,
                "dohBlock": doh_status,
            }
        except AsusRouterError as exc:
            log.warning("router apply failed: %s", exc)
            return {"enabled": True, "error": str(exc)}

    async def _apply_router_dns_director(
        self,
        router: AsusRouterClient,
        effective: dict[str, ov.OverrideTrace],
        devices: list[dict],
        ip_to_mac: dict[str, str],
        mac_to_name: dict[str, str],
    ) -> dict[str, Any]:
        """Push DNS Director rules for every device on a managed profile
        (other than ``internet-off`` -- which is already blocked at L2).

        DNS Director forces those MACs to use the dashboard's DNS server,
        so a user setting their device's DNS to ``8.8.8.8`` doesn't get
        them out of the kids/no-streaming/etc. profile.
        """
        enabled = self.store.get_setting("router.asus.dns_director_enabled") == "1"

        prev_dnsd_raw = self.store.get_setting(MANAGED_DNS_KEY) or "[]"
        try:
            prev_dnsd = list(json.loads(prev_dnsd_raw))
        except json.JSONDecodeError:
            prev_dnsd = []

        if not enabled:
            # Feature off: if we'd previously pushed rules, do a single
            # tear-down so the router doesn't keep redirecting devices'
            # DNS to a server the user has now opted out of.
            if not prev_dnsd:
                return {"enabled": False}
            try:
                report = await router.apply_managed_dns_director(
                    [],
                    custom_dns_ip=self.store.get_setting("router.asus.dns_director_ip") or "0.0.0.0",
                    previously_managed=prev_dnsd,
                )
            except AsusRouterError as exc:
                log.warning("DNS Director tear-down failed: %s", exc)
                return {"enabled": False, "error": str(exc)}
            self.store.set_setting(MANAGED_DNS_KEY, "[]")
            log.info("DNS Director disabled: cleared %d rule(s)", len(prev_dnsd))
            return {"enabled": False, "torn_down": True, **report}

        custom_dns_ip = self.store.get_setting("router.asus.dns_director_ip") or ""
        if not custom_dns_ip:
            return {"enabled": True, "error": "dns_director_ip not configured"}

        # Build (display-name, mac) for everyone whose effective profile is
        # one we want to enforce DNS for.
        desired: list[tuple[str, str]] = []
        seen: set[str] = set()
        ip_by_mac = {v: k for k, v in ip_to_mac.items()}
        dev_label_by_ip = {d["ip"]: d.get("label") for d in devices}
        for ip, trace in effective.items():
            if trace.profile_id in _DNSD_SKIP_PROFILES:
                continue
            if "/" in ip:
                continue
            mac = ip_to_mac.get(ip)
            if not mac:
                # Fallback: look up the persisted MAC for this device.
                for d in devices:
                    if d["ip"] == ip:
                        mac = d.get("mac_address")
                        break
            if not mac or mac in seen:
                continue
            seen.add(mac)
            label = mac_to_name.get(mac) or dev_label_by_ip.get(ip_by_mac.get(mac, "")) or ip
            # Strip characters the firmware tokeniser can't handle.
            label = label.replace("<", "").replace(">", "")[:32] or mac.upper()
            desired.append((label, mac))

        try:
            report = await router.apply_managed_dns_director(
                desired,
                custom_dns_ip=custom_dns_ip,
                previously_managed=prev_dnsd,
            )
        except AsusRouterError as exc:
            log.warning("router DNS Director apply failed: %s", exc)
            return {"enabled": True, "error": str(exc)}

        self.store.set_setting(MANAGED_DNS_KEY, json.dumps([m for _, m in desired]))
        log.info(
            "router DNS Director: pushed %d rule(s), preserved %d user rule(s)",
            len(desired),
            len(report.get("preserved_user_rules") or []),
        )
        return {
            "enabled": True,
            "customIp": custom_dns_ip,
            "redirected": [m for _, m in desired],
            "preservedUserRules": report.get("preserved_user_rules") or [],
        }

    async def _apply_doh_blocklist(
        self,
        effective: dict[str, ov.OverrideTrace],
        devices: list[dict],
        ip_to_mac: dict[str, str],
    ) -> dict[str, Any]:
        """Stage 3: drop all traffic from managed-profile MACs to known
        public DoH/DoT endpoints (via iptables + ipset over SSH).

        Only runs when both ``router.asus.doh_block_enabled`` and
        ``router.asus.ssh_enabled`` are on, and an SSH password is stored.
        Same skip-set as DNS Director (don't bother for ``unrestricted``
        or ``internet-off``).

        When the feature is *disabled* but ``MANAGED_DOH_KEY`` shows we
        had pushed rules previously, run a single tear-down tick so the
        router doesn't stay polluted with our drops.
        """
        ssh_enabled = self.store.get_setting("router.asus.ssh_enabled") == "1"
        doh_enabled = self.store.get_setting("router.asus.doh_block_enabled") == "1"

        # Decide whether we need to do anything at all.
        prev_raw = self.store.get_setting(MANAGED_DOH_KEY) or "[]"
        try:
            previously_managed = list(json.loads(prev_raw))
        except json.JSONDecodeError:
            previously_managed = []

        if not (ssh_enabled and doh_enabled):
            # Feature is off. If we previously pushed rules, tear them
            # down once so the router is left clean.
            if not previously_managed:
                return {"enabled": False}
            if self._ssh_factory is None:
                return {"enabled": False, "torn_down": False}
            # Pass ignore_enabled=True so we can still reach the router
            # to clean up even though the user has just toggled SSH off.
            try:
                cfg = self._ssh_factory(ignore_enabled=True)  # type: ignore[call-arg]
            except TypeError:
                cfg = self._ssh_factory()
            if cfg is None:
                # Credentials gone; we can't reach the router. Forget the
                # marker so we stop trying.
                self.store.set_setting(MANAGED_DOH_KEY, "[]")
                self._last_doh_pushed = ()
                return {"enabled": False, "torn_down": False,
                        "error": "ssh credentials not set; tear-down skipped"}
            try:
                async with AsusSshClient(cfg) as ssh:
                    report = await ssh.apply_doh_blocklist([])
            except AsusSshError as exc:
                log.warning("DoH blocklist tear-down failed: %s", exc)
                return {"enabled": False, "error": str(exc)}
            self.store.set_setting(MANAGED_DOH_KEY, "[]")
            self._last_doh_pushed = ()
            log.info("DoH blocklist disabled: torn down %d rule(s)",
                     report.get("removed", 0))
            return {"enabled": False, "torn_down": True, **report}

        if self._ssh_factory is None:
            return {"enabled": False, "error": "no ssh factory"}

        cfg = self._ssh_factory()
        if cfg is None:
            return {"enabled": True, "error": "ssh credentials not set"}

        # Build the desired MAC set: same logic as DNS Director.
        desired_macs: set[str] = set()
        for ip, trace in effective.items():
            if trace.profile_id in _DNSD_SKIP_PROFILES or "/" in ip:
                continue
            mac = ip_to_mac.get(ip)
            if not mac:
                for d in devices:
                    if d["ip"] == ip:
                        mac = d.get("mac_address")
                        break
            if mac:
                desired_macs.add(mac.lower())

        desired_sorted = sorted(desired_macs)
        # Skip if nothing changed since last push.
        same = (tuple(desired_sorted) == self._last_doh_pushed and
                set(previously_managed) == desired_macs)
        if same and self._last_doh_pushed is not None:
            return {
                "enabled": True,
                "macs": desired_sorted,
                "skipped": "no-change",
            }

        try:
            async with AsusSshClient(cfg) as ssh:
                report = await ssh.apply_doh_blocklist(desired_sorted)
        except AsusSshError as exc:
            log.warning("DoH blocklist apply failed: %s", exc)
            return {"enabled": True, "error": str(exc)}

        self.store.set_setting(MANAGED_DOH_KEY, json.dumps(desired_sorted))
        self._last_doh_pushed = tuple(desired_sorted)
        log.info("DoH blocklist: %d MACs, +%d/-%d rules",
                 len(desired_sorted), report.get("added", 0),
                 report.get("removed", 0))
        return {"enabled": True, **report}

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
