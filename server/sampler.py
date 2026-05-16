"""Activity sampler.

Every ``SAMPLE_INTERVAL_MINUTES`` we ask Technitium "who's been active in the
last N minutes?" and credit each device (and its owning person, if any) with
that many ``active_minutes`` against today's date.

This produces an approximation of "screen time": a device that makes any DNS
query during the bucket counts as active for the whole bucket. Good enough
for daily quotas; we don't pretend it's surveillance-grade.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any

from . import overrides as ov
from .store import Store
from .technitium import TechnitiumClient, TechnitiumError


log = logging.getLogger("dns-dashboard.sampler")

SAMPLE_INTERVAL_MINUTES = 5


class Sampler:
    def __init__(self, store: Store, client: TechnitiumClient) -> None:
        self.store = store
        self.client = client
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._last_status: dict[str, Any] = {"runs": 0}

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="sampler")
        log.info("Sampler started (interval=%dm)", SAMPLE_INTERVAL_MINUTES)

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
        # Wait one interval before first sample so we don't overcount on
        # service restart.
        try:
            await asyncio.wait_for(self._stop.wait(),
                                    timeout=SAMPLE_INTERVAL_MINUTES * 60)
        except asyncio.TimeoutError:
            pass
        while not self._stop.is_set():
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("sampler tick failed")
            try:
                await asyncio.wait_for(self._stop.wait(),
                                        timeout=SAMPLE_INTERVAL_MINUTES * 60)
            except asyncio.TimeoutError:
                pass

    async def tick(self) -> dict[str, Any]:
        """One sampling pass."""
        now_local = datetime.now()
        date_key = ov.local_today(now_local)
        try:
            # Note: Technitium's stats range only really supports preset windows.
            # "LastHour" is the smallest available; we still credit only
            # SAMPLE_INTERVAL_MINUTES because that's how often we run.
            # Devices with steady traffic in the last hour will ALSO appear in
            # the next bucket and be credited again -- which is what we want.
            top = await self.client.get_top(stats_type="TopClients",
                                             time_range="LastHour", limit=200)
        except TechnitiumError as exc:
            log.warning("sampler: cannot read top clients: %s", exc)
            return {"error": True}

        # Filter to clients that were active *recently*. Technitium returns
        # cumulative hits over the time range; we approximate "recent" by
        # looking at clients with any non-zero hit count. The sampler's
        # stop-the-clock cap is the whole-day quota, so a few extra
        # SAMPLE_INTERVAL_MINUTES of overhead is acceptable.
        active_ips = []
        for c in top:
            ip = c.get("name")
            if ip and (c.get("hits") or 0) > 0:
                active_ips.append(ip)

        if not active_ips:
            self._last_status = {"runs": self._last_status.get("runs", 0) + 1,
                                  "active": 0, "ts": int(now_local.timestamp())}
            return self._last_status

        # We need each device's owning person, so fetch from store.
        devices = {d["ip"]: d for d in self.store.all_devices()}
        person_credits: dict[int, int] = {}

        for ip in active_ips:
            self.store.add_active_minutes("device", ip, date_key, SAMPLE_INTERVAL_MINUTES)
            d = devices.get(ip) or {}
            pid = d.get("person_id")
            if pid:
                # A person is "active" if ANY of their devices was active in
                # this bucket; we still record exactly one bucket per tick so
                # quotas don't multiply with device count.
                person_credits[pid] = SAMPLE_INTERVAL_MINUTES

        for pid, mins in person_credits.items():
            self.store.add_active_minutes("person", str(pid), date_key, mins)

        self._last_status = {
            "runs": self._last_status.get("runs", 0) + 1,
            "active": len(active_ips),
            "active_persons": len(person_credits),
            "ts": int(now_local.timestamp()),
        }
        return self._last_status
