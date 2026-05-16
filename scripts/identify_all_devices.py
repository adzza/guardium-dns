"""One-shot: re-identify every device in the dashboard.

Useful right after deploying the fingerprinting feature so the UI is
fully populated without waiting for the daily background pass.
"""
from __future__ import annotations

import asyncio
import os
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, "/opt/dns-dashboard")

from server import fingerprint as fp  # noqa: E402
from server import oui  # noqa: E402
from server.store import Store  # noqa: E402
from server.technitium import TechnitiumClient, TechnitiumConfig  # noqa: E402


DB = Path(os.environ.get("DASHBOARD_DATA_DIR", "/var/lib/dns-dashboard")) / "dashboard.db"


async def main() -> int:
    if not DB.exists():
        print(f"ERROR: {DB} missing", file=sys.stderr)
        return 2

    # Force OUI load up-front so we know vendor lookups work.
    oui._ensure_loaded()  # type: ignore[attr-defined]
    print(f"OUI entries loaded: {len(oui._OUI_MAP or {})}")  # type: ignore[attr-defined]

    cfg = TechnitiumConfig(
        base_url=os.environ.get("TECHNITIUM_URL", "http://127.0.0.1:5380"),
        token=os.environ["TECHNITIUM_SERVICE_TOKEN"],
    )
    store = Store(DB)
    devices = store.all_devices()
    targets = [d for d in devices if "/" not in d["ip"]]
    print(f"Identifying {len(targets)} devices…")

    async with TechnitiumClient(cfg) as client:
        for i, d in enumerate(targets, 1):
            ip = d["ip"]
            mac = d.get("mac_address")
            t0 = time.time()
            try:
                result = await fp.identify_device(ip, mac=mac, technitium=client)
            except Exception as exc:  # noqa: BLE001
                print(f"  [{i:3d}] {ip:18}  ERROR: {exc}")
                continue
            store.set_device_fingerprint(
                ip,
                vendor=result.get("vendor"),
                hint=result.get("hint"),
            )
            elapsed = (time.time() - t0) * 1000
            print(
                f"  [{i:3d}] {ip:18} mac={(mac or '-'):18} "
                f"vendor={(result.get('vendor') or '-'):28} "
                f"hint={(result.get('hint') or '-'):20} ({elapsed:.0f}ms)"
            )
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
