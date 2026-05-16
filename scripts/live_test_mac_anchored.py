"""Live, non-destructive end-to-end test for MAC-anchored migration.

Inserts a phantom duplicate device row at a fake IP that shares a MAC
with a real, configured device. After the next reconcile tick the row
must be gone and the real device's profile must be unchanged.

Run on the server (where /var/lib/dns-dashboard/dashboard.db lives):

    .venv/bin/python scripts/live_test_mac_anchored.py
"""
from __future__ import annotations

import sqlite3
import sys
import time
from pathlib import Path

DB = Path("/var/lib/dns-dashboard/dashboard.db")
PHANTOM_IP = "192.168.4.249"
TARGET_MAC = "70:9c:d1:f6:9d:43"  # LAPTOP-PCQPQ6C5 @ 192.168.4.31


def fetch_row(cx: sqlite3.Connection, ip: str) -> dict | None:
    cx.row_factory = sqlite3.Row
    row = cx.execute("SELECT * FROM devices WHERE ip = ?", (ip,)).fetchone()
    return dict(row) if row else None


def main() -> int:
    if not DB.exists():
        print(f"ERROR: {DB} not found", file=sys.stderr)
        return 2
    cx = sqlite3.connect(str(DB), isolation_level=None)
    cx.row_factory = sqlite3.Row

    real = fetch_row(cx, "192.168.4.31")
    if not real:
        print("ERROR: live row at 192.168.4.31 not found, cannot run test")
        return 2
    print("BEFORE:")
    print(f"  .31  mac={real['mac_address']}  profile={real['base_profile_id']}  label={real['label']}")
    if (real["mac_address"] or "").lower() != TARGET_MAC:
        print(f"ERROR: expected MAC {TARGET_MAC} at .31, got {real['mac_address']}")
        return 2

    # Inject a *blank* phantom row at PHANTOM_IP -- nothing but ip + MAC,
    # exactly like the sampler would create after a DHCP-lease shuffle.
    cx.execute("DELETE FROM devices WHERE ip = ?", (PHANTOM_IP,))
    now = int(time.time())
    cx.execute(
        """INSERT INTO devices(ip, mac_address, first_seen, last_seen)
           VALUES (?, ?, ?, ?)""",
        (PHANTOM_IP, TARGET_MAC, now, now),
    )
    print(f"\nInjected blank phantom row: {PHANTOM_IP} mac={TARGET_MAC}")

    # Wait for the reconciler to run. Default interval is 60s; allow a
    # bit of slack.
    print("Waiting up to 90s for the reconciler to migrate...")
    deadline = time.time() + 90
    migrated = False
    while time.time() < deadline:
        time.sleep(5)
        phantom = fetch_row(cx, PHANTOM_IP)
        live = fetch_row(cx, "192.168.4.31")
        if phantom is None and live is not None:
            migrated = True
            break
        print(
            f"  ... still {'phantom' if phantom else '(no phantom)'} "
            f"/ live={live and live['base_profile_id']}"
        )

    print()
    after = fetch_row(cx, "192.168.4.31")
    phantom = fetch_row(cx, PHANTOM_IP)
    print("AFTER:")
    if after:
        print(
            f"  .31  mac={after['mac_address']}  "
            f"profile={after['base_profile_id']}  label={after['label']}"
        )
    else:
        print("  .31  MISSING (this would be a bug)")
    print(f"  .249 phantom: {'present' if phantom else 'gone'}")

    if not migrated:
        print("\nFAIL: migration did not happen in time", file=sys.stderr)
        # Clean up so we don't leave junk in the DB.
        cx.execute("DELETE FROM devices WHERE ip = ?", (PHANTOM_IP,))
        return 1

    # Verify the live row was preserved.
    if (after is None
        or (after["mac_address"] or "").lower() != TARGET_MAC
        or after["base_profile_id"] != real["base_profile_id"]
        or after["label"] != real["label"]):
        print("\nFAIL: live row was modified by migration", file=sys.stderr)
        return 1

    print("\nPASS: phantom merged, live row preserved.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
