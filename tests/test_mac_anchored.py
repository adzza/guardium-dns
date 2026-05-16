"""Unit tests for MAC-anchored device-row migration.

Covers ``Store.follow_device_to_new_ip`` and the reconciler's
``_reconcile_device_macs`` helper, which together make profile
assignments follow a device when its DHCP lease changes IP.

Run directly:
    .venv/bin/python tests/test_mac_anchored.py
"""
from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path

# Make `server.*` importable without packaging the project.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server.store import Store  # noqa: E402


class FollowDeviceToNewIpTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self._tmp.close()
        self.store = Store(self._tmp.name)

    def tearDown(self) -> None:
        Path(self._tmp.name).unlink(missing_ok=True)

    # -------------------------------------------------- helpers
    def _seed_device_with_state(
        self,
        ip: str,
        mac: str,
        *,
        label: str = "Hudson Laptop",
        profile: str = "kids",
        usage_minutes: int = 30,
    ) -> None:
        now = int(time.time())
        self.store.upsert_device(ip, label=label)
        self.store.set_device_mac(ip, mac)
        self.store.set_device_base_profile(ip, profile)
        self.store.add_override(
            target_kind="device", target_id=ip, profile_id=None,
            source="manual", starts_at=now, expires_at=now + 3600,
            created_by="tester", note="bedtime test",
        )
        self.store.create_schedule(
            target_kind="device", target_id=ip, name="Bedtime",
            weekday_mask=0b1111111, start_min=21 * 60, end_min=6 * 60,
            profile_id=None, enabled=True,
        )
        self.store.create_quota(
            target_kind="device", target_id=ip, name="Daily",
            weekday_mask=0b1111111, minutes_max=120,
            profile_when_exceeded=None, enabled=True,
        )
        # Daily usage on two distinct dates so we exercise per-date merge.
        self.store.add_active_minutes("device", ip, "2026-05-08", usage_minutes)
        self.store.add_active_minutes("device", ip, "2026-05-07", 90)
        self.store.add_app_active_minutes(
            "device", ip, "2026-05-08", "youtube", 25,
        )

    # -------------------------------------------------- happy path
    def test_migrate_to_fresh_ip(self) -> None:
        self._seed_device_with_state("192.168.4.31", "aa:bb:cc:dd:ee:01")
        report = self.store.follow_device_to_new_ip(
            "AA:BB:CC:DD:EE:01", "192.168.4.83",
        )
        self.assertTrue(report["migrated"])
        self.assertEqual(report["old_ip"], "192.168.4.31")
        self.assertEqual(report["new_ip"], "192.168.4.83")
        self.assertFalse(report["merged_blank_new"])

        old = self.store.get_device("192.168.4.31")
        self.assertIsNone(old)
        new = self.store.get_device("192.168.4.83")
        self.assertIsNotNone(new)
        self.assertEqual(new["label"], "Hudson Laptop")
        self.assertEqual(new["base_profile_id"], "kids")
        self.assertEqual(new["mac_address"], "aa:bb:cc:dd:ee:01")

        # All keyed records moved.
        self.assertEqual(
            len(self.store.active_overrides(int(time.time()))), 1,
        )
        scheds = [
            s for s in self.store.all_schedules()
            if s["target_kind"] == "device" and s["target_id"] == "192.168.4.83"
        ]
        self.assertEqual(len(scheds), 1)
        quotas = [
            q for q in self.store.all_quotas()
            if q["target_kind"] == "device" and q["target_id"] == "192.168.4.83"
        ]
        self.assertEqual(len(quotas), 1)

        # Daily usage rows still total to 30 + 90 minutes for the device.
        self.assertEqual(
            self.store.get_daily_usage("device", "192.168.4.83", "2026-05-08"),
            30,
        )
        self.assertEqual(
            self.store.get_daily_usage("device", "192.168.4.83", "2026-05-07"),
            90,
        )
        self.assertEqual(
            self.store.get_daily_usage("device", "192.168.4.31", "2026-05-08"),
            0,
        )

        apps = self.store.get_app_usages("device", "192.168.4.83", "2026-05-08")
        self.assertEqual([a["app_id"] for a in apps], ["youtube"])
        self.assertEqual(apps[0]["active_minutes"], 25)

    # -------------------------------------------------- merge with blank row
    def test_merge_into_existing_blank_row(self) -> None:
        self._seed_device_with_state("192.168.4.31", "aa:bb:cc:dd:ee:02")
        # Sampler-style blank row at the new IP: nothing but ip/last_seen.
        self.store.touch_device("192.168.4.99")

        report = self.store.follow_device_to_new_ip(
            "aa:bb:cc:dd:ee:02", "192.168.4.99",
        )
        self.assertTrue(report["migrated"])
        self.assertTrue(report["merged_blank_new"])

        new = self.store.get_device("192.168.4.99")
        self.assertEqual(new["label"], "Hudson Laptop")
        self.assertEqual(new["base_profile_id"], "kids")
        self.assertEqual(new["mac_address"], "aa:bb:cc:dd:ee:02")
        # Should not have created any duplicate row.
        all_devs = self.store.all_devices()
        self.assertEqual([d["ip"] for d in all_devs], ["192.168.4.99"])

    # -------------------------------------------------- daily usage merge
    def test_daily_usage_sums_when_both_have_entries(self) -> None:
        self._seed_device_with_state("192.168.4.31", "aa:bb:cc:dd:ee:03")
        # Pre-existing usage at the new IP for the same day -- this can
        # happen when the sampler counted activity at the new lease
        # before we noticed the IP change.
        self.store.touch_device("192.168.4.55")
        self.store.add_active_minutes("device", "192.168.4.55", "2026-05-08", 12)

        self.store.follow_device_to_new_ip("aa:bb:cc:dd:ee:03", "192.168.4.55")

        # 30 (old) + 12 (new) on 2026-05-08, 90 on 2026-05-07.
        self.assertEqual(
            self.store.get_daily_usage("device", "192.168.4.55", "2026-05-08"),
            42,
        )
        self.assertEqual(
            self.store.get_daily_usage("device", "192.168.4.55", "2026-05-07"),
            90,
        )

    # -------------------------------------------------- noop cases
    def test_noop_when_mac_is_unknown(self) -> None:
        self.store.touch_device("192.168.4.31")
        report = self.store.follow_device_to_new_ip(
            "ff:ff:ff:ff:ff:ff", "192.168.4.83",
        )
        self.assertFalse(report["migrated"])
        self.assertIsNone(self.store.get_device("192.168.4.83"))
        self.assertIsNotNone(self.store.get_device("192.168.4.31"))

    def test_noop_when_already_at_new_ip(self) -> None:
        self.store.upsert_device("192.168.4.31", label="Some Device")
        self.store.set_device_mac("192.168.4.31", "aa:bb:cc:dd:ee:04")
        report = self.store.follow_device_to_new_ip(
            "aa:bb:cc:dd:ee:04", "192.168.4.31",
        )
        self.assertFalse(report["migrated"])
        # Original row untouched.
        d = self.store.get_device("192.168.4.31")
        self.assertEqual(d["label"], "Some Device")

    # -------------------------------------------------- mac normalisation
    def test_mac_match_is_case_insensitive_and_dash_tolerant(self) -> None:
        self._seed_device_with_state("192.168.4.31", "AA-BB-CC-DD-EE-05")

        # Both a different case AND different separators must still match.
        report = self.store.follow_device_to_new_ip(
            "aa:bb:cc:dd:ee:05", "192.168.4.83",
        )
        self.assertTrue(report["migrated"])

    # -------------------------------------------------- existing config wins when phantom is blank
    def test_blank_old_does_not_clobber_existing_new_config(self) -> None:
        """Real-world scenario: an old phantom/sampler row with the same
        MAC as a fully-configured live row. The migration must NOT wipe
        the live row's profile/label.
        """
        # NEW row (live) -- the one the user has actually configured.
        self.store.upsert_device("192.168.4.31", label="LAPTOP-PCQPQ6C5")
        self.store.set_device_mac("192.168.4.31", "70:9c:d1:f6:9d:43")
        self.store.set_device_base_profile("192.168.4.31", "internet-off")

        # OLD row (phantom) -- nothing but the MAC. Could be a stale
        # sampler row from before this device was renumbered.
        self.store.upsert_device("192.168.4.249", label=None)
        self.store.set_device_mac("192.168.4.249", "70:9c:d1:f6:9d:43")

        report = self.store.follow_device_to_new_ip(
            "70:9c:d1:f6:9d:43", "192.168.4.31",
        )
        self.assertTrue(report["migrated"])
        self.assertEqual(report["old_ip"], "192.168.4.249")
        self.assertEqual(report["new_ip"], "192.168.4.31")

        kept = self.store.get_device("192.168.4.31")
        self.assertEqual(kept["base_profile_id"], "internet-off")
        self.assertEqual(kept["label"], "LAPTOP-PCQPQ6C5")
        self.assertEqual(kept["mac_address"], "70:9c:d1:f6:9d:43")
        self.assertIsNone(self.store.get_device("192.168.4.249"))

    # -------------------------------------------------- person/favourite carry
    def test_person_and_favourite_are_carried(self) -> None:
        person = self.store.create_person(
            name="Hudson", avatar=None, color="#a78bfa",
            base_profile_id="kids",
        )
        self.store.upsert_device("192.168.4.31", label="Hudson Laptop")
        self.store.set_device_mac("192.168.4.31", "aa:bb:cc:dd:ee:06")
        self.store.set_device_base_profile("192.168.4.31", "kids")
        self.store.attach_device_to_person("192.168.4.31", person["id"])
        self.store.set_favourite("192.168.4.31", True)

        self.store.follow_device_to_new_ip("aa:bb:cc:dd:ee:06", "192.168.4.83")
        new = self.store.get_device("192.168.4.83")
        self.assertEqual(new["person_id"], person["id"])
        self.assertEqual(new["favourite"], 1)


class ReconcilerMacReconciliationTests(unittest.TestCase):
    """Drive the reconciler helper directly without spinning up the
    background task or talking to a real router/Technitium.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self._tmp.close()
        self.store = Store(self._tmp.name)

    def tearDown(self) -> None:
        Path(self._tmp.name).unlink(missing_ok=True)

    def _make_reconciler(self):
        # Avoid importing FastAPI / Technitium client by stubbing.
        from server.reconciler import Reconciler

        class _StubClient:
            pass

        return Reconciler(self.store, _StubClient())  # type: ignore[arg-type]

    def test_reconcile_migrates_known_mac_to_new_ip(self) -> None:
        self.store.upsert_device("192.168.4.31", label="Hudson Laptop")
        self.store.set_device_mac("192.168.4.31", "aa:bb:cc:dd:ee:10")
        self.store.set_device_base_profile("192.168.4.31", "kids")

        rec = self._make_reconciler()
        migrations = rec._reconcile_device_macs({
            "192.168.4.83": "aa:bb:cc:dd:ee:10",
            "192.168.4.140": "aa:bb:cc:dd:ee:99",
        })
        self.assertEqual(len(migrations), 1)
        m = migrations[0]
        self.assertEqual(m["old_ip"], "192.168.4.31")
        self.assertEqual(m["new_ip"], "192.168.4.83")

        # Profile followed.
        new = self.store.get_device("192.168.4.83")
        self.assertEqual(new["base_profile_id"], "kids")
        self.assertEqual(new["mac_address"], "aa:bb:cc:dd:ee:10")
        # Old IP is gone.
        self.assertIsNone(self.store.get_device("192.168.4.31"))

    def test_reconcile_records_mac_for_new_devices_without_migration(self) -> None:
        rec = self._make_reconciler()
        migrations = rec._reconcile_device_macs({
            "192.168.4.83": "aa:bb:cc:dd:ee:11",
        })
        self.assertEqual(migrations, [])
        # Row was created with the MAC stamped on it.
        d = self.store.get_device("192.168.4.83")
        self.assertEqual(d["mac_address"], "aa:bb:cc:dd:ee:11")


def main() -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite([
        loader.loadTestsFromTestCase(FollowDeviceToNewIpTests),
        loader.loadTestsFromTestCase(ReconcilerMacReconciliationTests),
    ])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
