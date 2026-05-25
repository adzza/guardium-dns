"""Unit tests for the vendor-agnostic router-adapter dispatch.

Drives :meth:`server.reconciler.Reconciler._apply_router` directly with
a hand-rolled fake adapter, so we can assert on:

- the exact MAC sets the reconciler computes per stage (kill switch vs
  the shared protect-set for DNS Director + DoH),
- the friendly names it threads through,
- and the shape of the status dict returned to the caller (which the
  UI and Settings page both read).

These tests are how we lock the Phase-1 contract in place before
plugging the UniFi adapter into the same machinery in Phase 2+.
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server.overrides import OverrideTrace  # noqa: E402
from server.routers.base import Capabilities, RouterAdapter, RouterClient  # noqa: E402
from server.store import Store  # noqa: E402


def _trace(profile: str | None) -> OverrideTrace:
    return OverrideTrace(
        profile_id=profile,
        source="base",
        detail=None,
        expires_at=None,
        person_id=None,
    )


class FakeAdapter(RouterAdapter):
    """Records every call so tests can assert on dispatch.

    All three apply methods return the desired set and the names dict
    unchanged so the test can pin them; the reconciler's
    :meth:`_apply_router` glues the result into the status dict.
    """

    vendor = "fake"
    capabilities = Capabilities(
        supports_kill_switch=True,
        supports_dns_director=True,
        supports_doh_blocking=True,
        needs_ssh_for_doh=False,
    )

    def __init__(
        self,
        *,
        clients: list[RouterClient] | None = None,
        supports: Capabilities | None = None,
    ) -> None:
        self.clients = clients or []
        if supports is not None:
            self.capabilities = supports
        self.calls: list[dict] = []
        self.entered = 0
        self.exited = 0

    async def __aenter__(self) -> "FakeAdapter":
        self.entered += 1
        return self

    async def __aexit__(self, *_exc) -> None:
        self.exited += 1

    async def list_clients(self) -> list[RouterClient]:
        return list(self.clients)

    async def apply_kill_switch(self, desired_macs, *, names):
        self.calls.append({"stage": "kill", "macs": list(desired_macs), "names": dict(names)})
        return {
            "enabled": True,
            "blocked": list(desired_macs),
            "changed": True,
            "report": {"applied": len(desired_macs)},
        }

    async def apply_dns_director(self, desired_macs, *, names):
        self.calls.append({"stage": "dns", "macs": list(desired_macs), "names": dict(names)})
        return {
            "enabled": True,
            "customIp": "10.0.0.53",
            "redirected": list(desired_macs),
        }

    async def apply_doh_block(self, desired_macs, *, names):
        self.calls.append({"stage": "doh", "macs": list(desired_macs), "names": dict(names)})
        return {"enabled": True, "macs": list(desired_macs)}


class ApplyRouterDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self._tmp.close()
        self.store = Store(self._tmp.name)

    def tearDown(self) -> None:
        Path(self._tmp.name).unlink(missing_ok=True)

    def _make_reconciler(self):
        from server.reconciler import Reconciler

        class _StubClient:
            pass

        return Reconciler(self.store, _StubClient())  # type: ignore[arg-type]

    def test_kill_switch_only_targets_internet_off_devices(self) -> None:
        rec = self._make_reconciler()
        adapter = FakeAdapter()

        effective = {
            "192.168.1.10": _trace("internet-off"),  # -> kill
            "192.168.1.11": _trace("kids"),           # -> protect (dns+doh)
            "192.168.1.12": _trace("unrestricted"),   # -> nothing
            "192.168.1.13": _trace(None),             # -> nothing
        }
        devices = [
            {"ip": "192.168.1.10", "mac_address": "aa:aa:aa:aa:aa:10", "label": "Bedroom TV"},
            {"ip": "192.168.1.11", "mac_address": "aa:aa:aa:aa:aa:11", "label": "Hudson Laptop"},
            {"ip": "192.168.1.12", "mac_address": "aa:aa:aa:aa:aa:12", "label": "Dad PC"},
            {"ip": "192.168.1.13", "mac_address": "aa:aa:aa:aa:aa:13", "label": "Mystery"},
        ]
        # Empty live ip_to_mac forces the reconciler to fall back on the
        # persisted device.mac_address (exercises the merge logic in
        # _resolve_mac).
        result = asyncio.run(rec._apply_router(
            effective, devices,
            adapter=adapter,
            ip_to_mac={},
            mac_to_name={},
        ))

        self.assertEqual(result["enabled"], True)
        self.assertEqual(result["vendor"], "fake")
        # Kill switch sees only the internet-off MAC.
        kill_call = next(c for c in adapter.calls if c["stage"] == "kill")
        self.assertEqual(kill_call["macs"], ["aa:aa:aa:aa:aa:10"])
        self.assertEqual(kill_call["names"], {"aa:aa:aa:aa:aa:10": "Bedroom TV"})
        # Protect (DNS + DoH) sees only the kids MAC; unrestricted +
        # internet-off + no-profile are all skipped.
        dns_call = next(c for c in adapter.calls if c["stage"] == "dns")
        doh_call = next(c for c in adapter.calls if c["stage"] == "doh")
        self.assertEqual(dns_call["macs"], ["aa:aa:aa:aa:aa:11"])
        self.assertEqual(doh_call["macs"], ["aa:aa:aa:aa:aa:11"])
        self.assertEqual(dns_call["names"]["aa:aa:aa:aa:aa:11"], "Hudson Laptop")

    def test_missing_mac_is_reported_not_pushed(self) -> None:
        rec = self._make_reconciler()
        adapter = FakeAdapter()

        # internet-off device with no MAC known anywhere -> reported as
        # missing, NOT pushed to the adapter.
        effective = {"192.168.1.20": _trace("internet-off")}
        devices = [{"ip": "192.168.1.20", "mac_address": None, "label": None}]

        result = asyncio.run(rec._apply_router(
            effective, devices,
            adapter=adapter,
            ip_to_mac={},
            mac_to_name={},
        ))
        self.assertEqual(result["missing"], ["192.168.1.20"])
        self.assertEqual(result["blocked"], [])
        kill_call = next(c for c in adapter.calls if c["stage"] == "kill")
        self.assertEqual(kill_call["macs"], [])

    def test_live_ip_to_mac_takes_precedence_over_persisted(self) -> None:
        rec = self._make_reconciler()
        adapter = FakeAdapter()

        # device row remembers MAC -02, but the router currently sees
        # -99 at the same IP (e.g. device replaced). The live router
        # MAC must win.
        effective = {"192.168.1.30": _trace("kids")}
        devices = [{"ip": "192.168.1.30", "mac_address": "bb:bb:bb:bb:bb:02", "label": "Old"}]

        asyncio.run(rec._apply_router(
            effective, devices,
            adapter=adapter,
            ip_to_mac={"192.168.1.30": "bb:bb:bb:bb:bb:99"},
            mac_to_name={"bb:bb:bb:bb:bb:99": "New Hostname"},
        ))
        dns_call = next(c for c in adapter.calls if c["stage"] == "dns")
        self.assertEqual(dns_call["macs"], ["bb:bb:bb:bb:bb:99"])
        self.assertEqual(dns_call["names"]["bb:bb:bb:bb:bb:99"], "New Hostname")

    def test_capabilities_gate_dispatch(self) -> None:
        """Adapters that don't support a stage MUST NOT have its apply
        method called -- the reconciler skips them and reports
        ``supported: false`` in the status dict instead.
        """
        rec = self._make_reconciler()
        adapter = FakeAdapter(supports=Capabilities(
            supports_kill_switch=True,
            supports_dns_director=False,   # <- not supported
            supports_doh_blocking=True,
        ))

        effective = {
            "192.168.1.40": _trace("internet-off"),
            "192.168.1.41": _trace("kids"),
        }
        devices = [
            {"ip": "192.168.1.40", "mac_address": "cc:cc:cc:cc:cc:40", "label": "TV"},
            {"ip": "192.168.1.41", "mac_address": "cc:cc:cc:cc:cc:41", "label": "Laptop"},
        ]

        result = asyncio.run(rec._apply_router(
            effective, devices,
            adapter=adapter,
            ip_to_mac={},
            mac_to_name={},
        ))
        stages = {c["stage"] for c in adapter.calls}
        self.assertIn("kill", stages)
        self.assertIn("doh", stages)
        self.assertNotIn("dns", stages)
        self.assertEqual(result["dnsDirector"], {"enabled": False, "supported": False})

    def test_adapter_none_means_router_disabled(self) -> None:
        rec = self._make_reconciler()
        result = asyncio.run(rec._apply_router(
            {"192.168.1.50": _trace("internet-off")},
            [{"ip": "192.168.1.50", "mac_address": "dd:dd:dd:dd:dd:50", "label": "X"}],
            adapter=None,
            ip_to_mac={},
            mac_to_name={},
        ))
        self.assertEqual(result, {"enabled": False})

    def test_apply_exception_is_caught_into_error_dict(self) -> None:
        """A vendor adapter that crashes mid-apply MUST NOT take the
        whole reconciler tick down with it.
        """
        rec = self._make_reconciler()

        class BoomAdapter(FakeAdapter):
            async def apply_dns_director(self, desired_macs, *, names):
                raise RuntimeError("upstream 500")

        adapter = BoomAdapter()
        result = asyncio.run(rec._apply_router(
            {"192.168.1.60": _trace("kids")},
            [{"ip": "192.168.1.60", "mac_address": "ee:ee:ee:ee:ee:60", "label": "L"}],
            adapter=adapter,
            ip_to_mac={},
            mac_to_name={},
        ))
        self.assertEqual(result["dnsDirector"]["error"], "upstream 500")
        # Stage 1 and Stage 3 still ran.
        stages = {c["stage"] for c in adapter.calls}
        self.assertIn("kill", stages)
        self.assertIn("doh", stages)


class RegistryAutoMigrationTests(unittest.TestCase):
    """Verify the registry's legacy-ASUS auto-detect.

    Installed dashboards have ``router.asus.host`` saved but no
    ``router.vendor`` setting yet; first call to ``get_adapter`` must
    treat that as vendor=asus and persist the explicit setting so
    subsequent reads are unambiguous.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self._tmp.close()
        self.store = Store(self._tmp.name)

    def tearDown(self) -> None:
        Path(self._tmp.name).unlink(missing_ok=True)

    def test_no_settings_returns_none(self) -> None:
        from server.routers.registry import get_adapter
        self.assertIsNone(get_adapter(self.store, _FakeSecrets()))

    def test_legacy_asus_install_is_auto_migrated(self) -> None:
        # Legacy state: host is set but vendor isn't.
        self.store.set_setting("router.asus.host", "192.168.1.1")
        self.store.set_setting("router.asus.username", "admin")
        self.store.set_setting("router.asus.enabled", "1")
        # Adapter still returns None because the password isn't in the
        # SecretStore (FakeSecrets returns None), but the side effect
        # of persisting router.vendor=asus must still happen.
        from server.routers.registry import get_adapter
        get_adapter(self.store, _FakeSecrets())
        self.assertEqual(self.store.get_setting("router.vendor"), "asus")

    def test_unifi_blocked_without_alpha_flag(self) -> None:
        self.store.set_setting("router.vendor", "unifi")
        from server.routers.registry import get_adapter
        # Default env -- alpha flag not set -- must refuse.
        self.assertIsNone(get_adapter(self.store, _FakeSecrets()))

    def test_explicit_none_overrides_legacy_auto_detect(self) -> None:
        """User picks 'None' in Settings while ASUS creds are still
        saved (e.g. mid-switch from ASUS to UniFi). The registry must
        honour the explicit opt-out rather than silently re-promoting
        back to ASUS via the legacy auto-detect.
        """
        self.store.set_setting("router.vendor", "none")
        self.store.set_setting("router.asus.host", "192.168.1.1")
        from server.routers.registry import get_adapter
        self.assertIsNone(get_adapter(self.store, _FakeSecrets()))
        # And the setting wasn't clobbered back to 'asus' as a side
        # effect of the read.
        self.assertEqual(self.store.get_setting("router.vendor"), "none")

    def test_unifi_loaded_when_alpha_flag_set(self) -> None:
        """When the alpha flag IS set and UniFi creds are saved, the
        registry must return a real UnifiAdapter instance.
        """
        import os
        os.environ["GUARDIUM_ENABLE_UNIFI_ALPHA"] = "1"
        try:
            self.store.set_setting("router.vendor", "unifi")
            self.store.set_setting("router.unifi.host", "https://unifi.lan")
            self.store.set_setting("router.unifi.username", "guardium")
            secrets = _FakeSecrets(**{"router.unifi.password": "hunter2"})

            from server.routers.registry import get_adapter
            adapter = get_adapter(self.store, secrets)
            self.assertIsNotNone(adapter)
            assert adapter is not None
            self.assertEqual(adapter.vendor, "unifi")
            self.assertFalse(adapter.capabilities.supports_dns_director)
        finally:
            os.environ.pop("GUARDIUM_ENABLE_UNIFI_ALPHA", None)


class _FakeSecrets:
    def __init__(self, **values: str) -> None:
        self._values: dict[str, str] = dict(values)

    def get(self, key: str) -> str | None:
        return self._values.get(key)

    def set(self, key: str, value: str | None) -> None:
        if value is None:
            self._values.pop(key, None)
        else:
            self._values[key] = value


def main() -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite([
        loader.loadTestsFromTestCase(ApplyRouterDispatchTests),
        loader.loadTestsFromTestCase(RegistryAutoMigrationTests),
    ])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
