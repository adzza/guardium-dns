"""Unit tests for the Phase-2 UniFi scaffolding.

Read paths + traffic-rule JSON builders + DPI discovery only. The
``apply_kill_switch`` / ``apply_doh_block`` paths land in Phase 3 / 4
and get their own tests there.
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server.routers.base import Capabilities  # noqa: E402
from server.routers.unifi import (  # noqa: E402
    UNIFI_CAPABILITIES,
    UNIFI_KEYS,
    UnifiAdapter,
    _looks_like_gateway,
    _to_router_client,
)
from server.routers.unifi import doh_apps  # noqa: E402
from server.routers.unifi import traffic_rule as tr  # noqa: E402
from server.store import Store  # noqa: E402


class _FakeSecrets:
    def __init__(self, **values: str) -> None:
        self._values = dict(values)

    def get(self, key: str) -> str | None:
        return self._values.get(key)

    def set(self, key: str, value: str | None) -> None:
        if value is None:
            self._values.pop(key, None)
        else:
            self._values[key] = value


class CapabilitiesTests(unittest.TestCase):
    def test_capabilities_match_documented_design(self) -> None:
        self.assertIsInstance(UNIFI_CAPABILITIES, Capabilities)
        # The plan: Stage 1 + Stage 3 supported; Stage 2 (DNS
        # Director) is explicitly excluded for UniFi because the
        # firmware has no native per-MAC DNS redirect primitive.
        self.assertTrue(UNIFI_CAPABILITIES.supports_kill_switch)
        self.assertFalse(UNIFI_CAPABILITIES.supports_dns_director)
        self.assertTrue(UNIFI_CAPABILITIES.supports_doh_blocking)
        # Simple App Blocking is native to UniFi gateways: no SSH needed.
        self.assertFalse(UNIFI_CAPABILITIES.needs_ssh_for_doh)


class FromStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self._tmp.close()
        self.store = Store(self._tmp.name)

    def tearDown(self) -> None:
        Path(self._tmp.name).unlink(missing_ok=True)

    def test_returns_none_when_settings_missing(self) -> None:
        self.assertIsNone(UnifiAdapter.from_store(self.store, _FakeSecrets()))
        # Partial config -- host only -- still not enough.
        self.store.set_setting(UNIFI_KEYS["host"], "https://unifi.lan")
        self.assertIsNone(UnifiAdapter.from_store(self.store, _FakeSecrets()))

    def test_returns_instance_when_settings_complete(self) -> None:
        self.store.set_setting(UNIFI_KEYS["host"], "https://unifi.lan")
        self.store.set_setting(UNIFI_KEYS["username"], "guardium")
        self.store.set_setting(UNIFI_KEYS["site"], "alpha-home")
        secrets = _FakeSecrets(**{UNIFI_KEYS["password"]: "hunter2"})
        adapter = UnifiAdapter.from_store(self.store, secrets)
        self.assertIsNotNone(adapter)
        assert adapter is not None
        self.assertEqual(adapter.vendor, "unifi")
        self.assertEqual(adapter.site, "alpha-home")
        # Public API is opt-in -- absent secret => disabled.
        self.assertIsNone(adapter._public)

    def test_public_api_built_when_api_key_present(self) -> None:
        self.store.set_setting(UNIFI_KEYS["host"], "https://unifi.lan")
        self.store.set_setting(UNIFI_KEYS["username"], "guardium")
        self.store.set_setting(UNIFI_KEYS["verify_tls"], "1")
        secrets = _FakeSecrets(**{
            UNIFI_KEYS["password"]: "hunter2",
            UNIFI_KEYS["api_key"]: "kid_abc",
        })
        adapter = UnifiAdapter.from_store(self.store, secrets)
        assert adapter is not None
        self.assertIsNotNone(adapter._public)
        # verify_tls flowed through to both clients.
        self.assertTrue(adapter._legacy._verify)
        assert adapter._public is not None
        self.assertTrue(adapter._public._verify)


class ApplyMethodsTests(unittest.TestCase):
    """Phase-2 contract: kill switch and DoH block raise
    NotImplementedError; DNS Director is a permanent no-op.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self._tmp.close()
        store = Store(self._tmp.name)
        store.set_setting(UNIFI_KEYS["host"], "https://unifi.lan")
        store.set_setting(UNIFI_KEYS["username"], "guardium")
        secrets = _FakeSecrets(**{UNIFI_KEYS["password"]: "hunter2"})
        adapter = UnifiAdapter.from_store(store, secrets)
        assert adapter is not None
        self.adapter = adapter

    def tearDown(self) -> None:
        Path(self._tmp.name).unlink(missing_ok=True)

    def test_kill_switch_raises_not_implemented(self) -> None:
        with self.assertRaises(NotImplementedError):
            asyncio.run(self.adapter.apply_kill_switch(["aa:bb:cc:dd:ee:01"], names={}))

    def test_doh_block_raises_not_implemented(self) -> None:
        with self.assertRaises(NotImplementedError):
            asyncio.run(self.adapter.apply_doh_block(["aa:bb:cc:dd:ee:01"], names={}))

    def test_dns_director_is_a_permanent_no_op(self) -> None:
        result = asyncio.run(self.adapter.apply_dns_director(["aa:bb:cc:dd:ee:01"], names={}))
        self.assertEqual(result, {"enabled": False, "supported": False})


class StatStaNormalisationTests(unittest.TestCase):
    def test_minimal_row(self) -> None:
        rc = _to_router_client({
            "mac": "AA:BB:CC:DD:EE:01",
            "ip": "192.168.1.10",
            "name": "Hudson Laptop",
            "is_wired": False,
            "uptime": 1234,
        })
        self.assertEqual(rc.mac, "aa:bb:cc:dd:ee:01")
        self.assertEqual(rc.ip, "192.168.1.10")
        self.assertEqual(rc.name, "Hudson Laptop")
        self.assertTrue(rc.online)

    def test_hostname_fallback_chain(self) -> None:
        rc = _to_router_client({
            "mac": "aa:bb:cc:dd:ee:02",
            "last_ip": "192.168.1.11",
            "hostname": "android-1234",
            "uptime": 0,
        })
        self.assertEqual(rc.ip, "192.168.1.11")
        self.assertEqual(rc.name, "android-1234")
        self.assertFalse(rc.online)

    def test_no_ip_no_name_is_ok(self) -> None:
        rc = _to_router_client({"mac": "aa:bb:cc:dd:ee:03"})
        self.assertIsNone(rc.ip)
        self.assertIsNone(rc.name)


class GatewayDetectionTests(unittest.TestCase):
    def test_known_gateway_models_match(self) -> None:
        for model in ("UDM-Pro", "UDM-SE", "UCG-Ultra", "UXG-Pro", "EFG", "USG-3P"):
            self.assertTrue(_looks_like_gateway({"model": model}),
                             msg=f"{model} should be recognised as a gateway")

    def test_ap_and_switch_are_not_gateways(self) -> None:
        self.assertFalse(_looks_like_gateway({"model": "U6-Pro"}))
        self.assertFalse(_looks_like_gateway({"model": "USW-Pro-24"}))

    def test_name_fallback(self) -> None:
        self.assertTrue(_looks_like_gateway({"model": "???", "name": "Home gateway"}))


class TrafficRuleBuilderTests(unittest.TestCase):
    def test_kill_switch_minimal(self) -> None:
        rule = tr.build_kill_switch_rule(["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"])
        self.assertEqual(rule["name"], tr.KILL_SWITCH_NAME)
        self.assertEqual(rule["action"], "BLOCK")
        self.assertEqual(rule["matching_target"], "INTERNET")
        self.assertTrue(rule["enabled"])
        self.assertEqual(
            [d["client_mac"] for d in rule["target_devices"]],
            ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"],
        )
        # No app fields on a kill-switch rule.
        self.assertEqual(rule["app_ids"], [])
        # Round-trippable as JSON (the controller is picky about types).
        json.dumps(rule)

    def test_kill_switch_normalises_macs(self) -> None:
        rule = tr.build_kill_switch_rule([
            "AA-BB-CC-DD-EE-01",
            "AA:BB:CC:DD:EE:01",      # duplicate, must be deduped
            "garbage",                # not a MAC -> dropped
            "  AA:BB:CC:DD:EE:02 ",   # leading/trailing space
        ])
        macs = [d["client_mac"] for d in rule["target_devices"]]
        self.assertEqual(macs, ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"])

    def test_empty_macs_yield_disabled_rule(self) -> None:
        """Tear-down soft path: keep the row (and its cached _id) but
        flip ``enabled`` to False so nothing is actually blocked.
        """
        rule = tr.build_kill_switch_rule([])
        self.assertFalse(rule["enabled"])
        self.assertEqual(rule["target_devices"], [])

    def test_doh_block_includes_app_ids(self) -> None:
        rule = tr.build_doh_block_rule(
            ["aa:bb:cc:dd:ee:01"],
            ["551", "552"],
        )
        self.assertEqual(rule["matching_target"], "APP")
        self.assertEqual(rule["app_ids"], ["551", "552"])
        self.assertTrue(rule["enabled"])

    def test_doh_block_disabled_when_no_app_ids(self) -> None:
        # Even with MACs, an empty app_ids list must not produce an
        # active rule -- the controller would interpret that as "block
        # all apps".
        rule = tr.build_doh_block_rule(["aa:bb:cc:dd:ee:01"], [])
        self.assertFalse(rule["enabled"])

    def test_is_managed_rule_identifies_our_prefix(self) -> None:
        self.assertTrue(tr.is_managed_rule({"name": "Guardium Internet Off"}))
        self.assertFalse(tr.is_managed_rule({"name": "Block guest network"}))
        self.assertFalse(tr.is_managed_rule({}))


class DohAppDiscoveryTests(unittest.TestCase):
    def test_match_terms(self) -> None:
        async def go():
            class _Fake:
                async def list_dpi_applications(self):
                    return [
                        {"id": 100, "name": "YouTube"},
                        {"id": 551, "name": "DNS over HTTPS"},
                        {"id": 552, "name": "DNS over TLS"},
                        {"id": 553, "name": "DoH (Cloudflare)"},  # alias match
                        {"id": 999, "name": "Robot"},             # mustn't match "DoT"
                    ]
            ids = await doh_apps.discover_doh_app_ids(_Fake())
            return ids

        ids = asyncio.run(go())
        self.assertCountEqual(ids, ["551", "552", "553"])

    def test_empty_catalogue_falls_back(self) -> None:
        async def go():
            class _Fake:
                async def list_dpi_applications(self):
                    return [{"id": 100, "name": "YouTube"}]
            return await doh_apps.discover_doh_app_ids(_Fake())
        ids = asyncio.run(go())
        # Fallback list kicks in.
        self.assertEqual(ids, doh_apps.fallback_app_ids())

    def test_cache_round_trip(self) -> None:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        tmp.close()
        try:
            store = Store(tmp.name)
            self.assertIsNone(doh_apps.load_cached_app_ids(store))
            doh_apps.save_cached_app_ids(store, ["551", "552"])
            self.assertEqual(
                doh_apps.load_cached_app_ids(store),
                ["551", "552"],
            )
        finally:
            Path(tmp.name).unlink(missing_ok=True)


def main() -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite([
        loader.loadTestsFromTestCase(CapabilitiesTests),
        loader.loadTestsFromTestCase(FromStoreTests),
        loader.loadTestsFromTestCase(ApplyMethodsTests),
        loader.loadTestsFromTestCase(StatStaNormalisationTests),
        loader.loadTestsFromTestCase(GatewayDetectionTests),
        loader.loadTestsFromTestCase(TrafficRuleBuilderTests),
        loader.loadTestsFromTestCase(DohAppDiscoveryTests),
    ])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
