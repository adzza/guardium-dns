#!/usr/bin/env python3
"""Read-path probe for the alpha UniFi adapter.

Phase 2 of the UniFi integration ships *only* discovery + read paths;
``apply_*`` methods raise ``NotImplementedError``. This script exists
so beta testers can prove the adapter can talk to their controller --
log in, list sites + clients, find a gateway, discover DoH/DoT app
IDs -- without touching reconciler state.

Two ways to run:

1. **From a Guardium install**: drop the script onto the host that
   runs the dashboard and run it with no args. It reads
   ``router.unifi.*`` settings from ``data/dashboard.db`` and the
   matching encrypted secrets from ``data/.secret_key``.

       $ GUARDIUM_ENABLE_UNIFI_ALPHA=1 python3 scripts/probe_unifi.py

2. **Standalone** (handy on a laptop with no Guardium install): pass
   ``--host``, ``--username``, ``--password`` (and optionally
   ``--api-key``, ``--site``, ``--verify-tls``):

       $ python3 scripts/probe_unifi.py \
             --host https://unifi.lan \
             --username guardium \
             --password '...' \
             --api-key '...' \
             --site default

Exit code is 0 if every probed read-path succeeded, non-zero on the
first hard failure (so this is safe to wire into CI later).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any


# Make `server.*` importable when run from the project root or from
# within scripts/.
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Read-path probe for the alpha Guardium UniFi adapter.",
    )
    p.add_argument("--host", help="Controller base URL "
                                   "(e.g. https://unifi.lan or https://10.0.0.1:443)")
    p.add_argument("--username", help="UniFi local admin (NOT Ubiquiti SSO)")
    p.add_argument("--password", help="Local admin password")
    p.add_argument("--site", default=None, help="Site slug (default: 'default')")
    p.add_argument("--api-key", default=None,
                    help="Public-API key (optional; enables DPI discovery + "
                         "gateway model probe)")
    p.add_argument("--verify-tls", action="store_true",
                    help="Verify TLS certs (default off; UniFi ships self-signed)")
    p.add_argument("--data-dir", default=None,
                    help="Path to data/ (default: ./data). Only used when "
                         "settings aren't passed explicitly.")
    return p.parse_args()


def _load_from_store(data_dir: Path) -> dict[str, str | None]:
    """Read UniFi settings out of the dashboard's SQLite store."""
    from server.store import Store
    from server.vault import SecretStore

    db_path = data_dir / "dashboard.db"
    key_path = data_dir / ".secret_key"
    if not db_path.exists():
        print(f"error: no dashboard DB at {db_path}", file=sys.stderr)
        sys.exit(2)

    store = Store(db_path)
    secrets = SecretStore(store, key_path)
    return {
        "host":       store.get_setting("router.unifi.host"),
        "username":   store.get_setting("router.unifi.username"),
        "password":   secrets.get("router.unifi.password"),
        "site":       store.get_setting("router.unifi.site") or "default",
        "api_key":    secrets.get("router.unifi.api_key"),
        "verify_tls": "1" if store.get_setting("router.unifi.verify_tls") == "1" else None,
    }


def _resolve_settings(args: argparse.Namespace) -> dict[str, Any]:
    """Merge CLI args + the dashboard DB. CLI args win where supplied.

    Returns a dict suitable for instantiating :class:`UnifiAdapter`
    constructor inputs.
    """
    settings: dict[str, Any] = {
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "site": args.site,
        "api_key": args.api_key,
        "verify_tls": bool(args.verify_tls),
    }
    if not (settings["host"] and settings["username"] and settings["password"]):
        # Fall back to the dashboard's saved settings.
        data_dir = Path(args.data_dir).resolve() if args.data_dir else (ROOT / "data")
        from_store = _load_from_store(data_dir)
        for k, v in from_store.items():
            if k == "verify_tls":
                if settings["verify_tls"] is False:
                    settings["verify_tls"] = bool(v)
                continue
            if not settings.get(k):
                settings[k] = v
    settings["site"] = settings.get("site") or "default"
    return settings


async def _run_probe(settings: dict[str, Any]) -> int:
    from server.routers.unifi import UnifiAdapter
    from server.routers.unifi.legacy_api import (
        UnifiAuthError,
        UnifiError,
        UnifiLegacyApi,
    )
    from server.routers.unifi.public_api import UnifiPublicApi

    if not (settings.get("host") and settings.get("username") and settings.get("password")):
        print("error: host, username and password are required (via CLI flags "
              "or saved in the dashboard DB).", file=sys.stderr)
        return 2

    legacy = UnifiLegacyApi(
        host=settings["host"],
        username=settings["username"],
        password=settings["password"],
        site=settings["site"],
        verify_tls=bool(settings.get("verify_tls")),
    )
    public = None
    if settings.get("api_key"):
        public = UnifiPublicApi(
            host=settings["host"],
            api_key=settings["api_key"],
            verify_tls=bool(settings.get("verify_tls")),
        )

    failures = 0

    # --- Probe 1: legacy login --------------------------------------
    try:
        async with legacy as api:
            print(f"[1/5] login OK (flavour={api.flavour})")

            try:
                sites = await api.list_sites()
                print(f"[2/5] sites: {len(sites)}")
                for s in sites:
                    print(f"      - {s.get('name')!r:>18}  desc={s.get('desc') or s.get('description') or ''!r}")
            except UnifiError as exc:
                print(f"[2/5] sites: FAILED -- {exc}", file=sys.stderr)
                failures += 1

            try:
                clients = await api.list_clients()
                print(f"[3/5] clients: {len(clients)} on site={settings['site']!r}")
                for c in clients[:5]:
                    print(f"      - mac={c.get('mac')} ip={c.get('ip') or c.get('last_ip')!r} "
                          f"name={c.get('name') or c.get('hostname') or ''!r}")
                if len(clients) > 5:
                    print(f"      ... and {len(clients) - 5} more.")
            except UnifiError as exc:
                print(f"[3/5] clients: FAILED -- {exc}", file=sys.stderr)
                failures += 1

            try:
                rules = await api.list_traffic_rules()
                print(f"[4/5] traffic rules: {len(rules)}")
                for r in rules:
                    print(f"      - id={r.get('_id')!r} "
                          f"name={r.get('name')!r} "
                          f"matching_target={r.get('matching_target')!r} "
                          f"enabled={r.get('enabled')!r}")
            except UnifiError as exc:
                print(f"[4/5] traffic rules: FAILED -- {exc}", file=sys.stderr)
                failures += 1
    except UnifiAuthError as exc:
        print(f"[1/5] login: AUTH FAILED -- {exc}", file=sys.stderr)
        return 2
    except UnifiError as exc:
        print(f"[1/5] login: FAILED -- {exc}", file=sys.stderr)
        return 2

    # --- Probe 5: public API (DPI + gateway model) ------------------
    if public is None:
        print("[5/5] public API: skipped (no API key supplied)")
        return 1 if failures else 0

    from server.routers.unifi.doh_apps import discover_doh_app_ids

    try:
        async with public as p:
            try:
                sites = await p.list_sites()
                site_id = None
                for s in sites:
                    if s.get("name") == settings["site"] or s.get("internalReference") == settings["site"]:
                        site_id = s.get("id") or s.get("siteId")
                        break
                if site_id is None and sites:
                    site_id = sites[0].get("id") or sites[0].get("siteId")
                print(f"[5/5] public API: site_id={site_id!r}")

                if site_id:
                    devices = await p.list_devices(site_id)
                    print(f"      devices: {len(devices)} (gateways: "
                          f"{sum(1 for d in devices if 'UDM' in str(d.get('model','')).upper() or 'UCG' in str(d.get('model','')).upper())})")
                    for d in devices[:5]:
                        print(f"      - model={d.get('model')!r} "
                              f"name={d.get('name')!r} "
                              f"version={d.get('version')!r}")

                doh_ids = await discover_doh_app_ids(p)
                print(f"      DoH/DoT app IDs (discovered): {doh_ids}")
            except Exception as exc:  # noqa: BLE001
                print(f"[5/5] public API: FAILED -- {exc}", file=sys.stderr)
                failures += 1
    except Exception as exc:  # noqa: BLE001
        print(f"[5/5] public API: FAILED to open -- {exc}", file=sys.stderr)
        failures += 1

    return 1 if failures else 0


def main() -> int:
    args = _parse_args()
    if os.environ.get("GUARDIUM_ENABLE_UNIFI_ALPHA") != "1":
        print(
            "warning: GUARDIUM_ENABLE_UNIFI_ALPHA is not set. The dashboard\n"
            "         won't load the UniFi adapter for real reconciler ticks\n"
            "         until you set it, but this probe will run anyway.\n",
            file=sys.stderr,
        )
    settings = _resolve_settings(args)
    return asyncio.run(_run_probe(settings))


if __name__ == "__main__":
    sys.exit(main())
