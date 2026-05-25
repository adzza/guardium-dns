"""Guardium DNS FastAPI application.

The dashboard exposes:

    GET  /                  - main UI (requires login)
    GET  /login             - login form
    POST /api/auth/login    - login (proxies Technitium /api/user/login)
    POST /api/auth/logout
    GET  /api/auth/me

    GET  /api/overview      - aggregated dashboard payload
    GET  /api/profiles      - list of available profiles
    GET  /api/apps          - app-blocking catalog
    GET  /api/audit         - audit log
    GET  /api/health        - liveness probe (no auth)

    POST /api/devices/{ip}              - rename / annotate
    POST /api/devices/{ip}/profile      - set device base profile
    DELETE /api/devices/{ip}/profile    - clear device base profile
    POST /api/devices/{ip}/favourite    - star/unstar
    POST /api/devices/{ip}/adopt-hostname
    POST /api/devices/{ip}/pause        - manual pause (transient override)
    POST /api/devices/{ip}/resume       - clear manual override
    POST /api/devices/{ip}/person       - attach to a person (or detach if null)
    GET  /api/devices/{ip}/queries      - per-device DNS query log

    GET    /api/people                  - list people
    POST   /api/people                  - create
    PATCH  /api/people/{id}
    DELETE /api/people/{id}
    POST   /api/people/{id}/profile     - set person base profile
    POST   /api/people/{id}/pause       - manual pause for the whole person
    POST   /api/people/{id}/resume

    GET    /api/schedules               - list (all targets)
    POST   /api/schedules               - create
    PATCH  /api/schedules/{id}
    DELETE /api/schedules/{id}

    GET    /api/quotas
    POST   /api/quotas
    PATCH  /api/quotas/{id}
    DELETE /api/quotas/{id}

    POST   /api/family/pause            - quick "dinner is ready" pause-for-all
    POST   /api/family/resume

Authentication: log in with Technitium admin credentials. The Technitium
session token is stored in an HTTP-only cookie. Every API call uses that
token to talk to Technitium directly, so the dashboard inherits Technitium's
permissions model exactly.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import apps as appcat
from . import fingerprint as fp
from . import oui
from . import overrides as ov
from . import profiles
from .hostnames import HostnameResolver
from .reconciler import Reconciler, trace_to_dict
from .routers.asus import (
    AsusRouterClient,
    AsusRouterError,
    AsusSshClient,
    AsusSshError,
    SshConfig,
    detect_router_endpoint,
)
from .routers.registry import (
    VENDOR_SETTING_KEY,
    get_adapter as get_router_adapter,
)
from .routers.unifi import UNIFI_KEYS
from .routers.unifi.legacy_api import (
    UnifiAuthError,
    UnifiError,
    UnifiLegacyApi,
)
from .sampler import Sampler
from .store import Store
from .technitium import TechnitiumClient, TechnitiumConfig, TechnitiumError
from .vault import SecretStore


log = logging.getLogger("dns-dashboard")

# ---- configuration -----------------------------------------------------------

TECHNITIUM_URL = os.environ.get("TECHNITIUM_URL", "http://127.0.0.1:5380")
DASHBOARD_HOST = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "8080"))
DATA_DIR = Path(os.environ.get("DASHBOARD_DATA_DIR", "/var/lib/dns-dashboard"))
WEB_DIR = Path(os.environ.get("DASHBOARD_WEB_DIR", str(Path(__file__).resolve().parents[1] / "web")))
SESSION_COOKIE = "dnsdash_token"
SESSION_USER_COOKIE = "dnsdash_user"
COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7 days

LAN_DNS_RESOLVERS = os.environ.get("LAN_DNS_RESOLVERS", "").strip()
LAN_DOMAIN_STRIP = [
    d.strip()
    for d in os.environ.get("LAN_DOMAIN_STRIP", "lan,local,home,asus.com,router.asus.com").split(",")
    if d.strip()
]

DATA_DIR.mkdir(parents=True, exist_ok=True)
store = Store(DATA_DIR / "dashboard.db")
secrets = SecretStore(store, DATA_DIR / ".secret_key")


# ---- router settings keys ----------------------------------------------------

ROUTER_KEYS = {
    "host":     "router.asus.host",
    "username": "router.asus.username",
    "password": "router.asus.password",  # encrypted via SecretStore
    "scheme":   "router.asus.scheme",
    "port":     "router.asus.port",
    "enabled":  "router.asus.enabled",
    # Stage 2 -- DNS Director
    "dns_director_enabled": "router.asus.dns_director_enabled",
    "dns_director_ip":      "router.asus.dns_director_ip",
    # Stage 3 -- DoH IP blocklist via SSH
    "ssh_enabled":          "router.asus.ssh_enabled",
    "ssh_port":             "router.asus.ssh_port",
    "ssh_password":         "router.asus.ssh_password",  # encrypted
    "doh_block_enabled":    "router.asus.doh_block_enabled",
}


def _router_settings() -> dict[str, str | None]:
    """Read non-secret router settings from the store."""
    return {
        "host":     store.get_setting(ROUTER_KEYS["host"]),
        "username": store.get_setting(ROUTER_KEYS["username"]),
        "scheme":   store.get_setting(ROUTER_KEYS["scheme"]) or "http",
        "port":     store.get_setting(ROUTER_KEYS["port"]),
        "enabled":  store.get_setting(ROUTER_KEYS["enabled"]) == "1",
        # Stage 2
        "dns_director_enabled": store.get_setting(ROUTER_KEYS["dns_director_enabled"]) == "1",
        "dns_director_ip":      store.get_setting(ROUTER_KEYS["dns_director_ip"]),
        # Stage 3
        "ssh_enabled":          store.get_setting(ROUTER_KEYS["ssh_enabled"]) == "1",
        "ssh_port":             store.get_setting(ROUTER_KEYS["ssh_port"]),
        "doh_block_enabled":    store.get_setting(ROUTER_KEYS["doh_block_enabled"]) == "1",
    }


def build_router_client() -> AsusRouterClient | None:
    """Construct an AsusRouterClient from saved settings, or ``None``."""
    cfg = _router_settings()
    if not cfg["enabled"]:
        return None
    host = cfg["host"]
    user = cfg["username"]
    pw = secrets.get(ROUTER_KEYS["password"])
    if not (host and user and pw):
        return None
    port_raw = cfg["port"]
    port = int(port_raw) if port_raw and port_raw.isdigit() else None
    return AsusRouterClient(
        host=host,
        username=user,
        password=pw,
        scheme=cfg["scheme"] or "http",
        port=port,
    )


def build_ssh_config(*, ignore_enabled: bool = False) -> "SshConfig | None":
    """Construct an SshConfig for the router, or ``None`` if unavailable.

    Falls back to the web-UI password if a separate SSH password isn't
    set -- typical AsusWRT setup uses the same admin credentials for both.

    ``ignore_enabled`` lets the reconciler grab a config even when the
    user has just toggled "Enable SSH" off, so we can still reach the
    router to *tear down* whatever rules we previously installed.
    """
    cfg = _router_settings()
    if not cfg["enabled"]:
        return None
    if not (ignore_enabled or cfg["ssh_enabled"]):
        return None
    host = cfg["host"]
    user = cfg["username"]
    if not (host and user):
        return None
    pw = secrets.get(ROUTER_KEYS["ssh_password"]) or secrets.get(ROUTER_KEYS["password"])
    if not pw:
        return None
    port_raw = cfg["ssh_port"]
    port = int(port_raw) if port_raw and port_raw.isdigit() else 2222
    return SshConfig(host=host, port=port, username=user, password=pw)


# ---- lifespan / Technitium client -------------------------------------------

def _detect_default_gateway() -> str | None:
    try:
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                if parts[1] == "00000000":
                    raw = parts[2]
                    octets = [int(raw[i : i + 2], 16) for i in range(6, -1, -2)]
                    return ".".join(str(o) for o in octets)
    except OSError:
        return None
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    service_token = os.environ.get("TECHNITIUM_SERVICE_TOKEN")
    cfg = TechnitiumConfig(base_url=TECHNITIUM_URL, token=service_token)
    app.state.service_client = TechnitiumClient(cfg)

    if LAN_DNS_RESOLVERS:
        resolvers = [r.strip() for r in LAN_DNS_RESOLVERS.split(",") if r.strip()]
    else:
        gw = _detect_default_gateway()
        resolvers = [gw] if gw else []
    if resolvers:
        log.info("Hostname resolver targeting: %s", ", ".join(resolvers))
        app.state.hostname_resolver = HostnameResolver(
            nameservers=resolvers,
            domain_strip=LAN_DOMAIN_STRIP,
        )
    else:
        log.warning("No LAN DNS resolver configured/detected; hostname enrichment disabled")
        app.state.hostname_resolver = None

    app.state.reconciler = None
    app.state.sampler = None

    if service_token:
        try:
            await ensure_managed_groups(app.state.service_client)
            log.info("Seeded/verified managed Advanced Blocking groups")
        except Exception:
            log.exception("Failed to seed managed groups at startup (continuing)")

        try:
            await app.state.service_client.install_app_from_store(
                "Query Logs (Sqlite)",
                "https://download.technitium.com/dns/apps/QueryLogsSqliteApp-v9.1.zip",
            )
            log.info("Verified Query Logs (Sqlite) app installation")
        except Exception:
            log.exception("Failed to install Query Logs app at startup (continuing)")

        # One-time backfill: any IP currently mapped to a managed group in
        # Technitium that has a NULL base_profile_id in our store gets the
        # mapping promoted to its base profile. This protects upgraders so
        # the reconciler doesn't decide their old direct-API profile
        # assignments are "no longer wanted" and clear them.
        try:
            await _backfill_base_profiles(app.state.service_client)
        except Exception:
            log.exception("base-profile backfill failed (continuing)")

        # Reconciler + sampler need the service client to push periodic state
        # updates without depending on a logged-in user.
        app.state.reconciler = Reconciler(
            store,
            app.state.service_client,
            adapter_factory=lambda: get_router_adapter(store, secrets),
        )
        app.state.sampler = Sampler(store, app.state.service_client)
        await app.state.reconciler.start()
        await app.state.sampler.start()
    else:
        log.warning("TECHNITIUM_SERVICE_TOKEN not set; reconciler & sampler disabled. "
                    "Schedules/quotas/family-pause will not fire automatically.")

    try:
        yield
    finally:
        if app.state.reconciler is not None:
            await app.state.reconciler.stop()
        if app.state.sampler is not None:
            await app.state.sampler.stop()
        await app.state.service_client.aclose()


app = FastAPI(title="Guardium DNS", version="2.0.0", lifespan=lifespan)


# ---- helpers ----------------------------------------------------------------

def make_user_client(token: str | None) -> TechnitiumClient:
    return TechnitiumClient(TechnitiumConfig(base_url=TECHNITIUM_URL, token=token))


_INVALID_TOKEN_MARKERS = (
    "invalid token",
    "session expired",
    "session does not exist",
    "session has expired",
)


def _is_invalid_token_error(exc: TechnitiumError) -> bool:
    msg = str(exc).lower()
    return any(m in msg for m in _INVALID_TOKEN_MARKERS)


def _http_from_technitium(exc: TechnitiumError, default_status: int = 502) -> HTTPException:
    """Translate a Technitium upstream error into an HTTPException.

    Stale/invalid session tokens become 401 so the frontend can redirect the
    user back to the login screen instead of surfacing an opaque 502.
    """
    if _is_invalid_token_error(exc):
        return HTTPException(status_code=401, detail="session expired")
    return HTTPException(status_code=default_status, detail=str(exc))


async def require_token(
    request: Request,
    dnsdash_token: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> str:
    if not dnsdash_token:
        raise HTTPException(status_code=401, detail="not authenticated")
    return dnsdash_token


async def get_actor(
    dnsdash_user: str | None = Cookie(default=None, alias=SESSION_USER_COOKIE),
) -> str:
    return dnsdash_user or "unknown"


def _is_valid_ip_or_cidr(value: str) -> bool:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def _kick_reconcile() -> None:
    """Run an immediate reconcile pass after a state change so the user sees
    their action take effect right away (instead of waiting up to 60s)."""
    rec: Reconciler | None = getattr(app.state, "reconciler", None)
    if rec is None:
        return
    try:
        await rec.tick()
    except Exception:
        log.exception("immediate reconcile failed")


# ---- Advanced Blocking integration ------------------------------------------

ADVANCED_BLOCKING_APP = "Advanced Blocking"


async def ensure_managed_groups(client: TechnitiumClient) -> dict[str, Any]:
    """Make sure every managed profile exists as a group in the AB app config."""
    config = await client.get_app_config(ADVANCED_BLOCKING_APP)
    existing_groups = config.setdefault("groups", [])

    new_groups: list[dict[str, Any]] = []
    for g in existing_groups:
        if g["name"] in profiles.MANAGED_GROUP_NAMES:
            continue
        new_groups.append(g)

    for pid, p in profiles.PROFILES.items():
        new_groups.append(json.loads(json.dumps(p["group"])))

    config["groups"] = new_groups

    network_map = config.setdefault("networkGroupMap", {})
    if "0.0.0.0/0" not in network_map:
        network_map["0.0.0.0/0"] = profiles.DEFAULT_GROUP
    if "[::]/0" not in network_map:
        network_map["[::]/0"] = profiles.DEFAULT_GROUP

    config.setdefault("enableBlocking", True)
    config.setdefault("blockingAnswerTtl", 30)
    config.setdefault("blockListUrlUpdateIntervalHours", 24)
    config.setdefault("blockListUrlUpdateIntervalMinutes", 0)
    config.setdefault("localEndPointGroupMap", {})

    await client.set_app_config(ADVANCED_BLOCKING_APP, config)
    return config


async def get_network_group_map(client: TechnitiumClient) -> dict[str, str]:
    config = await client.get_app_config(ADVANCED_BLOCKING_APP)
    return dict(config.get("networkGroupMap") or {})


async def _backfill_base_profiles(client: TechnitiumClient) -> int:
    """Promote live networkGroupMap entries to per-device base_profile_id.

    Idempotent: only fills in store rows whose base_profile_id is NULL.
    Returns the number of devices updated.
    """
    try:
        network_map = await get_network_group_map(client)
    except TechnitiumError:
        return 0
    name_to_profile = {p["group"]["name"]: pid for pid, p in profiles.PROFILES.items()}
    updated = 0
    for stored in store.all_devices():
        if stored.get("base_profile_id"):
            continue
        ip = stored["ip"]
        if "/" in ip:
            continue
        group = network_map.get(ip)
        if not group:
            continue
        pid = name_to_profile.get(group)
        if not pid:
            continue
        store.set_device_base_profile(ip, pid)
        updated += 1
    if updated:
        log.info("Backfilled base_profile_id for %d existing device(s)", updated)
    return updated


# ---- routes: auth -----------------------------------------------------------

class LoginPayload(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


@app.post("/api/auth/login")
async def login(payload: LoginPayload, response: Response) -> dict[str, Any]:
    async with make_user_client(None) as client:
        try:
            data = await client.login(payload.username, payload.password)
        except TechnitiumError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from None

    token = data.get("token")
    if not token:
        raise HTTPException(status_code=502, detail="Technitium did not return a token")

    response.set_cookie(SESSION_COOKIE, token, max_age=COOKIE_MAX_AGE,
                        httponly=True, samesite="lax", secure=False)
    response.set_cookie(SESSION_USER_COOKIE, payload.username, max_age=COOKIE_MAX_AGE,
                        httponly=False, samesite="lax", secure=False)

    store.log_audit(actor=payload.username, ip=None, action="login")
    return {
        "username": data.get("username", payload.username),
        "displayName": data.get("displayName"),
        "permissions": (data.get("info") or {}).get("permissions", {}),
    }


@app.post("/api/auth/logout")
async def logout(response: Response, token: str = Depends(require_token), actor: str = Depends(get_actor)) -> dict[str, Any]:
    async with make_user_client(token) as client:
        await client.logout(token)
    response.delete_cookie(SESSION_COOKIE)
    response.delete_cookie(SESSION_USER_COOKIE)
    store.log_audit(actor=actor, ip=None, action="logout")
    return {"ok": True}


@app.get("/api/auth/me")
async def auth_me(token: str = Depends(require_token), actor: str = Depends(get_actor)) -> dict[str, Any]:
    async with make_user_client(token) as client:
        try:
            data = await client.session_info(token)
        except TechnitiumError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from None
    return {"username": actor, "session": data.get("response", {})}


# ---- routes: catalogue ------------------------------------------------------

@app.get("/api/profiles")
async def api_profiles(_: str = Depends(require_token)) -> dict[str, Any]:
    return {"profiles": profiles.profile_summary()}


@app.get("/api/apps")
async def api_apps(_: str = Depends(require_token)) -> dict[str, Any]:
    return appcat.catalog_summary()


# ---- routes: overview -------------------------------------------------------

@app.get("/api/overview")
async def api_overview(
    request: Request,
    time_range: str = "LastHour",
    token: str = Depends(require_token),
) -> dict[str, Any]:
    if time_range not in ("LastHour", "LastDay", "LastWeek", "LastMonth", "LastYear"):
        raise HTTPException(status_code=400, detail="invalid time_range")

    async with make_user_client(token) as client:
        stats_task = asyncio.create_task(client.get_dashboard_stats(time_range=time_range))
        top_clients_task = asyncio.create_task(client.get_top(stats_type="TopClients", time_range=time_range, limit=50))
        top_domains_task = asyncio.create_task(client.get_top(stats_type="TopDomains", time_range=time_range, limit=20))
        top_blocked_task = asyncio.create_task(client.get_top(stats_type="TopBlockedDomains", time_range=time_range, limit=20))
        net_map_task = asyncio.create_task(get_network_group_map(client))

        try:
            stats = await stats_task
            top_clients = await top_clients_task
            top_domains = await top_domains_task
            top_blocked = await top_blocked_task
            network_map = await net_map_task
        except TechnitiumError as exc:
            raise _http_from_technitium(exc) from None

    for c in top_clients:
        ip = c.get("name")
        if ip:
            store.touch_device(ip)

    resolver: HostnameResolver | None = getattr(request.app.state, "hostname_resolver", None)
    all_ips: list[str] = []
    seen: set[str] = set()
    for c in top_clients:
        ip = c.get("name")
        if ip and ip not in seen and _is_valid_ip_or_cidr(ip) and "/" not in ip:
            seen.add(ip)
            all_ips.append(ip)
    for stored in store.all_devices():
        ip = stored["ip"]
        if ip not in seen and _is_valid_ip_or_cidr(ip) and "/" not in ip:
            seen.add(ip)
            all_ips.append(ip)
    hostnames: dict[str, str | None] = {}
    if resolver:
        try:
            hostnames = await resolver.lookup_many(all_ips)
        except Exception:
            log.exception("hostname resolver failed")
            hostnames = {}

    # Snapshot all the override-engine inputs once.
    now_local = datetime.now()
    now_utc = int(time.time())
    today = ov.local_today(now_local)

    schedules = store.all_schedules()
    quotas = store.all_quotas()
    actives = store.active_overrides(now_utc)
    usage = store.get_daily_usages(today)
    people_rows = store.all_people()
    devices_rows = store.all_devices()

    scheds_by_target: dict[tuple[str, str], list[dict]] = {}
    for s in schedules:
        scheds_by_target.setdefault((s["target_kind"], s["target_id"] or "*"), []).append(s)
    quotas_by_target: dict[tuple[str, str], list[dict]] = {}
    for q in quotas:
        quotas_by_target.setdefault((q["target_kind"], q["target_id"]), []).append(q)
    ovs_by_target: dict[tuple[str, str], list[dict]] = {}
    for o in actives:
        ovs_by_target.setdefault((o["target_kind"], o["target_id"]), []).append(o)

    person_traces: dict[int, ov.OverrideTrace] = {}
    for p in people_rows:
        pid = p["id"]
        state = ov.TargetState(
            base_profile_id=p["base_profile_id"],
            schedules=scheds_by_target.get(("person", str(pid)), [])
                     + scheds_by_target.get(("all", "*"), []),
            quotas=quotas_by_target.get(("person", str(pid)), []),
            overrides=ovs_by_target.get(("person", str(pid)), []),
            daily_usage_minutes=usage.get(("person", str(pid)), 0),
        )
        person_traces[pid] = ov.resolve_target(state, now_local=now_local, now_utc=now_utc, person_id=pid)

    devices = _build_devices(top_clients, network_map, hostnames,
                              devices_rows, scheds_by_target, quotas_by_target,
                              ovs_by_target, usage, person_traces, now_local, now_utc)

    # People payload with computed effective state + their devices.
    name_to_profile = {p["group"]["name"]: pid for pid, p in profiles.PROFILES.items()}
    people = []
    for p in people_rows:
        pid = p["id"]
        trace = person_traces[pid]
        # Cumulate device-level usage as a fallback display number; person-level
        # usage is the authoritative quota counter.
        person_devices = [d for d in devices if d.get("personId") == pid]
        people.append({
            "id": pid,
            "name": p["name"],
            "avatar": p["avatar"],
            "color": p["color"],
            "baseProfileId": p["base_profile_id"],
            "sortOrder": p["sort_order"],
            "deviceCount": len(person_devices),
            "onlineCount": sum(1 for d in person_devices if d["online"]),
            "todayMinutes": usage.get(("person", str(pid)), 0),
            "effective": trace_to_dict(trace),
            "schedules": [_schedule_dto(s) for s in scheds_by_target.get(("person", str(pid)), [])],
            "quotas": [_quota_dto(q) for q in quotas_by_target.get(("person", str(pid)), [])],
            "overrides": [_override_dto(o) for o in ovs_by_target.get(("person", str(pid)), [])],
            "devices": [{
                "ip": d["ip"],
                "label": d["label"],
                "hostname": d["hostname"],
                "online": d["online"],
                "todayMinutes": usage.get(("device", d["ip"]), 0),
            } for d in person_devices],
        })

    # Profile distribution.
    distribution: dict[str, dict[str, Any]] = {}
    for d in devices:
        eff_pid = (d.get("effective") or {}).get("profileId")
        key = eff_pid or "_none"
        bucket = distribution.setdefault(key, {
            "profileId": eff_pid,
            "groupName": profiles.PROFILES[eff_pid]["group"]["name"] if eff_pid in profiles.PROFILES else None,
            "count": 0,
            "devices": [],
        })
        bucket["count"] += 1
        bucket["devices"].append({
            "ip": d["ip"],
            "label": d["label"],
            "hostname": d.get("hostname"),
            "online": d["online"],
        })
    # Also surface user-created groups that exist in Technitium but aren't
    # owned by a known profile -- so the techie view stays honest.
    for ip, group in network_map.items():
        if "/" in ip:
            continue
        if group not in name_to_profile:
            key = f"_grp_{group}"
            bucket = distribution.setdefault(key, {
                "profileId": None,
                "groupName": group,
                "count": 0,
                "devices": [],
                "external": True,
            })
            if not any(d["ip"] == ip for d in bucket["devices"]):
                bucket["count"] += 1
                bucket["devices"].append({"ip": ip, "label": None, "hostname": None, "online": False})

    favourites = [d for d in devices if d.get("favourite")]
    favourites.sort(key=lambda d: (-(d.get("favOrder") or 0), d["ip"]))

    # The family-pause action stamps one override row per device (the
    # implementation chose per-device rows so exclusions and unassigned-
    # device skipping can be cleanly expressed). Detect "is family-pause
    # currently on?" by source, not by target_kind.
    family_pause = next((o for o in actives if o.get("source") == "family-pause"), None)

    return {
        "stats": stats.get("stats", {}),
        "mainChartData": stats.get("mainChartData", {}),
        "queryResponseChartData": stats.get("queryResponseChartData", {}),
        "topClients": top_clients,
        "topDomains": top_domains,
        "topBlockedDomains": top_blocked,
        "devices": devices,
        "favourites": favourites,
        "people": people,
        "schedules": [_schedule_dto(s) for s in schedules],
        "quotas": [_quota_dto(q) for q in quotas],
        "distribution": list(distribution.values()),
        "networkGroupMap": network_map,
        "timeRange": time_range,
        "today": today,
        "serverTime": now_utc,
        "familyPause": _override_dto(family_pause) if family_pause else None,
        "hostnameResolver": resolver.nameservers if resolver else [],
        "reconcilerStatus": (request.app.state.reconciler.status
                              if getattr(request.app.state, "reconciler", None) else None),
    }


def _schedule_dto(s: dict) -> dict[str, Any]:
    return {
        "id": s["id"],
        "targetKind": s["target_kind"],
        "targetId": s["target_id"],
        "name": s["name"],
        "weekdayMask": s["weekday_mask"],
        "startMin": s["start_min"],
        "endMin": s["end_min"],
        "profileId": s["profile_id"],
        "enabled": bool(s["enabled"]),
    }


def _quota_dto(q: dict) -> dict[str, Any]:
    return {
        "id": q["id"],
        "targetKind": q["target_kind"],
        "targetId": q["target_id"],
        "name": q["name"],
        "weekdayMask": q["weekday_mask"],
        "minutesMax": q["minutes_max"],
        "profileWhenExceeded": q["profile_when_exceeded"],
        "enabled": bool(q["enabled"]),
    }


def _override_dto(o: dict | None) -> dict[str, Any] | None:
    if not o:
        return None
    return {
        "id": o["id"],
        "targetKind": o["target_kind"],
        "targetId": o["target_id"],
        "profileId": o["profile_id"],
        "source": o["source"],
        "startsAt": o["starts_at"],
        "expiresAt": o["expires_at"],
        "createdBy": o["created_by"],
        "note": o["note"],
    }


def _build_devices(
    top_clients: list[dict[str, Any]],
    network_map: dict[str, str],
    hostnames: dict[str, str | None],
    stored_devices: list[dict],
    scheds_by_target: dict[tuple[str, str], list[dict]],
    quotas_by_target: dict[tuple[str, str], list[dict]],
    ovs_by_target: dict[tuple[str, str], list[dict]],
    usage: dict[tuple[str, str], int],
    person_traces: dict[int, ov.OverrideTrace],
    now_local: datetime,
    now_utc: int,
) -> list[dict[str, Any]]:
    name_to_profile = {p["group"]["name"]: pid for pid, p in profiles.PROFILES.items()}

    seen_ips: set[str] = set()
    devices: list[dict[str, Any]] = []
    by_ip = {d["ip"]: d for d in stored_devices}

    def _make(ip: str, hits: int, online: bool) -> dict[str, Any]:
        stored = by_ip.get(ip) or {}
        person_id = stored.get("person_id")
        state = ov.TargetState(
            base_profile_id=stored.get("base_profile_id"),
            schedules=scheds_by_target.get(("device", ip), [])
                     + scheds_by_target.get(("all", "*"), []),
            quotas=quotas_by_target.get(("device", ip), []),
            overrides=ovs_by_target.get(("device", ip), []),
            daily_usage_minutes=usage.get(("device", ip), 0),
        )
        trace = ov.resolve_target(state, now_local=now_local, now_utc=now_utc)
        if person_id and person_id in person_traces:
            trace = ov.merge_person_into_device(trace, person_traces[person_id])

        # Live profile id from Technitium's group map (so techie view can show drift).
        live_group = network_map.get(ip)
        live_profile = name_to_profile.get(live_group) if live_group else None

        return {
            "ip": ip,
            "label": stored.get("label"),
            "hostname": hostnames.get(ip),
            "notes": stored.get("notes"),
            "favourite": bool(stored.get("favourite")),
            "favOrder": stored.get("fav_order") or 0,
            "personId": person_id,
            "baseProfileId": stored.get("base_profile_id"),
            "macAddress": stored.get("mac_address"),
            "vendor": stored.get("vendor"),
            "fingerprintHint": stored.get("fingerprint_hint"),
            "fingerprintAt": stored.get("fingerprint_inferred_at"),
            "hits": hits,
            "online": online,
            "group": live_group,
            "profileId": trace.profile_id,             # effective (computed)
            "liveProfileId": live_profile,             # actually-applied right now
            "effective": trace_to_dict(trace),
            "todayMinutes": usage.get(("device", ip), 0),
            "firstSeen": stored.get("first_seen"),
            "lastSeen": stored.get("last_seen"),
        }

    for c in top_clients:
        ip = c.get("name")
        if not ip:
            continue
        seen_ips.add(ip)
        devices.append(_make(ip, c.get("hits", 0), True))

    for stored in stored_devices:
        ip = stored["ip"]
        if ip in seen_ips or not _is_valid_ip_or_cidr(ip):
            continue
        devices.append(_make(ip, 0, False))

    devices.sort(key=lambda d: (not d["online"], -d["hits"], d["ip"]))
    return devices


# ---- routes: devices --------------------------------------------------------

class DeviceUpdate(BaseModel):
    label: str | None = Field(default=None, max_length=80)
    notes: str | None = Field(default=None, max_length=400)


@app.post("/api/devices/{ip}")
async def api_update_device(
    ip: str,
    payload: DeviceUpdate,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if not _is_valid_ip_or_cidr(ip):
        raise HTTPException(status_code=400, detail="invalid IP/CIDR")
    label = (payload.label or "").strip() or None
    notes = (payload.notes or "").strip() or None
    store.update_label(ip, label, notes)
    store.log_audit(actor=actor, ip=ip, action="rename", detail=label)
    return {"ok": True, "device": store.get_device(ip)}


class ProfilePayload(BaseModel):
    profileId: str | None = None


@app.post("/api/devices/{ip}/profile")
async def api_set_device_profile(
    ip: str,
    payload: ProfilePayload,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if not _is_valid_ip_or_cidr(ip):
        raise HTTPException(status_code=400, detail="invalid IP/CIDR")
    if payload.profileId and payload.profileId not in profiles.PROFILES:
        raise HTTPException(status_code=400, detail="unknown profile")
    store.set_device_base_profile(ip, payload.profileId)
    store.log_audit(actor=actor, ip=ip,
                     action="set-profile" if payload.profileId else "clear-profile",
                     detail=payload.profileId)
    await _kick_reconcile()
    return {"ok": True, "ip": ip, "profileId": payload.profileId}


@app.delete("/api/devices/{ip}/profile")
async def api_clear_device_profile(
    ip: str,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    store.set_device_base_profile(ip, None)
    store.log_audit(actor=actor, ip=ip, action="clear-profile")
    await _kick_reconcile()
    return {"ok": True, "ip": ip}


class FavouritePayload(BaseModel):
    favourite: bool


@app.post("/api/devices/{ip}/favourite")
async def api_set_favourite(
    ip: str,
    payload: FavouritePayload,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if not _is_valid_ip_or_cidr(ip):
        raise HTTPException(status_code=400, detail="invalid IP/CIDR")
    store.set_favourite(ip, payload.favourite)
    store.log_audit(actor=actor, ip=ip,
                     action="favourite" if payload.favourite else "unfavourite")
    return {"ok": True, "ip": ip, "favourite": payload.favourite}


class PausePayload(BaseModel):
    minutes: int = Field(default=60, ge=1, le=24 * 60)
    profileId: str | None = None  # null = internet-off
    note: str | None = Field(default=None, max_length=200)


@app.post("/api/devices/{ip}/pause")
async def api_pause_device(
    ip: str,
    payload: PausePayload,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if not _is_valid_ip_or_cidr(ip):
        raise HTTPException(status_code=400, detail="invalid IP/CIDR")
    if payload.profileId and payload.profileId not in profiles.PROFILES:
        raise HTTPException(status_code=400, detail="unknown profile")
    now = int(time.time())
    expires = now + payload.minutes * 60
    store.add_override(target_kind="device", target_id=ip,
                        profile_id=payload.profileId, source="manual",
                        starts_at=now, expires_at=expires,
                        created_by=actor, note=payload.note)
    store.log_audit(actor=actor, ip=ip, action="pause",
                     detail=f"{payload.minutes}m -> {payload.profileId or 'internet-off'}")
    await _kick_reconcile()
    return {"ok": True, "ip": ip, "expiresAt": expires}


@app.post("/api/devices/{ip}/resume")
async def api_resume_device(
    ip: str,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if not _is_valid_ip_or_cidr(ip):
        raise HTTPException(status_code=400, detail="invalid IP/CIDR")
    cleared = store.clear_overrides(target_kind="device", target_id=ip,
                                      sources=["manual"])
    store.log_audit(actor=actor, ip=ip, action="resume", detail=str(cleared))
    await _kick_reconcile()
    return {"ok": True, "ip": ip, "cleared": cleared}


class AttachPersonPayload(BaseModel):
    personId: int | None = None


@app.post("/api/devices/{ip}/person")
async def api_attach_person(
    ip: str,
    payload: AttachPersonPayload,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if not _is_valid_ip_or_cidr(ip):
        raise HTTPException(status_code=400, detail="invalid IP/CIDR")
    if payload.personId is not None and store.get_person(payload.personId) is None:
        raise HTTPException(status_code=404, detail="unknown person")
    store.attach_device_to_person(ip, payload.personId)
    store.log_audit(actor=actor, ip=ip,
                     action="attach-person" if payload.personId else "detach-person",
                     detail=str(payload.personId) if payload.personId else None)
    await _kick_reconcile()
    return {"ok": True, "ip": ip, "personId": payload.personId}


@app.post("/api/devices/{ip}/adopt-hostname")
async def api_adopt_hostname(
    request: Request,
    ip: str,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if not _is_valid_ip_or_cidr(ip):
        raise HTTPException(status_code=400, detail="invalid IP/CIDR")
    resolver: HostnameResolver | None = getattr(request.app.state, "hostname_resolver", None)
    if not resolver:
        raise HTTPException(status_code=503, detail="hostname resolver not configured")
    hostname = await resolver.lookup(ip)
    if not hostname:
        raise HTTPException(status_code=404, detail="no PTR record for this IP")
    store.update_label(ip, hostname, None)
    store.log_audit(actor=actor, ip=ip, action="adopt-hostname", detail=hostname)
    return {"ok": True, "ip": ip, "label": hostname}


@app.post("/api/hostnames/refresh")
async def api_refresh_hostnames(
    request: Request,
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    resolver: HostnameResolver | None = getattr(request.app.state, "hostname_resolver", None)
    if not resolver:
        raise HTTPException(status_code=503, detail="hostname resolver not configured")
    resolver.invalidate()
    return {"ok": True}


@app.get("/api/devices/{ip}/queries")
async def api_device_queries(
    ip: str,
    page: int = 1,
    size: int = 75,
    token: str = Depends(require_token),
) -> dict[str, Any]:
    if not _is_valid_ip_or_cidr(ip):
        raise HTTPException(status_code=400, detail="invalid IP/CIDR")
    async with make_user_client(token) as client:
        data = await client.query_logs(page_number=page, entries_per_page=size, client_ip=ip)
    entries = data.get("entries") or []
    total = data.get("totalEntries", len(entries))
    blocked = sum(1 for e in entries if (e.get("rcode") == "NxDomain"
                                          or "blocking" in (e.get("dnsServerResponse") or "").lower()))
    return {
        "ip": ip,
        "totalEntries": total,
        "page": data.get("pageNumber", page),
        "totalPages": data.get("totalPages", 1),
        "blockedInPage": blocked,
        "entries": entries,
    }


@app.post("/api/devices/{ip}/identify")
async def api_device_identify(
    ip: str,
    actor: str = Depends(get_actor),
    token: str = Depends(require_token),
) -> dict[str, Any]:
    """Force-refresh the vendor + device-type hint for one device.

    Useful from the device detail panel: gives the user immediate
    feedback without waiting for the daily background pass.

    The gateway / router IP is intentionally not fingerprinted: its
    query log is a mix of forwarded traffic from every other device,
    so any single inferred device-type would be misleading.
    """
    if not _is_valid_ip_or_cidr(ip):
        raise HTTPException(status_code=400, detail="invalid IP/CIDR")
    stored = store.get_device(ip) or {}
    mac = stored.get("mac_address")
    gateway_ip = store.get_setting("router.asus.host") or ""
    if ip in {"127.0.0.1", "::1", gateway_ip}:
        # Stamp vendor only (if any) and bail; no domain-pattern hint.
        vendor = oui.vendor_for(mac) if mac else None
        store.set_device_fingerprint(ip, vendor=vendor, hint=None)
        return {
            "ip": ip, "macAddress": mac,
            "vendor": vendor, "fingerprintHint": None,
            "skipped": "gateway",
        }
    async with make_user_client(token) as client:
        result = await fp.identify_device(ip, mac=mac, technitium=client)
    store.set_device_fingerprint(
        ip,
        vendor=result.get("vendor"),
        hint=result.get("hint"),
    )
    store.log_audit(
        actor=actor, ip=ip, action="identify",
        detail=f"vendor={result.get('vendor') or '?'} hint={result.get('hint') or '?'}",
    )
    return {
        "ip": ip,
        "macAddress": mac,
        "vendor": result.get("vendor"),
        "fingerprintHint": result.get("hint"),
    }


@app.get("/api/oui/status")
async def api_oui_status(_token: str = Depends(require_token)) -> dict[str, Any]:
    """Diagnostic: confirm the OUI registry is loaded."""
    oui._ensure_loaded()  # type: ignore[attr-defined]
    return {
        "loaded": oui.is_loaded(),
        "entries": len(oui._OUI_MAP or {}),  # type: ignore[attr-defined]
    }


@app.get("/api/devices/{ip}/diagnose")
async def api_device_diagnose(
    ip: str,
    token: str = Depends(require_token),
) -> dict[str, Any]:
    """Health-check a device's profile enforcement.

    Reports the live group mapping in Technitium, recent query stats from the
    Sqlite Query Logs app, and a human-readable verdict. Used by the dashboard
    "Diagnose" panel so a parent can confirm "yes, the rule is firing" or
    "the device hasn't asked DNS yet, try a fresh test".
    """
    if not _is_valid_ip_or_cidr(ip):
        raise HTTPException(status_code=400, detail="invalid IP/CIDR")

    device = store.get_device(ip)
    base_profile_id = device.get("base_profile_id") if device else None
    person_id = device.get("person_id") if device else None

    person_base = None
    if person_id:
        person = store.get_person(person_id)
        if person:
            person_base = person.get("base_profile_id")

    # Look up the live mapping in Technitium so we know exactly which group is
    # currently in force from the DNS server's perspective. Also pull recent
    # queries for this IP. Reuse a single client for both.
    live_group = None
    async with make_user_client(token) as client:
        try:
            ngm = await get_network_group_map(client)
            live_group = ngm.get(ip)
        except Exception:  # pragma: no cover - network errors aren't fatal here
            live_group = None
        page1 = await client.query_logs(
            page_number=1, entries_per_page=200, client_ip=ip
        )
    entries = page1.get("entries") or []

    total = len(entries)
    blocked = sum(1 for e in entries if e.get("responseType") == "Blocked")
    cached = sum(1 for e in entries if e.get("responseType") == "Cached")
    recursive = sum(1 for e in entries if e.get("responseType") == "Recursive")

    last_seen = entries[0].get("timestamp") if entries else None

    # Pick the profile whose verdict we should evaluate. Manual overrides win,
    # but here we use the simplest signal -- the live group Technitium has.
    effective_profile_id = live_group or base_profile_id or person_base
    expected_patterns = profiles.EXPECTED_BLOCK_PATTERNS.get(effective_profile_id or "", [])

    matching_blocked = []
    matching_allowed = []
    for e in entries:
        qname = (e.get("qname") or "").lower()
        if not any(p in qname for p in expected_patterns):
            continue
        if e.get("responseType") == "Blocked":
            matching_blocked.append(e)
        else:
            matching_allowed.append(e)

    # Recent blocked across all categories (useful UX even when no profile).
    recent_blocked_qnames = []
    seen = set()
    for e in entries:
        if e.get("responseType") != "Blocked":
            continue
        q = e.get("qname")
        if not q or q in seen:
            continue
        seen.add(q)
        recent_blocked_qnames.append({"qname": q, "ts": e.get("timestamp")})
        if len(recent_blocked_qnames) >= 10:
            break

    # Optional: router-enforcement state for internet-off devices.
    router_state: dict[str, Any] | None = None
    if effective_profile_id == "internet-off":
        rc = build_router_client()
        if rc is not None:
            try:
                async with rc:
                    blocked_macs = {m.lower() for m in await rc.get_blocked_macs()}
                stored_mac = (device or {}).get("mac_address")
                if stored_mac:
                    router_state = {
                        "configured": True,
                        "deviceMac": stored_mac,
                        "blockedAtRouter": stored_mac.lower() in blocked_macs,
                    }
                else:
                    router_state = {
                        "configured": True,
                        "deviceMac": None,
                        "blockedAtRouter": False,
                        "note": "MAC not learned yet — wait for next reconcile tick.",
                    }
            except AsusRouterError as exc:
                router_state = {"configured": True, "error": str(exc)}
        else:
            router_state = {"configured": False}

    # Verdict logic.
    if not effective_profile_id or effective_profile_id == "unrestricted":
        verdict = {
            "status": "no-rules",
            "title": "No rules apply",
            "detail": "This device isn't on any content profile, so nothing's being blocked by us.",
        }
    elif effective_profile_id == "internet-off":
        if router_state and router_state.get("blockedAtRouter"):
            verdict = {
                "status": "active",
                "title": "Internet off — enforced at router",
                "detail": "The router has cut this device off at the firewall (MAC-based). DoH or hardcoded DNS can't bypass this.",
            }
        elif total == 0:
            verdict = {
                "status": "active",
                "title": "Internet off and quiet",
                "detail": "Device is offline or its DNS cache is still serving cached IPs. Toggle Wi-Fi on the device to clear the cache.",
            }
        elif blocked > 0:
            verdict = {
                "status": "active",
                "title": "Internet off is firing",
                "detail": f"{blocked} of the last {total} queries have been blocked. Cached responses may keep serving briefly.",
            }
        else:
            verdict = {
                "status": "warning",
                "title": "Profile applied but blocks not seen",
                "detail": "Queries are flowing but none are being blocked yet. The kill-switch matches everything; if you don't see blocks within ~30s, the device may be using a hardcoded resolver or a long-lived TLS connection.",
            }
    elif total == 0:
        verdict = {
            "status": "untested",
            "title": "No queries seen yet",
            "detail": "We haven't received any DNS queries from this device since the rule was applied. Try opening the relevant app on the device — if it's been running with cached IPs, force-quit the app first.",
        }
    elif matching_blocked:
        verdict = {
            "status": "active",
            "title": "Rule is firing",
            "detail": f"Blocked {len(matching_blocked)} relevant query/queries (e.g. {matching_blocked[0].get('qname')}). The profile is working as designed.",
        }
    elif matching_allowed:
        verdict = {
            "status": "warning",
            "title": "Possible bypass",
            "detail": f"This device successfully resolved {matching_allowed[0].get('qname')} while the profile is active. The rule is in place but the response was {matching_allowed[0].get('responseType')} — check the device for hardcoded DNS or DoH.",
        }
    else:
        verdict = {
            "status": "untested-category",
            "title": "Rule is in place — not yet exercised",
            "detail": "The profile is active for this device (other domains have been blocked), but the relevant category hasn't been requested since the rule was applied. Force-quit the target app and try again to clear the device's DNS cache.",
        }

    return {
        "ip": ip,
        "label": (device or {}).get("label"),
        "personId": person_id,
        "baseProfileId": base_profile_id,
        "liveProfileId": live_group,
        "effectiveProfileId": effective_profile_id,
        "expectedBlockPatterns": expected_patterns,
        "summary": {
            "totalRecent": total,
            "blocked": blocked,
            "cached": cached,
            "recursive": recursive,
            "lastSeen": last_seen,
        },
        "matching": {
            "blocked": [
                {"qname": e.get("qname"), "ts": e.get("timestamp"),
                 "rcode": e.get("rcode")}
                for e in matching_blocked[:10]
            ],
            "allowed": [
                {"qname": e.get("qname"), "ts": e.get("timestamp"),
                 "responseType": e.get("responseType")}
                for e in matching_allowed[:10]
            ],
        },
        "recentBlocked": recent_blocked_qnames,
        "verdict": verdict,
        "router": router_state,
    }


# ---- routes: people ---------------------------------------------------------

class PersonCreate(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    avatar: str | None = Field(default=None, max_length=10)  # emoji or single char
    color: str | None = Field(default=None, max_length=20)
    baseProfileId: str | None = None


class PersonUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=40)
    avatar: str | None = Field(default=None, max_length=10)
    color: str | None = Field(default=None, max_length=20)
    baseProfileId: str | None = None
    sortOrder: int | None = None


def _person_dto(p: dict) -> dict[str, Any]:
    return {
        "id": p["id"],
        "name": p["name"],
        "avatar": p["avatar"],
        "color": p["color"],
        "baseProfileId": p["base_profile_id"],
        "sortOrder": p["sort_order"],
    }


@app.get("/api/people")
async def api_list_people(_token: str = Depends(require_token)) -> dict[str, Any]:
    return {"people": [_person_dto(p) for p in store.all_people()]}


@app.post("/api/people")
async def api_create_person(
    payload: PersonCreate,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if payload.baseProfileId and payload.baseProfileId not in profiles.PROFILES:
        raise HTTPException(status_code=400, detail="unknown profile")
    p = store.create_person(name=payload.name.strip(),
                              avatar=payload.avatar,
                              color=payload.color,
                              base_profile_id=payload.baseProfileId)
    store.log_audit(actor=actor, ip=None, action="create-person", detail=p["name"])
    await _kick_reconcile()
    return {"ok": True, "person": _person_dto(p)}


@app.patch("/api/people/{person_id}")
async def api_update_person(
    person_id: int,
    payload: PersonUpdate,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if payload.baseProfileId and payload.baseProfileId not in profiles.PROFILES:
        raise HTTPException(status_code=400, detail="unknown profile")
    fields = {}
    if payload.name is not None:        fields["name"] = payload.name.strip()
    if payload.avatar is not None:      fields["avatar"] = payload.avatar
    if payload.color is not None:       fields["color"] = payload.color
    if payload.baseProfileId is not None or "baseProfileId" in payload.model_fields_set:
        fields["base_profile_id"] = payload.baseProfileId
    if payload.sortOrder is not None:   fields["sort_order"] = payload.sortOrder
    p = store.update_person(person_id, **fields)
    if p is None:
        raise HTTPException(status_code=404, detail="person not found")
    store.log_audit(actor=actor, ip=None, action="update-person",
                     detail=f"{person_id}: {fields}")
    await _kick_reconcile()
    return {"ok": True, "person": _person_dto(p)}


@app.delete("/api/people/{person_id}")
async def api_delete_person(
    person_id: int,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if store.get_person(person_id) is None:
        raise HTTPException(status_code=404, detail="person not found")
    store.delete_person(person_id)
    store.log_audit(actor=actor, ip=None, action="delete-person", detail=str(person_id))
    await _kick_reconcile()
    return {"ok": True}


@app.post("/api/people/{person_id}/pause")
async def api_pause_person(
    person_id: int,
    payload: PausePayload,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if store.get_person(person_id) is None:
        raise HTTPException(status_code=404, detail="person not found")
    if payload.profileId and payload.profileId not in profiles.PROFILES:
        raise HTTPException(status_code=400, detail="unknown profile")
    now = int(time.time())
    expires = now + payload.minutes * 60
    store.add_override(target_kind="person", target_id=str(person_id),
                        profile_id=payload.profileId, source="manual",
                        starts_at=now, expires_at=expires,
                        created_by=actor, note=payload.note)
    store.log_audit(actor=actor, ip=None, action="pause-person",
                     detail=f"{person_id}: {payload.minutes}m")
    await _kick_reconcile()
    return {"ok": True, "personId": person_id, "expiresAt": expires}


@app.post("/api/people/{person_id}/resume")
async def api_resume_person(
    person_id: int,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    cleared = store.clear_overrides(target_kind="person", target_id=str(person_id),
                                      sources=["manual"])
    store.log_audit(actor=actor, ip=None, action="resume-person", detail=str(person_id))
    await _kick_reconcile()
    return {"ok": True, "personId": person_id, "cleared": cleared}


# ---- routes: schedules ------------------------------------------------------

class ScheduleCreate(BaseModel):
    targetKind: str = Field(pattern="^(device|person|all)$")
    targetId: str | None = None
    name: str | None = Field(default=None, max_length=40)
    weekdayMask: int = Field(ge=0, le=0x7F)
    startMin: int = Field(ge=0, le=1440)
    endMin: int = Field(ge=0, le=1440)
    profileId: str | None = None
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    name: str | None = None
    weekdayMask: int | None = Field(default=None, ge=0, le=0x7F)
    startMin: int | None = Field(default=None, ge=0, le=1440)
    endMin: int | None = Field(default=None, ge=0, le=1440)
    profileId: str | None = None
    enabled: bool | None = None


@app.get("/api/schedules")
async def api_list_schedules(_token: str = Depends(require_token)) -> dict[str, Any]:
    return {"schedules": [_schedule_dto(s) for s in store.all_schedules()]}


@app.post("/api/schedules")
async def api_create_schedule(
    payload: ScheduleCreate,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if payload.targetKind != "all" and not payload.targetId:
        raise HTTPException(status_code=400, detail="targetId required")
    if payload.profileId and payload.profileId not in profiles.PROFILES:
        raise HTTPException(status_code=400, detail="unknown profile")
    s = store.create_schedule(
        target_kind=payload.targetKind, target_id=payload.targetId,
        name=payload.name, weekday_mask=payload.weekdayMask,
        start_min=payload.startMin, end_min=payload.endMin,
        profile_id=payload.profileId, enabled=payload.enabled,
    )
    store.log_audit(actor=actor, ip=None, action="create-schedule", detail=str(s["id"]))
    await _kick_reconcile()
    return {"ok": True, "schedule": _schedule_dto(s)}


@app.patch("/api/schedules/{schedule_id}")
async def api_update_schedule(
    schedule_id: int,
    payload: ScheduleUpdate,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if payload.profileId and payload.profileId not in profiles.PROFILES:
        raise HTTPException(status_code=400, detail="unknown profile")
    fields: dict[str, Any] = {}
    if payload.name is not None:         fields["name"] = payload.name
    if payload.weekdayMask is not None:  fields["weekday_mask"] = payload.weekdayMask
    if payload.startMin is not None:     fields["start_min"] = payload.startMin
    if payload.endMin is not None:       fields["end_min"] = payload.endMin
    if payload.enabled is not None:      fields["enabled"] = payload.enabled
    if "profileId" in payload.model_fields_set:
        fields["profile_id"] = payload.profileId
    s = store.update_schedule(schedule_id, **fields)
    if s is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    store.log_audit(actor=actor, ip=None, action="update-schedule", detail=str(schedule_id))
    await _kick_reconcile()
    return {"ok": True, "schedule": _schedule_dto(s)}


@app.delete("/api/schedules/{schedule_id}")
async def api_delete_schedule(
    schedule_id: int,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    store.delete_schedule(schedule_id)
    store.log_audit(actor=actor, ip=None, action="delete-schedule", detail=str(schedule_id))
    await _kick_reconcile()
    return {"ok": True}


# ---- routes: quotas ---------------------------------------------------------

class QuotaCreate(BaseModel):
    targetKind: str = Field(pattern="^(device|person)$")
    targetId: str
    name: str | None = Field(default=None, max_length=40)
    weekdayMask: int = Field(ge=0, le=0x7F)
    minutesMax: int = Field(ge=1, le=24 * 60)
    profileWhenExceeded: str | None = None
    enabled: bool = True


class QuotaUpdate(BaseModel):
    name: str | None = None
    weekdayMask: int | None = Field(default=None, ge=0, le=0x7F)
    minutesMax: int | None = Field(default=None, ge=1, le=24 * 60)
    profileWhenExceeded: str | None = None
    enabled: bool | None = None


@app.get("/api/quotas")
async def api_list_quotas(_token: str = Depends(require_token)) -> dict[str, Any]:
    return {"quotas": [_quota_dto(q) for q in store.all_quotas()]}


@app.post("/api/quotas")
async def api_create_quota(
    payload: QuotaCreate,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if payload.profileWhenExceeded and payload.profileWhenExceeded not in profiles.PROFILES:
        raise HTTPException(status_code=400, detail="unknown profile")
    q = store.create_quota(
        target_kind=payload.targetKind, target_id=payload.targetId,
        name=payload.name, weekday_mask=payload.weekdayMask,
        minutes_max=payload.minutesMax,
        profile_when_exceeded=payload.profileWhenExceeded, enabled=payload.enabled,
    )
    store.log_audit(actor=actor, ip=None, action="create-quota", detail=str(q["id"]))
    await _kick_reconcile()
    return {"ok": True, "quota": _quota_dto(q)}


@app.patch("/api/quotas/{quota_id}")
async def api_update_quota(
    quota_id: int,
    payload: QuotaUpdate,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if payload.profileWhenExceeded and payload.profileWhenExceeded not in profiles.PROFILES:
        raise HTTPException(status_code=400, detail="unknown profile")
    fields: dict[str, Any] = {}
    if payload.name is not None:         fields["name"] = payload.name
    if payload.weekdayMask is not None:  fields["weekday_mask"] = payload.weekdayMask
    if payload.minutesMax is not None:   fields["minutes_max"] = payload.minutesMax
    if payload.enabled is not None:      fields["enabled"] = payload.enabled
    if "profileWhenExceeded" in payload.model_fields_set:
        fields["profile_when_exceeded"] = payload.profileWhenExceeded
    q = store.update_quota(quota_id, **fields)
    if q is None:
        raise HTTPException(status_code=404, detail="quota not found")
    store.log_audit(actor=actor, ip=None, action="update-quota", detail=str(quota_id))
    await _kick_reconcile()
    return {"ok": True, "quota": _quota_dto(q)}


@app.delete("/api/quotas/{quota_id}")
async def api_delete_quota(
    quota_id: int,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    store.delete_quota(quota_id)
    store.log_audit(actor=actor, ip=None, action="delete-quota", detail=str(quota_id))
    await _kick_reconcile()
    return {"ok": True}


# ---- routes: family-pause ---------------------------------------------------

class FamilyPausePayload(BaseModel):
    minutes: int = Field(default=60, ge=1, le=24 * 60)
    profileId: str | None = None
    excludeIps: list[str] = Field(default_factory=list)
    excludePersonIds: list[int] = Field(default_factory=list)
    # When False (the default), devices that aren't assigned to any person
    # are LEFT ALONE -- this protects servers, NAS, home automation, the
    # dashboard's own LXC, etc., which otherwise get caught by "Pause for
    # dinner" with no easy way to whitelist them. Power users who want a
    # whole-network kill can flip this to True.
    includeUnassigned: bool = False
    note: str | None = Field(default=None, max_length=200)


@app.post("/api/family/pause")
async def api_family_pause(
    payload: FamilyPausePayload,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    if payload.profileId and payload.profileId not in profiles.PROFILES:
        raise HTTPException(status_code=400, detail="unknown profile")
    now = int(time.time())
    expires = now + payload.minutes * 60
    note = payload.note or "family pause"

    # Implementation: create one "family-pause" override per non-excluded
    # device. We don't use target=all because we want clean exclusion
    # semantics (per-person skip, per-IP skip, and "leave unassigned
    # devices alone" all compose cleanly when each device row decides
    # for itself whether to stamp an override).
    excluded_ips = set(payload.excludeIps)
    excluded_persons = set(payload.excludePersonIds)
    affected = 0
    skipped_unassigned = 0
    for d in store.all_devices():
        ip = d["ip"]
        if not _is_valid_ip_or_cidr(ip):
            continue
        if ip in excluded_ips:
            continue
        if d.get("person_id") in excluded_persons:
            continue
        if d.get("person_id") is None and not payload.includeUnassigned:
            skipped_unassigned += 1
            continue
        store.add_override(target_kind="device", target_id=ip,
                            profile_id=payload.profileId, source="family-pause",
                            starts_at=now, expires_at=expires,
                            created_by=actor, note=note)
        affected += 1

    audit_detail = f"{payload.minutes}m, {affected} devices"
    if skipped_unassigned:
        audit_detail += f", skipped {skipped_unassigned} unassigned"
    if payload.includeUnassigned:
        audit_detail += ", incl. unassigned"
    store.log_audit(actor=actor, ip=None, action="family-pause",
                     detail=audit_detail)
    await _kick_reconcile()
    return {
        "ok": True,
        "affected": affected,
        "skippedUnassigned": skipped_unassigned,
        "expiresAt": expires,
    }


@app.post("/api/family/resume")
async def api_family_resume(
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    cleared = 0
    for d in store.all_devices():
        cleared += store.clear_overrides(target_kind="device", target_id=d["ip"],
                                            sources=["family-pause"])
    store.log_audit(actor=actor, ip=None, action="family-resume", detail=str(cleared))
    await _kick_reconcile()
    return {"ok": True, "cleared": cleared}


# ---- routes: misc -----------------------------------------------------------

# ---- routes: settings (router) ---------------------------------------------

VALID_VENDORS = {"asus", "unifi", "none"}


class UnifiSettingsPayload(BaseModel):
    """UniFi-specific fields. Mirrors the ASUS top-level fields but
    kept under its own object so the two vendor configs don't collide.
    """
    host: str | None = None
    username: str | None = None
    password: str | None = None     # write-only; null=leave, ""=clear
    site: str | None = None
    apiKey: str | None = None       # write-only; null=leave, ""=clear
    verifyTls: bool | None = None
    dohBlockEnabled: bool | None = None


class RouterSettingsPayload(BaseModel):
    # Vendor selector: which adapter runs in the reconciler.
    vendor: str | None = Field(default=None, pattern=r"^(asus|unifi|none)$")
    # ASUS fields stay at the top level for backwards compatibility
    # with older frontends that don't know about the multi-vendor split.
    host: str | None = None
    username: str | None = None
    password: str | None = None  # write-only; null = leave unchanged, "" = clear
    scheme: str | None = Field(default=None, pattern=r"^(http|https)$")
    port: int | None = Field(default=None, ge=1, le=65535)
    enabled: bool | None = None
    # Stage 2 -- DNS Director
    dnsDirectorEnabled: bool | None = None
    dnsDirectorIp: str | None = None
    # Stage 3 -- SSH + DoH blocklist
    sshEnabled: bool | None = None
    sshPort: int | None = Field(default=None, ge=1, le=65535)
    sshPassword: str | None = None  # null = unchanged, "" = clear
    dohBlockEnabled: bool | None = None
    # UniFi nested object.
    unifi: UnifiSettingsPayload | None = None


def _public_unifi_settings() -> dict[str, Any]:
    return {
        "host": store.get_setting(UNIFI_KEYS["host"]),
        "username": store.get_setting(UNIFI_KEYS["username"]),
        "site": store.get_setting(UNIFI_KEYS["site"]) or "default",
        "verifyTls": store.get_setting(UNIFI_KEYS["verify_tls"]) == "1",
        "passwordSet": bool(secrets.get(UNIFI_KEYS["password"])),
        "apiKeySet": bool(secrets.get(UNIFI_KEYS["api_key"])),
        "dohBlockEnabled": store.get_setting(UNIFI_KEYS["doh_block_enabled"]) == "1",
    }


def _public_capabilities() -> dict[str, Any] | None:
    """Capabilities of the *currently configured* router adapter.

    Returns ``None`` when no router is configured (``router.vendor =
    none`` or unset and ASUS host isn't set). The UI uses this to grey
    out per-stage toggles the active vendor doesn't support.
    """
    adapter = get_router_adapter(store, secrets)
    if adapter is None:
        return None
    caps = adapter.capabilities
    return {
        "vendor": adapter.vendor,
        "supportsKillSwitch":  caps.supports_kill_switch,
        "supportsDnsDirector": caps.supports_dns_director,
        "supportsDohBlocking": caps.supports_doh_blocking,
        "needsSshForDoh":      caps.needs_ssh_for_doh,
    }


def _public_router_settings() -> dict[str, Any]:
    cfg = _router_settings()
    saved_vendor = store.get_setting(VENDOR_SETTING_KEY)
    # The registry auto-migrates legacy ASUS installs; mirror that here
    # so a fresh GET right after upgrade shows the inferred vendor.
    if not saved_vendor and cfg["host"]:
        saved_vendor = "asus"
    return {
        "vendor": saved_vendor or "none",
        "capabilities": _public_capabilities(),
        "host": cfg["host"],
        "username": cfg["username"],
        "scheme": cfg["scheme"],
        "port": int(cfg["port"]) if cfg["port"] and cfg["port"].isdigit() else None,
        "enabled": bool(cfg["enabled"]),
        "passwordSet": bool(secrets.get(ROUTER_KEYS["password"])),
        # Stage 2
        "dnsDirectorEnabled": bool(cfg["dns_director_enabled"]),
        "dnsDirectorIp": cfg["dns_director_ip"],
        # Stage 3
        "sshEnabled": bool(cfg["ssh_enabled"]),
        "sshPort": int(cfg["ssh_port"]) if cfg["ssh_port"] and cfg["ssh_port"].isdigit() else None,
        "sshPasswordSet": bool(secrets.get(ROUTER_KEYS["ssh_password"])),
        "dohBlockEnabled": bool(cfg["doh_block_enabled"]),
        # UniFi block.
        "unifi": _public_unifi_settings(),
    }


@app.get("/api/settings/router")
async def api_router_get(_: str = Depends(require_token)) -> dict[str, Any]:
    return {"router": _public_router_settings()}


@app.put("/api/settings/router")
async def api_router_put(
    payload: RouterSettingsPayload,
    actor: str = Depends(get_actor),
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    # Vendor selector. "none" is persisted as an explicit opt-out
    # rather than deleting the row -- otherwise the registry's
    # legacy-ASUS auto-detect would silently re-promote a user who
    # picked "None" back to "asus" on the very next tick.
    if payload.vendor is not None:
        store.set_setting(VENDOR_SETTING_KEY, payload.vendor)
    if payload.host is not None:
        host = payload.host.strip()
        store.set_setting(ROUTER_KEYS["host"], host or None)
    if payload.username is not None:
        store.set_setting(ROUTER_KEYS["username"], payload.username.strip() or None)
    if payload.password is not None:
        # "" explicitly clears, anything else replaces.
        secrets.set(ROUTER_KEYS["password"], payload.password if payload.password else None)
    if payload.scheme is not None:
        store.set_setting(ROUTER_KEYS["scheme"], payload.scheme)
    if payload.port is not None:
        store.set_setting(ROUTER_KEYS["port"], str(payload.port))
    if payload.enabled is not None:
        store.set_setting(ROUTER_KEYS["enabled"], "1" if payload.enabled else "0")
    if payload.dnsDirectorEnabled is not None:
        store.set_setting(ROUTER_KEYS["dns_director_enabled"],
                          "1" if payload.dnsDirectorEnabled else "0")
    if payload.dnsDirectorIp is not None:
        ip = payload.dnsDirectorIp.strip()
        if ip and not _is_valid_ip_or_cidr(ip):
            raise HTTPException(status_code=400, detail="dnsDirectorIp is not a valid IP")
        store.set_setting(ROUTER_KEYS["dns_director_ip"], ip or None)
    if payload.sshEnabled is not None:
        store.set_setting(ROUTER_KEYS["ssh_enabled"],
                          "1" if payload.sshEnabled else "0")
    if payload.sshPort is not None:
        store.set_setting(ROUTER_KEYS["ssh_port"], str(payload.sshPort))
    if payload.sshPassword is not None:
        secrets.set(ROUTER_KEYS["ssh_password"],
                     payload.sshPassword if payload.sshPassword else None)
    if payload.dohBlockEnabled is not None:
        store.set_setting(ROUTER_KEYS["doh_block_enabled"],
                          "1" if payload.dohBlockEnabled else "0")

    # UniFi nested fields.
    if payload.unifi is not None:
        u = payload.unifi
        if u.host is not None:
            store.set_setting(UNIFI_KEYS["host"], u.host.strip() or None)
        if u.username is not None:
            store.set_setting(UNIFI_KEYS["username"], u.username.strip() or None)
        if u.password is not None:
            secrets.set(UNIFI_KEYS["password"], u.password if u.password else None)
        if u.site is not None:
            store.set_setting(UNIFI_KEYS["site"], u.site.strip() or None)
        if u.apiKey is not None:
            secrets.set(UNIFI_KEYS["api_key"], u.apiKey if u.apiKey else None)
        if u.verifyTls is not None:
            store.set_setting(UNIFI_KEYS["verify_tls"], "1" if u.verifyTls else "0")
        if u.dohBlockEnabled is not None:
            store.set_setting(UNIFI_KEYS["doh_block_enabled"],
                              "1" if u.dohBlockEnabled else "0")

    # Audit. Hide password fields from the JSON dump.
    redacted = payload.model_dump()
    redacted.pop("password", None)
    if isinstance(redacted.get("unifi"), dict):
        redacted["unifi"].pop("password", None)
        redacted["unifi"].pop("apiKey", None)
    store.log_audit(actor=actor, ip=None, action="router.settings",
                     detail=json.dumps({
                         k: v for k, v in redacted.items()
                         if v is not None
                     }))
    # Push reconcile so the next tick honours new settings (or stops
    # honouring old ones, if disabled).
    asyncio.create_task(_kick_reconcile())
    return {"router": _public_router_settings()}


@app.get("/api/router/capabilities")
async def api_router_capabilities(
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    """Capabilities of the currently configured adapter (or ``null``).

    The Settings UI uses this to enable/disable per-stage toggles so
    users only see options their hardware actually supports. The
    response is intentionally tiny -- no creds, no live state.
    """
    return {"capabilities": _public_capabilities()}


@app.post("/api/settings/router/test")
async def api_router_test(
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    """Probe the configured router with a connect-and-list round-trip.

    Dispatches by ``router.vendor`` so the UI's "Test connection"
    button always probes the active adapter. For ASUS this also
    auto-persists the working scheme/port the user can't necessarily
    know up-front.
    """
    vendor = (store.get_setting(VENDOR_SETTING_KEY) or "").strip().lower()
    if not vendor:
        # Legacy: infer ASUS when an ASUS host is set but the vendor
        # selector hasn't been clicked yet.
        if store.get_setting(ROUTER_KEYS["host"]):
            vendor = "asus"
        else:
            raise HTTPException(
                status_code=400,
                detail="no router vendor selected. Pick ASUS or UniFi in Settings first.",
            )

    if vendor == "asus":
        return await _test_router_asus()
    if vendor == "unifi":
        return await _test_router_unifi()
    raise HTTPException(status_code=400, detail=f"unknown vendor: {vendor!r}")


async def _test_router_asus() -> dict[str, Any]:
    cfg = _router_settings()
    if not (cfg["host"] and cfg["username"]):
        raise HTTPException(status_code=400, detail="host and username are required")
    pw = secrets.get(ROUTER_KEYS["password"])
    if not pw:
        raise HTTPException(status_code=400, detail="router password not saved")
    port_raw = cfg["port"]
    port = int(port_raw) if port_raw and port_raw.isdigit() else None
    preferred = (cfg["scheme"] or "http", port)

    try:
        result = await detect_router_endpoint(
            cfg["host"], cfg["username"], pw, preferred=preferred,
        )
    except AsusRouterError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    # Persist the working scheme/port so the rest of the dashboard (the
    # reconciler especially) uses the right endpoint without the user
    # having to re-enter anything.
    detected_scheme = result["scheme"]
    detected_port = result["port"]
    if detected_scheme != (cfg["scheme"] or "http"):
        store.set_setting(ROUTER_KEYS["scheme"], detected_scheme)
    if str(detected_port) != (cfg["port"] or ""):
        store.set_setting(ROUTER_KEYS["port"], str(detected_port))
    return {
        "ok": True,
        "vendor": "asus",
        "info": result["info"],
        "detected": {"scheme": detected_scheme, "port": detected_port},
    }


async def _test_router_unifi() -> dict[str, Any]:
    host = store.get_setting(UNIFI_KEYS["host"])
    username = store.get_setting(UNIFI_KEYS["username"])
    password = secrets.get(UNIFI_KEYS["password"])
    if not (host and username):
        raise HTTPException(status_code=400, detail="UniFi host and username are required")
    if not password:
        raise HTTPException(status_code=400, detail="UniFi password not saved")
    site = store.get_setting(UNIFI_KEYS["site"]) or "default"
    verify_tls = store.get_setting(UNIFI_KEYS["verify_tls"]) == "1"

    try:
        async with UnifiLegacyApi(
            host=host, username=username, password=password,
            site=site, verify_tls=verify_tls,
        ) as api:
            sites = await api.list_sites()
            clients = await api.list_clients()
            rules = await api.list_traffic_rules()
            flavour = api.flavour
    except UnifiAuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except UnifiError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None

    return {
        "ok": True,
        "vendor": "unifi",
        "info": {
            "flavour": flavour,
            "site": site,
            "sitesCount": len(sites),
            "clientsCount": len(clients),
            "trafficRulesCount": len(rules),
        },
    }


@app.get("/api/settings/router/clients")
async def api_router_clients(
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    """Return the router's known clients for the Settings UI preview."""
    rc = build_router_client()
    if rc is None:
        raise HTTPException(status_code=400, detail="router not configured/enabled")
    try:
        async with rc:
            clients = await rc.list_clients()
            blocked = await rc.get_blocked_macs()
    except AsusRouterError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
    return {
        "clients": [
            {
                "mac": c.mac, "ip": c.ip, "name": c.name, "online": c.online,
                "blocked": c.mac in set(blocked),
            }
            for c in clients
        ],
        "blocked": blocked,
    }


# ---- routes: router SSH (Stage 3) -------------------------------------------

@app.post("/api/settings/router/ssh/test")
async def api_router_ssh_test(
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    """Open an SSH session to the router and return basic capability info."""
    cfg = build_ssh_config()
    if cfg is None:
        raise HTTPException(
            status_code=400,
            detail="SSH not configured. Save router credentials and tick "
                   "'Enable SSH' first.",
        )
    try:
        async with AsusSshClient(cfg) as ssh:
            status = await ssh.gather_status()
            has_xt_set = await ssh.has_iptables_match_set()
    except AsusSshError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
    return {
        "ok": True,
        "host": cfg.host,
        "port": cfg.port,
        "router": status,
        "iptablesMatchSet": has_xt_set,
    }


@app.post("/api/settings/router/apply-now")
async def api_router_apply_now(
    request: Request,
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    """Force a reconcile tick and return the result.

    Useful from the Settings page so the user gets immediate feedback
    rather than waiting up to 60s for the next tick.
    """
    rec: Reconciler | None = getattr(request.app.state, "reconciler", None)
    if rec is None:
        raise HTTPException(status_code=503, detail="reconciler not running")
    status = await rec.tick()
    return {"ok": True, "status": status}


# ---- routes: audit ----------------------------------------------------------

@app.get("/api/audit")
async def api_audit(_: str = Depends(require_token)) -> dict[str, Any]:
    return {"entries": store.recent_audit(limit=100)}


@app.get("/api/health")
async def api_health() -> dict[str, Any]:
    return {"ok": True, "service": "dns-dashboard"}


@app.get("/api/diagnostics/reconcile")
async def api_diagnostics_reconcile(
    request: Request,
    _token: str = Depends(require_token),
) -> dict[str, Any]:
    rec: Reconciler | None = getattr(request.app.state, "reconciler", None)
    if rec is None:
        return {"enabled": False}
    status = await rec.tick()
    return {"enabled": True, "status": status}


# ---- static frontend --------------------------------------------------------

@app.get("/login")
async def login_page() -> FileResponse:
    return FileResponse(WEB_DIR / "login.html")


@app.get("/")
async def root_page(
    dnsdash_token: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> Response:
    if not dnsdash_token:
        return JSONResponse(
            content={"detail": "redirect"},
            status_code=307,
            headers={"Location": "/login"},
        )
    return FileResponse(WEB_DIR / "index.html")


app.mount("/assets", StaticFiles(directory=WEB_DIR), name="assets")


# ---- entrypoint -------------------------------------------------------------

def main() -> None:
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    uvicorn.run(
        "server.app:app",
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        log_level="info",
        access_log=False,
    )


if __name__ == "__main__":
    main()
