"""Async HTTP client for AsusWRT routers (RT-AX/RT-BE family).

The dashboard uses this to:
1. Authenticate to the router web UI and keep a session cookie.
2. Mirror "internet-off" effective profiles into the router's MAC-based
   "Block Internet Access" firewall rule (nvram ``MULTIFILTER_*``).
3. Discover the MAC of every connected client so the dashboard can match
   IPs to MACs even when DHCP records change.

Reverse-engineered surface (stable since AsusWRT 384.x; matches
RT-BE88U firmware as of 2025):

* ``POST /login.cgi``
    body: ``login_authorization=<base64(user:pass)>`` plus a couple of
    boilerplate fields. On success returns ``Set-Cookie: asus_token=...``.

* ``GET  /appGet.cgi?hook=...``
    one-liner JSON queries, e.g.
    ``hook=nvram_get(MULTIFILTER_ENABLE);nvram_get(MULTIFILTER_MAC);...``
    (semicolon-delimited list of nvram_get calls).

* ``POST /start_apply.htm``
    body: ``action_mode=apply&action_script=<service>&<nvram=values>``.
    For the parental-controls block list the canonical service name is
    ``restart_firewall``.

* ``GET  /update_clients.asp``
    returns the live "Network Map" client list, including hostname, MAC,
    IP and RSSI. We normalise this into something the reconciler can
    use.

The client deliberately performs minimal logic: it does what the web UI
does, no more. Higher-level intent ("ensure this MAC is blocked") lives
in the reconciler.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import ssl
from dataclasses import dataclass, field
from typing import Any

import httpx


log = logging.getLogger("dns-dashboard.router-asus")


class AsusRouterError(Exception):
    """Anything the router rejected or replied unexpectedly to."""


@dataclass
class AsusClient:
    mac: str
    ip: str | None
    name: str | None
    online: bool
    raw: dict = field(default_factory=dict)


def _norm_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    return mac.lower().replace("-", ":").strip()


def _explain_http_error(exc: Exception) -> str:
    """Translate httpx exceptions into something a parent-friendly error
    banner can show.

    The ASUS web UI is reachable in *one* of these shapes depending on
    firmware/settings:
      http://router/         (port 80, plain)
      https://router:8443/   (TLS on AsusWRT's default HTTPS port)
      https://router/        (TLS on 443, less common)
    Mismatches produce a few characteristic failures we surface clearly.
    """
    text = str(exc)
    msg = text.lower()
    if "wrong_version_number" in msg or isinstance(exc, ssl.SSLError):
        return ("router answered plain HTTP, but we tried HTTPS. "
                "Try scheme = http (or, if you really want HTTPS, port 8443).")
    if "connection refused" in msg:
        return ("router refused the connection on this port. "
                "Most ASUS routers use http/80 or https/8443.")
    if "timed out" in msg or isinstance(exc, httpx.TimeoutException):
        return ("router didn't answer in time. Check the IP and that the "
                "dashboard host can reach the router (try ping).")
    if "name or service not known" in msg or "nodename nor servname" in msg:
        return "could not resolve the router host name."
    return f"could not reach router: {text}"


class AsusRouterClient:
    """Single-session client. Not thread-safe; one client per worker."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        scheme: str = "http",
        port: int | None = None,
        timeout: float = 8.0,
        verify_tls: bool = False,
    ) -> None:
        self.host = host.strip()
        self.username = username
        self.password = password
        self.scheme = scheme
        self.port = port
        self.timeout = timeout
        self._verify = verify_tls
        self._client: httpx.AsyncClient | None = None
        self._lock = asyncio.Lock()
        self._login_attempted = False

    @property
    def base_url(self) -> str:
        port = self.port or (443 if self.scheme == "https" else 80)
        if (self.scheme == "http" and port == 80) or (self.scheme == "https" and port == 443):
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{port}"

    async def __aenter__(self) -> "AsusRouterClient":
        await self._ensure_client()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                verify=self._verify,
                follow_redirects=False,
                headers={
                    # AsusWRT inspects the Referer / User-Agent loosely.
                    # Mimicking a browser avoids CSRF redirects.
                    "User-Agent": "Mozilla/5.0 (Guardium DNS) httpx",
                    "Referer": self.base_url + "/",
                },
            )
        return self._client

    # ------------------------------------------------------------------ login

    async def login(self) -> None:
        """Authenticate and store the session cookie on the http client."""
        client = await self._ensure_client()
        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        data = {
            "group_id": "",
            "action_mode": "",
            "action_script": "",
            "action_wait": "5",
            "current_page": "Main_Login.asp",
            "next_page": "index.asp",
            "login_authorization": token,
            "login_captcha": "",
        }
        try:
            resp = await client.post("/login.cgi", data=data)
        except (httpx.HTTPError, ssl.SSLError) as exc:
            raise AsusRouterError(_explain_http_error(exc)) from exc

        # AsusWRT replies 200 even on bad creds; the success signal is
        # an `asus_token` cookie *and* a body with `error_status: "0"` or
        # an empty/redirect body.
        cookies = client.cookies
        if "asus_token" not in cookies and "asus_token" not in resp.cookies:
            body = (resp.text or "").strip().lower()
            if "error_status" in body or "captcha" in body or resp.status_code >= 400:
                raise AsusRouterError("login rejected (check username/password)")
            # Some older firmwares hand back the token only in body.
            m = re.search(r"asus_token\s*=\s*['\"]?([A-Za-z0-9_\-]+)", resp.text or "")
            if not m:
                raise AsusRouterError(
                    f"login failed: HTTP {resp.status_code}, no asus_token cookie"
                )
            client.cookies.set("asus_token", m.group(1))

        self._login_attempted = True

    async def _request(
        self, method: str, path: str, *, retry_login: bool = True, **kwargs: Any
    ) -> httpx.Response:
        client = await self._ensure_client()
        if not self._login_attempted:
            await self.login()
        try:
            resp = await client.request(method, path, **kwargs)
        except (httpx.HTTPError, ssl.SSLError) as exc:
            raise AsusRouterError(_explain_http_error(exc)) from exc

        # AsusWRT redirects to Main_Login.asp when the cookie expires.
        if (
            resp.status_code in (301, 302)
            and "login" in (resp.headers.get("location") or "").lower()
        ) or (
            resp.status_code == 200
            and "Main_Login.asp" in (resp.text or "")[:400]
        ):
            if not retry_login:
                raise AsusRouterError("session expired and re-login also rejected")
            log.info("router session expired, re-authenticating")
            self._login_attempted = False
            await self.login()
            return await self._request(method, path, retry_login=False, **kwargs)

        if resp.status_code >= 500:
            raise AsusRouterError(f"router HTTP {resp.status_code}: {resp.text[:200]}")
        return resp

    # ----------------------------------------------------------------- nvram

    async def nvram_get(self, names: list[str]) -> dict[str, str]:
        """Fetch one or more nvram variables in a single HTTP call."""
        if not names:
            return {}
        hooks = ";".join(f"nvram_get({n})" for n in names)
        resp = await self._request("GET", "/appGet.cgi", params={"hook": hooks})
        # appGet returns JSON like {"MULTIFILTER_ENABLE": "1", "MULTIFILTER_MAC": ""}
        try:
            data = resp.json()
        except json.JSONDecodeError as exc:
            raise AsusRouterError(f"nvram_get parse failed: {exc}: {resp.text[:200]}") from exc
        if not isinstance(data, dict):
            raise AsusRouterError(f"unexpected nvram_get reply: {data!r}")
        return {k: ("" if v is None else str(v)) for k, v in data.items()}

    async def apply_nvram(
        self, *, action_script: str, values: dict[str, str], action_wait: int = 1
    ) -> None:
        """Push nvram values and trigger a service restart."""
        body = {
            "action_mode": "apply",
            "action_script": action_script,
            "action_wait": str(action_wait),
            **values,
        }
        resp = await self._request("POST", "/start_apply.htm", data=body)
        if resp.status_code >= 400:
            raise AsusRouterError(f"apply failed: HTTP {resp.status_code}: {resp.text[:200]}")

    # --------------------------------------------------------------- clients

    async def list_clients(self) -> list[AsusClient]:
        """Return the router's known clients with hostname/IP/MAC/online."""
        # The custom_clientlist nvram and the live cliental_list.asp share
        # mostly the same shape. We pull both and merge for completeness.
        nvram = await self.nvram_get(["custom_clientlist"])
        named: dict[str, str] = {}
        raw = nvram.get("custom_clientlist", "") or ""
        # Format: <Name>name>mac>group>type>callback>keeparp>...
        for entry in raw.split("<"):
            if not entry:
                continue
            parts = entry.split(">")
            if len(parts) >= 2:
                name = parts[0].strip()
                mac = _norm_mac(parts[1])
                if mac:
                    named[mac] = name or named.get(mac, "")

        # Live client list (online + IPs)
        live: dict[str, dict] = {}
        try:
            resp = await self._request(
                "GET",
                "/appGet.cgi",
                params={"hook": "get_clientlist()"},
            )
            data = resp.json() if resp.status_code == 200 else {}
        except (httpx.HTTPError, json.JSONDecodeError, AsusRouterError):
            data = {}
        cl = data.get("get_clientlist", {}) if isinstance(data, dict) else {}
        if isinstance(cl, dict):
            mac_order = cl.get("maclist", []) or []
            for mac in mac_order:
                m = _norm_mac(mac)
                if not m:
                    continue
                rec = cl.get(mac) or {}
                if isinstance(rec, dict):
                    live[m] = rec

        # Build merged result.
        out: list[AsusClient] = []
        seen: set[str] = set()
        for mac, rec in live.items():
            seen.add(mac)
            out.append(
                AsusClient(
                    mac=mac,
                    ip=rec.get("ip") or None,
                    name=(rec.get("nickName") or rec.get("name")
                          or named.get(mac) or rec.get("hostname") or None),
                    online=str(rec.get("isOnline", "0")) == "1",
                    raw=rec,
                )
            )
        for mac, name in named.items():
            if mac in seen:
                continue
            out.append(AsusClient(mac=mac, ip=None, name=name or None,
                                   online=False, raw={}))
        return out

    # ------------------------------------------------------ block-internet API

    # ----------------------------------------------------- DNS Director (Stage 2)
    #
    # Per-MAC DNS redirection. Even if the device hardcodes a different
    # resolver in its OS settings, AsusWRT's iptables rules transparently
    # rewrite outbound port 53 traffic from that MAC to the IP we choose
    # (typically the dashboard's own DNS server).
    #
    # NB: this DOES NOT defeat DoH (HTTPS to a hardcoded IP). For that you
    # need Stage 3 (DoH IP blocklist over SSH).
    #
    # nvram surface (verified empirically on RT-BE88U fw 3.0.0.6_102):
    #   dnsfilter_enable_x = '0' off / '1' on
    #   dnsfilter_mode     = '0' = no global override (per-MAC only)
    #   dnsfilter_custom1  = the IP we redirect to
    #   dnsfilter_rulelist = '<DisplayName>MAC>Mode' per entry, "<" between
    #                        entries. Mode 11 = use custom1.

    DNS_MODE_CUSTOM1 = "11"

    async def get_managed_dns_rules(self) -> list[tuple[str, str, str]]:
        """Return the live DNS director rule list as ``[(name, mac, mode)]``.

        Preserves the original casing of the MAC field so we can round-trip
        without mutating user-managed entries.
        """
        snap = await self.nvram_get(["dnsfilter_rulelist"])
        raw = snap.get("dnsfilter_rulelist") or ""
        # The router stores "<" as HTML entity "&#60". When we read via
        # appGet.cgi the HTML escape may already be decoded to a literal "<"
        # depending on firmware. Handle both.
        decoded = raw.replace("&#60", "<").replace("&#62", ">")
        out: list[tuple[str, str, str]] = []
        for entry in decoded.split("<"):
            if not entry:
                continue
            parts = entry.split(">")
            if len(parts) >= 3:
                out.append((parts[0], parts[1], parts[2]))
        return out

    async def apply_managed_dns_director(
        self,
        desired_rules: list[tuple[str, str]],
        *,
        custom_dns_ip: str,
        previously_managed: list[str],
    ) -> dict[str, Any]:
        """Reconcile the router's DNS Director rule list.

        ``desired_rules`` is ``[(display_name, mac), ...]``. Each desired
        entry is forced to use ``custom_dns_ip`` via mode 11.

        Same merge story as MAC blocking: we preserve any rules the user
        added by hand (including their mode choice) and only touch entries
        we previously created.
        """
        prev = {_norm_mac(m) for m in previously_managed if _norm_mac(m)}
        desired_clean: list[tuple[str, str]] = []
        seen: set[str] = set()
        for name, mac in desired_rules:
            m = _norm_mac(mac)
            if not m or m in seen:
                continue
            seen.add(m)
            desired_clean.append((name or m.upper(), m))

        existing = await self.get_managed_dns_rules()
        snap = await self.nvram_get([
            "dnsfilter_enable_x", "dnsfilter_mode",
            "dnsfilter_custom1", "dnsfilter_custom2", "dnsfilter_custom3",
        ])

        merged: list[tuple[str, str, str]] = []
        # 1. Pass through user-managed entries (preserving original casing).
        for name, mac, mode in existing:
            if _norm_mac(mac) in prev:
                continue  # was ours; we'll re-add only desired ones
            merged.append((name, mac, mode))

        # 2. Append our desired entries (skip if user already has the MAC).
        for name, mac in desired_clean:
            if any(_norm_mac(m) == mac for _, m, _ in merged):
                continue
            merged.append((name, mac.upper(), self.DNS_MODE_CUSTOM1))

        rulelist = "".join(f"<{name}>{mac}>{mode}" for name, mac, mode in merged)

        # If we have any rules at all (ours or user's), keep enable on and
        # ensure custom1 holds the IP we want.
        had_any = bool(merged)
        values = {
            "dnsfilter_enable_x": "1" if had_any else "0",
            "dnsfilter_mode": snap.get("dnsfilter_mode") or "0",
            "dnsfilter_custom1": custom_dns_ip if desired_clean
                                  else (snap.get("dnsfilter_custom1") or custom_dns_ip),
            "dnsfilter_custom2": snap.get("dnsfilter_custom2") or "",
            "dnsfilter_custom3": snap.get("dnsfilter_custom3") or "",
            "dnsfilter_rulelist": rulelist,
        }
        await self.apply_nvram(action_script="restart_dnsmasq", values=values)
        return {
            "ours": [m for _, m in desired_clean],
            "preserved_user_rules": [
                _norm_mac(m) for _, m, _ in existing
                if _norm_mac(m) and _norm_mac(m) not in prev
            ],
            "enabled": values["dnsfilter_enable_x"] == "1",
            "custom1": values["dnsfilter_custom1"],
        }

    async def get_blocked_macs(self) -> list[str]:
        """Return every MAC currently in the router's block list.

        On RT-BE family firmware, ``MULTIFILTER_ENABLE`` is `0` (off),
        `1` ("Time Scheduling"), or `2` ("Block Internet Access").
        Either of `1` or `2` mean some entries are active.
        """
        snap = await self.nvram_get([
            "MULTIFILTER_ENABLE", "MULTIFILTER_MAC",
        ])
        if (snap.get("MULTIFILTER_ENABLE") or "0") in ("0", ""):
            return []
        raw = (snap.get("MULTIFILTER_MAC") or "").replace("&#62", ">").replace("&#60", "<")
        macs = raw.split(">")
        return [m for m in (_norm_mac(x) for x in macs) if m]

    async def apply_managed_blocked_macs(
        self,
        desired_macs: list[str],
        *,
        previously_managed: list[str],
        names: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Reconcile the router's "Block Internet Access" list.

        Strategy: read the live ``MULTIFILTER_*`` triples, split them into
        "ours" (in ``previously_managed``) and "theirs" (everything else --
        rules the user added by hand in the router web UI). Drop the "ours"
        entries that are no longer desired, add entries for any new desired
        MACs (with an empty per-device schedule, which the firmware treats
        as "always block"), and write everything back. The user's manual
        rules and their schedules are passed through untouched.

        Empirically verified on RT-BE88U (firmware 3.0.0.6_102 BB0B):
        - ``MULTIFILTER_ENABLE = '2'`` is "Block Internet Access" mode
          (the value the firmware itself writes when the toggle is on).
        - Each variable uses ``>`` to separate per-device entries.
        - An empty per-device entry in ``MULTIFILTER_MACFILTER_DAYTIME_V2``
          is the canonical "no schedule, always block" value.
        """
        # Names dict is keyed however the caller passes it; we normalise to
        # lowercase so the firmware-side display matches the on-device label.
        names_lower: dict[str, str] = {
            _norm_mac(k): v for k, v in (names or {}).items() if _norm_mac(k)
        }  # type: ignore[misc]
        prev_managed = {_norm_mac(m) for m in previously_managed if _norm_mac(m)}
        desired_clean: list[str] = []
        seen: set[str] = set()
        for raw in desired_macs:
            m = _norm_mac(raw)
            if m and m not in seen:
                seen.add(m)
                desired_clean.append(m)
        desired_set = set(desired_clean)

        snap = await self.nvram_get([
            "MULTIFILTER_ENABLE", "MULTIFILTER_ALL", "MULTIFILTER_MAC",
            "MULTIFILTER_DEVICENAME", "MULTIFILTER_MACFILTER_DAYTIME_V2",
            "MULTIFILTER_URL_ENABLE", "MULTIFILTER_URL", "MULTIFILTER_URL_LIST",
        ])

        # Parse the existing triples. AsusWRT pads short fields by silently
        # truncating, so we always pad the three lists to the longest one.
        # NB: ``appGet.cgi`` returns ``>`` HTML-encoded as ``&#62`` (and
        # ``<`` as ``&#60``) on every read after the first write. We must
        # decode both forms before splitting or every tick after the first
        # one accretes garbage instead of round-tripping cleanly.
        def _decode(value: str | None) -> str:
            return (value or "").replace("&#62", ">").replace("&#60", "<")
        macs = [m for m in _decode(snap.get("MULTIFILTER_MAC")).split(">")]
        names_existing = [n for n in _decode(snap.get("MULTIFILTER_DEVICENAME")).split(">")]
        days_existing = [d for d in _decode(snap.get("MULTIFILTER_MACFILTER_DAYTIME_V2")).split(">")]
        # Drop the trailing empty splits that come from a fully empty value.
        if macs == [""]:
            macs = []
            names_existing = []
            days_existing = []
        n = len(macs)
        names_existing += [""] * (n - len(names_existing))
        days_existing  += [""] * (n - len(days_existing))

        merged_macs: list[str] = []
        merged_names: list[str] = []
        merged_days: list[str] = []

        # 1. Pass through every entry the user added (anything not in our
        #    previously-managed set), preserving its name and schedule.
        for i, mac in enumerate(macs):
            normed = _norm_mac(mac)
            if not normed:
                continue
            if normed in prev_managed:
                # Was ours -- skip; we'll re-add only the still-desired ones.
                continue
            merged_macs.append(mac)  # keep original casing
            merged_names.append(names_existing[i])
            merged_days.append(days_existing[i])

        # 2. Append our desired MACs (always-block, empty schedule).
        for mac in desired_clean:
            label = names_lower.get(mac) or mac.upper()
            # Avoid duplicates if the user *also* has this MAC manually --
            # respect their rule rather than trample it.
            if any(_norm_mac(m) == mac for m in merged_macs):
                continue
            merged_macs.append(mac.upper())
            merged_names.append(label)
            merged_days.append("")  # empty = always block

        joined_mac = ">".join(merged_macs)
        joined_name = ">".join(merged_names)
        joined_day = ">".join(merged_days)

        # If the merged list is empty AND we had previously turned the
        # feature on, restore ENABLE to '0'. Otherwise keep the user's
        # current ENABLE (they may have it on for their own rules).
        had_prev_enable = (snap.get("MULTIFILTER_ENABLE") or "0") != "0"
        if not merged_macs:
            new_enable = "0"
        else:
            new_enable = "2"  # "Block Internet Access" mode on this firmware
            if had_prev_enable and snap.get("MULTIFILTER_ENABLE") in ("1", "2"):
                new_enable = snap["MULTIFILTER_ENABLE"]  # respect user's choice

        values = {
            "MULTIFILTER_ENABLE": new_enable,
            "MULTIFILTER_ALL": snap.get("MULTIFILTER_ALL") or "0",
            "MULTIFILTER_MAC": joined_mac,
            "MULTIFILTER_DEVICENAME": joined_name,
            "MULTIFILTER_MACFILTER_DAYTIME_V2": joined_day,
            "MULTIFILTER_URL_ENABLE": snap.get("MULTIFILTER_URL_ENABLE") or "0",
            "MULTIFILTER_URL": snap.get("MULTIFILTER_URL") or "",
            "MULTIFILTER_URL_LIST": snap.get("MULTIFILTER_URL_LIST") or "",
        }

        await self.apply_nvram(action_script="restart_firewall", values=values)
        return {
            "pushed_macs": [m.lower() for m in merged_macs],
            "ours": desired_clean,
            "preserved_user_rules": [
                m.lower() for m in macs
                if _norm_mac(m) and _norm_mac(m) not in prev_managed
            ],
            "enable": new_enable,
        }

    # ---------------------------------------------------------------- helpers

    async def test_connection(self) -> dict[str, Any]:
        """Verify host + creds; returns small status dict for the UI."""
        async with self._lock:
            self._login_attempted = False  # force fresh login
            await self.login()
            try:
                snap = await self.nvram_get([
                    "productid", "firmver", "buildno", "extendno", "lan_ipaddr",
                ])
            except AsusRouterError as exc:
                # We logged in but couldn't read nvram; surface what we have.
                return {"ok": True, "model": None, "warning": str(exc)}
            return {
                "ok": True,
                "model": snap.get("productid") or "unknown",
                "firmware": "_".join(
                    s for s in (snap.get("firmver"), snap.get("buildno"),
                                snap.get("extendno")) if s
                ),
                "lanIp": snap.get("lan_ipaddr"),
            }


# AsusWRT defaults across recent firmwares. Order matters: the first one
# that completes a login wins. http/80 is most common on stock firmware,
# https/8443 is the default if HTTPS is enabled in the web UI.
DEFAULT_PROBE_ORDER: list[tuple[str, int]] = [
    ("http",  80),
    ("https", 8443),
    ("https", 443),
    ("http",  8080),
]


async def detect_router_endpoint(
    host: str,
    username: str,
    password: str,
    *,
    preferred: tuple[str, int | None] | None = None,
    timeout: float = 6.0,
) -> dict[str, Any]:
    """Probe a list of (scheme, port) combos until one logs in.

    Returns ``{"scheme": "...", "port": N, "info": <test_connection dict>}``
    on success, or raises AsusRouterError with a combined hint listing every
    combo that was tried and why it failed.
    """
    tried: list[tuple[str, int]] = []
    if preferred:
        scheme, port = preferred
        tried.append((scheme, port if port else (443 if scheme == "https" else 80)))
    for combo in DEFAULT_PROBE_ORDER:
        if combo not in tried:
            tried.append(combo)

    failures: list[str] = []
    for scheme, port in tried:
        client = AsusRouterClient(
            host=host, username=username, password=password,
            scheme=scheme, port=port, timeout=timeout,
        )
        try:
            async with client:
                info = await client.test_connection()
            return {"scheme": scheme, "port": port, "info": info}
        except AsusRouterError as exc:
            log.debug("probe failed: %s://%s:%s -> %s", scheme, host, port, exc)
            failures.append(f"{scheme}://{port}: {exc}")

    raise AsusRouterError(
        "could not reach the router on any common port. "
        + " · ".join(failures[:3])
    )
