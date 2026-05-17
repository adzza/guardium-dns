"""Cookie + CSRF client for the UniFi Network controller's "private" API.

There are two ABI shapes in the wild:

1. **UniFi OS hosts** (UDM / UDM-Pro / UDM-SE / UDR / UCG / UXG-Pro / EFG /
   CK G2+ / UniFi OS Server) — login at ``POST /api/auth/login``, then
   every Network API path is prefixed with ``/proxy/network``. CSRF
   header ``X-CSRF-Token`` is required on all writes; the server rotates
   it on each response via ``X-Updated-CSRF-Token``.

2. **Legacy standalone Network Application** (the old "Network
   Application 7.x running on a Pi") — login at ``POST /api/login`` on
   port 8443, no path prefix, no CSRF requirement.

We auto-detect by trying #1 first. If the controller returns 404 on the
UniFi OS login path we fall back to the legacy login. The detected
shape is cached on the client instance for the life of the session.

Endpoints we exercise in Phase 2 (read-only):

- ``GET /api/self/sites``          — list sites the admin can see
- ``GET /api/s/{site}/stat/sta``   — currently connected clients
- ``GET /v2/api/site/{site}/trafficrules`` — existing Traffic Rules
  (the surface we'll create+update in Phase 3 / 4).

Endpoints we'll add in subsequent phases:

- ``POST /api/s/{site}/cmd/stamgr`` (block-sta / unblock-sta) — hard L2
  kick fallback for Stage 1 if the Traffic Rule path proves flakey.
- ``POST /v2/api/site/{site}/trafficrules`` — create the managed rule.
- ``PUT  /v2/api/site/{site}/trafficrules/{_id}`` — idempotent updates.
- ``DELETE /v2/api/site/{site}/trafficrules/{_id}`` — tear-down.

References (all undocumented officially):
- UniFi Network Application's web app source — definitive but minified.
- Art-of-WiFi UniFi-API-client (PHP) — reverse-engineered endpoint catalogue.
- Terraform ``resnickio/unifi`` provider — schema for Traffic Rules.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx


log = logging.getLogger("dns-dashboard.routers.unifi.legacy")


class UnifiError(Exception):
    """Anything the controller rejected or replied unexpectedly to."""


class UnifiAuthError(UnifiError):
    """Specifically: the controller refused the supplied credentials.

    Surfaced separately because the controller has an aggressive
    ``AUTHENTICATION_FAILED_LIMIT_REACHED`` lockout policy; we want to
    NOT auto-retry login on auth failures, only on session-expired 401s
    from a previously-good login.
    """


class UnifiLegacyApi:
    """Single-session, single-host client. Not thread-safe.

    Usage::

        async with UnifiLegacyApi(host=..., username=..., password=...) as api:
            sites = await api.list_sites()
            clients = await api.list_clients()

    On enter we log in and detect the host flavour; on exit we close
    the underlying httpx client (and therefore drop the cookie).
    """

    def __init__(
        self,
        *,
        host: str,
        username: str,
        password: str,
        site: str = "default",
        verify_tls: bool = False,
        timeout: float = 10.0,
    ) -> None:
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.site = site
        self._verify = verify_tls
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        # Resolved at login. "os" -> UniFi OS host (path prefix
        # /proxy/network); "legacy" -> standalone Network Application.
        self._flavour: str | None = None
        self._csrf: str | None = None
        self._logged_in = False

    # ---- context manager ----------------------------------------------

    async def __aenter__(self) -> "UnifiLegacyApi":
        await self._ensure_client()
        await self._login()
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self._logged_in = False
        self._csrf = None

    # ---- public read API ----------------------------------------------

    @property
    def flavour(self) -> str | None:
        """``"os"`` or ``"legacy"`` once :meth:`__aenter__` has run."""
        return self._flavour

    async def list_sites(self) -> list[dict[str, Any]]:
        """List sites the authenticated admin can see."""
        data = await self._get_json(self._api_path("/api/self/sites"))
        return list(data.get("data") or [])

    async def list_clients(self) -> list[dict[str, Any]]:
        """Currently-connected clients (``/stat/sta``).

        UniFi calls these "stations". Each entry has ``mac``, ``ip`` (if
        the controller has seen one), ``hostname`` / ``name``, and an
        ``oui`` field if the controller has resolved the vendor.
        """
        data = await self._get_json(
            self._api_path(f"/api/s/{self.site}/stat/sta"),
        )
        return list(data.get("data") or [])

    async def list_traffic_rules(self) -> list[dict[str, Any]]:
        """Existing Traffic Rules (the v2 API surface).

        v2 endpoints return plain JSON lists, NOT the legacy
        ``{"data": [...], "meta": {...}}`` envelope.
        """
        return await self._get_json(
            self._api_path(f"/v2/api/site/{self.site}/trafficrules"),
            envelope=False,
        )

    # ---- request plumbing ---------------------------------------------

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.host,
                timeout=self._timeout,
                verify=self._verify,
                follow_redirects=False,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Guardium DNS (UniFi adapter)",
                },
            )
        return self._client

    def _api_path(self, path: str) -> str:
        """Apply ``/proxy/network`` prefix on UniFi OS hosts; passthrough
        on the legacy standalone.
        """
        if self._flavour == "os":
            return f"/proxy/network{path}"
        return path

    async def _login(self) -> None:
        """Try UniFi OS login first; fall back to legacy on 404.

        On success records the host flavour and the initial CSRF token.
        """
        client = await self._ensure_client()
        body = {"username": self.username, "password": self.password}

        # 1. UniFi OS shape.
        try:
            resp = await client.post("/api/auth/login", json=body)
        except httpx.HTTPError as exc:
            raise UnifiError(f"could not reach controller: {exc}") from exc

        if resp.status_code == 200:
            self._flavour = "os"
            self._csrf = (
                resp.headers.get("X-Updated-CSRF-Token")
                or resp.headers.get("X-CSRF-Token")
            )
            self._logged_in = True
            log.info("UniFi login OK (flavour=os, csrf=%s)",
                     "yes" if self._csrf else "absent")
            return

        if resp.status_code in (401, 403):
            raise UnifiAuthError(self._explain_auth_failure(resp))

        if resp.status_code != 404:
            raise UnifiError(
                f"controller rejected UniFi-OS login: HTTP {resp.status_code}: "
                f"{resp.text[:200]}"
            )

        # 2. Legacy fall-back.
        try:
            resp = await client.post("/api/login", json=body)
        except httpx.HTTPError as exc:
            raise UnifiError(f"could not reach controller: {exc}") from exc

        if resp.status_code != 200:
            if resp.status_code in (401, 403):
                raise UnifiAuthError(self._explain_auth_failure(resp))
            raise UnifiError(
                f"controller rejected legacy login: HTTP {resp.status_code}: "
                f"{resp.text[:200]}"
            )
        self._flavour = "legacy"
        self._csrf = None  # legacy doesn't use CSRF
        self._logged_in = True
        log.info("UniFi login OK (flavour=legacy)")

    async def _get_json(
        self,
        path: str,
        *,
        envelope: bool = True,
        params: dict | None = None,
    ) -> Any:
        """GET ``path`` and parse JSON.

        ``envelope=True`` (default) returns the parsed body unchanged
        -- the caller pulls ``.data`` out of the legacy envelope. v2
        endpoints (``/v2/api/...``) return plain JSON; pass
        ``envelope=False`` to make that intent explicit at the call
        site even though we don't currently use the flag here, so this
        stays a single code path.
        """
        client = await self._ensure_client()
        resp = await self._call_with_relogin("GET", path, params=params)
        return self._parse_json(resp, path)

    async def _call_with_relogin(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: Any | None = None,
    ) -> httpx.Response:
        """Execute one HTTP call; on 401 re-login once and retry."""
        if not self._logged_in:
            await self._login()
        client = await self._ensure_client()

        for attempt in (0, 1):
            headers: dict[str, str] = {}
            if self._csrf and method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
                headers["X-CSRF-Token"] = self._csrf

            try:
                resp = await client.request(
                    method, path, params=params, json=json_body, headers=headers,
                )
            except httpx.HTTPError as exc:
                raise UnifiError(f"{method} {path} network error: {exc}") from exc

            # Track rotating CSRF token.
            new_csrf = resp.headers.get("X-Updated-CSRF-Token")
            if new_csrf:
                self._csrf = new_csrf

            if resp.status_code == 401 and attempt == 0:
                # Session expired; the controller cleared our cookie.
                log.info("UniFi session 401 on %s %s; re-login and retry",
                         method, path)
                self._logged_in = False
                await self._login()
                continue

            if resp.status_code >= 400:
                raise UnifiError(self._explain_http_error(resp, method, path))

            return resp

        raise UnifiError(f"{method} {path}: 401 after relogin (auth loop)")

    def _parse_json(self, resp: httpx.Response, path: str) -> Any:
        try:
            return resp.json()
        except ValueError as exc:
            raise UnifiError(
                f"GET {path}: response was not JSON: {resp.text[:200]}"
            ) from exc

    @staticmethod
    def _explain_auth_failure(resp: httpx.Response) -> str:
        body = (resp.text or "").lower()
        if "authentication_failed_limit_reached" in body:
            return (
                "controller has temporarily locked this account after too many "
                "failed logins. Wait a few minutes, double-check the password, "
                "or use a dedicated Guardium admin account."
            )
        return "controller refused credentials (check username + password)"

    @staticmethod
    def _explain_http_error(resp: httpx.Response, method: str, path: str) -> str:
        body = resp.text[:300] if resp.text else ""
        return f"controller HTTP {resp.status_code} on {method} {path}: {body}"
