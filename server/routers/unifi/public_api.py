"""API-key client for UniFi's ``/proxy/network/integration/v1`` surface.

This is the *supported, documented* API Ubiquiti shipped circa 2024
for integrations. It's read-mostly and lives only on UniFi OS hosts
(UDM/UDM-Pro/Cloud Key G2+/OS Server). Legacy standalone Network
Application installs don't expose ``/integration/v1`` at all, so this
client is optional from Guardium's point of view -- if the user
doesn't supply an API key we just fall back to the
:class:`UnifiLegacyApi` cookie session for everything.

We use the public API for the two things it's actually best at:

- **DPI discovery** -- the legacy ``/v2`` API doesn't reliably expose
  application category IDs; the integration API does. See
  :mod:`.doh_apps` for the lookup that converts "DoH" / "DoT" into
  the IDs needed for Simple App Blocking rules.
- **Gateway model probe** -- so we can warn the user early if their
  gateway model is one of the few that doesn't support Simple App
  Blocking, before they wonder why the DoH rule isn't actually
  blocking anything.

Authentication: every request carries an ``X-API-KEY`` header. Tokens
are issued via the UniFi Network UI under
*Settings → Control Plane → Admins & Users → API Keys*.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx


log = logging.getLogger("dns-dashboard.routers.unifi.public")


class UnifiPublicApiError(Exception):
    """The controller rejected a public-API request."""


# All public-API paths live under this prefix on UniFi OS hosts.
_BASE = "/proxy/network/integration/v1"


class UnifiPublicApi:
    """Async client for the integration API.

    The session is stateless from our side -- each request is just an
    HTTPS call with the API-key header -- but we keep an ``httpx`` client
    open across requests for connection reuse.
    """

    def __init__(
        self,
        *,
        host: str,
        api_key: str,
        verify_tls: bool = False,
        timeout: float = 10.0,
    ) -> None:
        self.host = host.rstrip("/")
        self._api_key = api_key
        self._verify = verify_tls
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "UnifiPublicApi":
        await self._ensure_client()
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ---- public read API ----------------------------------------------

    async def list_sites(self) -> list[dict[str, Any]]:
        return self._unwrap_list(await self._get(f"{_BASE}/sites"))

    async def list_clients(self, site_id: str) -> list[dict[str, Any]]:
        return self._unwrap_list(
            await self._get(f"{_BASE}/sites/{site_id}/clients")
        )

    async def list_devices(self, site_id: str) -> list[dict[str, Any]]:
        """List gateways, switches, APs. Used for the gateway-model probe."""
        return self._unwrap_list(
            await self._get(f"{_BASE}/sites/{site_id}/devices")
        )

    async def list_dpi_categories(self) -> list[dict[str, Any]]:
        return self._unwrap_list(await self._get(f"{_BASE}/dpi/categories"))

    async def list_dpi_applications(self) -> list[dict[str, Any]]:
        return self._unwrap_list(await self._get(f"{_BASE}/dpi/applications"))

    # ---- helpers ------------------------------------------------------

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.host,
                timeout=self._timeout,
                verify=self._verify,
                follow_redirects=False,
                headers={
                    "Accept": "application/json",
                    "X-API-KEY": self._api_key,
                    "User-Agent": "Guardium DNS (UniFi adapter)",
                },
            )
        return self._client

    async def _get(self, path: str) -> Any:
        client = await self._ensure_client()
        try:
            resp = await client.get(path)
        except httpx.HTTPError as exc:
            raise UnifiPublicApiError(
                f"network error reaching public API {path}: {exc}"
            ) from exc
        if resp.status_code == 401:
            raise UnifiPublicApiError(
                "controller refused the API key (check it's still valid "
                "and has 'Network' scope)."
            )
        if resp.status_code == 404:
            raise UnifiPublicApiError(
                f"public API path {path} returned 404. This usually means "
                "the controller is a legacy standalone Network Application "
                "(no integration API). Use the cookie session only."
            )
        if resp.status_code >= 400:
            raise UnifiPublicApiError(
                f"public API HTTP {resp.status_code} on {path}: "
                f"{resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise UnifiPublicApiError(
                f"public API {path} response was not JSON: {resp.text[:200]}"
            ) from exc

    @staticmethod
    def _unwrap_list(payload: Any) -> list[dict[str, Any]]:
        """The public API uses ``{"data": [...], "offset": ..., "limit": ...}``
        for paged results. We don't paginate yet -- household-scale data
        comfortably fits in the default page -- but we unwrap so callers
        get a flat list either way.
        """
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, list):
                return data
        raise UnifiPublicApiError(
            f"unexpected public API payload shape: {type(payload).__name__}"
        )
