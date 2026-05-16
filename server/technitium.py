"""Async client for the Technitium DNS Server HTTP API.

All endpoints are documented at https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md.
This client is intentionally thin: it just calls the API and returns the
``response`` field from the JSON envelope, raising ``TechnitiumError`` if the
server replies with ``status != "ok"``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

import httpx


class TechnitiumError(RuntimeError):
    """Raised when Technitium returns ``status: error`` (or non-2xx HTTP)."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class TechnitiumConfig:
    base_url: str
    token: str | None = None
    timeout: float = 15.0


class TechnitiumClient:
    def __init__(self, config: TechnitiumConfig) -> None:
        self._config = config
        self._client = httpx.AsyncClient(
            base_url=config.base_url.rstrip("/"),
            timeout=config.timeout,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "TechnitiumClient":
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.aclose()

    async def _call(
        self,
        path: str,
        params: Mapping[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        if params:
            for k, v in params.items():
                if v is None:
                    continue
                merged[k] = "true" if v is True else "false" if v is False else v
        auth_token = token if token is not None else self._config.token
        if auth_token and "token" not in merged and not path.startswith("/api/user/login"):
            merged["token"] = auth_token
        try:
            resp = await self._client.get(path, params=merged)
        except httpx.HTTPError as exc:
            raise TechnitiumError(f"transport error calling {path}: {exc}") from exc
        if resp.status_code >= 500:
            raise TechnitiumError(
                f"{path} returned HTTP {resp.status_code}",
                status_code=resp.status_code,
            )
        try:
            data = resp.json()
        except json.JSONDecodeError as exc:
            raise TechnitiumError(f"invalid JSON from {path}: {exc}") from exc
        status = data.get("status")
        if status != "ok":
            msg = data.get("errorMessage") or data.get("status") or "unknown error"
            raise TechnitiumError(
                f"{path}: {msg}",
                status_code=resp.status_code,
            )
        return data

    async def login(self, user: str, password: str) -> dict[str, Any]:
        """Returns the full login response (token, displayName, info, etc.)."""
        return await self._call(
            "/api/user/login",
            {"user": user, "pass": password, "includeInfo": True},
        )

    async def session_info(self, token: str) -> dict[str, Any]:
        return await self._call("/api/user/session/get", {"includeInfo": True}, token=token)

    async def logout(self, token: str) -> None:
        try:
            await self._call("/api/user/logout", token=token)
        except TechnitiumError:
            pass

    async def get_dashboard_stats(
        self, *, time_range: str = "LastHour", utc: bool = False
    ) -> dict[str, Any]:
        data = await self._call(
            "/api/dashboard/stats/get",
            {"type": time_range, "utc": utc},
        )
        return data["response"]

    async def get_top(
        self,
        *,
        stats_type: str,
        time_range: str = "LastHour",
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        data = await self._call(
            "/api/dashboard/stats/getTop",
            {"type": time_range, "statsType": stats_type, "limit": limit},
        )
        resp = data["response"]
        # Technitium returns different keys per statsType: topClients, topDomains, etc.
        for k in ("topClients", "topDomains", "topBlockedDomains"):
            if k in resp:
                return resp[k]
        for v in resp.values():
            if isinstance(v, list):
                return v
        return []

    async def list_apps(self) -> list[dict[str, Any]]:
        data = await self._call("/api/apps/list")
        return data["response"]["apps"]

    async def get_app_config(self, name: str) -> dict[str, Any]:
        """Returns the parsed JSON config for an installed DNS app."""
        data = await self._call("/api/apps/config/get", {"name": name})
        raw = data["response"].get("config") or "{}"
        return json.loads(raw)

    async def set_app_config(self, name: str, config: dict[str, Any]) -> None:
        """Replaces the entire app config blob.

        Technitium expects the config as a POSTed form field (it accepts GET too).
        We send it as a query/body parameter via POST since the JSON can be large.
        """
        body = {
            "token": self._config.token,
            "name": name,
            "config": json.dumps(config),
        }
        try:
            resp = await self._client.post("/api/apps/config/set", data=body)
        except httpx.HTTPError as exc:
            raise TechnitiumError(f"transport error setting app config: {exc}") from exc
        try:
            data = resp.json()
        except json.JSONDecodeError as exc:
            raise TechnitiumError(f"invalid JSON setting app config: {exc}") from exc
        if data.get("status") != "ok":
            raise TechnitiumError(
                f"setAppConfig: {data.get('errorMessage', 'unknown error')}",
                status_code=resp.status_code,
            )

    async def query_logs(
        self,
        *,
        app_name: str = "Query Logs (Sqlite)",
        class_path: str = "QueryLogsSqlite.App",
        page_number: int = 1,
        entries_per_page: int = 50,
        client_ip: str | None = None,
        qname: str | None = None,
    ) -> dict[str, Any]:
        """Read entries from an installed query-logger app.

        The endpoint is ``/api/logs/query`` (NOT ``/api/logs/queryLogs``) and
        requires both ``name`` (the installed app's display name) and
        ``classPath`` (the DnsApp class path inside that app).
        """
        params: dict[str, Any] = {
            "name": app_name,
            "classPath": class_path,
            "pageNumber": page_number,
            "entriesPerPage": entries_per_page,
            "descendingOrder": True,
        }
        if client_ip:
            params["clientIpAddress"] = client_ip
        if qname:
            params["qname"] = qname
        try:
            data = await self._call("/api/logs/query", params)
        except TechnitiumError:
            return {"entries": [], "totalEntries": 0, "totalPages": 0, "pageNumber": page_number}
        return data["response"]

    async def install_app_from_store(self, app_name: str, url: str) -> None:
        """Download and install a Technitium DNS app (idempotent; already-
        installed apps return an error which we swallow)."""
        try:
            await self._call(
                "/api/apps/downloadAndInstall",
                {"name": app_name, "url": url},
            )
        except TechnitiumError as exc:
            msg = str(exc).lower()
            if "already" in msg or "installed" in msg:
                return
            raise
