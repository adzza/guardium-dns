"""Reverse-DNS hostname resolver.

The ASUS router runs ``dnsmasq`` and answers PTR queries for every DHCP lease
out of the box. So instead of running our own DHCP server (which would break
AiMesh), we simply ask the gateway for the hostname of each client IP.

Results are cached for :data:`CACHE_TTL` seconds. Per-IP failures are also
cached negatively (with a shorter TTL) so we don't hammer the router for IPs
the dnsmasq doesn't know.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import dns.reversename


log = logging.getLogger("dns-dashboard.hostnames")

CACHE_TTL = 300         # 5 minutes for successful lookups
NEGATIVE_TTL = 60       # 1 minute for failures
QUERY_TIMEOUT = 1.5     # seconds per individual query


@dataclass
class _Entry:
    hostname: str | None
    expires: float


class HostnameResolver:
    """Asynchronously resolves PTR records via a configured upstream resolver."""

    def __init__(self, *, nameservers: list[str], domain_strip: list[str] | None = None) -> None:
        self._nameservers = nameservers
        self._domain_strip = [d.strip(".").lower() for d in (domain_strip or [])]
        self._cache: dict[str, _Entry] = {}
        self._lock = asyncio.Lock()

        self._resolver = dns.asyncresolver.Resolver(configure=False)
        self._resolver.nameservers = nameservers
        self._resolver.lifetime = QUERY_TIMEOUT
        self._resolver.timeout = QUERY_TIMEOUT

    @property
    def nameservers(self) -> list[str]:
        return list(self._nameservers)

    def _strip(self, name: str) -> str:
        n = name.rstrip(".")
        for suffix in self._domain_strip:
            if n.lower().endswith("." + suffix):
                n = n[: -(len(suffix) + 1)]
                break
            if n.lower() == suffix:
                n = ""
                break
        return n

    async def _query(self, ip: str) -> str | None:
        try:
            qname = dns.reversename.from_address(ip)
        except (dns.exception.SyntaxError, ValueError):
            return None
        try:
            answer = await self._resolver.resolve(qname, dns.rdatatype.PTR)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            return None
        except Exception:  # noqa: BLE001
            log.exception("PTR lookup for %s failed", ip)
            return None
        for rdata in answer:
            try:
                return self._strip(str(rdata.target))
            except Exception:  # noqa: BLE001
                continue
        return None

    async def lookup(self, ip: str) -> str | None:
        now = time.time()
        async with self._lock:
            cached = self._cache.get(ip)
            if cached and cached.expires > now:
                return cached.hostname
        host = await self._query(ip)
        async with self._lock:
            ttl = CACHE_TTL if host else NEGATIVE_TTL
            self._cache[ip] = _Entry(hostname=host, expires=now + ttl)
        return host

    async def lookup_many(self, ips: list[str]) -> dict[str, str | None]:
        if not ips:
            return {}
        # Pull cached entries first to avoid creating tasks for known IPs.
        now = time.time()
        result: dict[str, str | None] = {}
        to_query: list[str] = []
        async with self._lock:
            for ip in ips:
                cached = self._cache.get(ip)
                if cached and cached.expires > now:
                    result[ip] = cached.hostname
                else:
                    to_query.append(ip)
        if to_query:
            answers = await asyncio.gather(*(self._query(ip) for ip in to_query))
            now2 = time.time()
            async with self._lock:
                for ip, host in zip(to_query, answers, strict=True):
                    ttl = CACHE_TTL if host else NEGATIVE_TTL
                    self._cache[ip] = _Entry(hostname=host, expires=now2 + ttl)
                    result[ip] = host
        return result

    def invalidate(self, ip: str | None = None) -> None:
        if ip is None:
            self._cache.clear()
        else:
            self._cache.pop(ip, None)
