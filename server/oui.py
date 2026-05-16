"""Offline MAC OUI vendor lookup.

The first three octets of a MAC address (the *Organizationally Unique
Identifier*) map to a vendor in the IEEE registry, e.g.

    8C:9D:75:xx:xx:xx -> Sercomm Corporation
    70:9C:D1:xx:xx:xx -> Hewlett Packard Inc.

This module loads the IEEE OUI registry into memory once and exposes
``vendor_for(mac)`` for O(1) lookups. Memory cost is ~3-5 MB for the
full registry.

Source priority:

1. ``$DASHBOARD_OUI_FILE`` if set.
2. ``$DASHBOARD_DATA_DIR/oui.csv`` (typical install path).
3. ``server/data/oui.csv`` bundled in the repo.
4. Best-effort one-time fetch from ``standards-oui.ieee.org`` to
   ``$DASHBOARD_DATA_DIR/oui.csv`` (~5 MB) the first time the module
   is imported on a fresh install. Failures are logged and the lookup
   silently disables itself -- the dashboard still works, vendor
   information just shows as ``None``.
"""
from __future__ import annotations

import csv
import logging
import os
import re
import threading
from pathlib import Path
from typing import Optional


log = logging.getLogger("dns-dashboard.oui")

# Where on disk to look for / cache the registry.
_DEFAULT_BUNDLE = Path(__file__).resolve().parent / "data" / "oui.csv"
_DATA_DIR = Path(os.environ.get("DASHBOARD_DATA_DIR", "/var/lib/dns-dashboard"))
_DATA_CACHE = _DATA_DIR / "oui.csv"
_OVERRIDE = os.environ.get("DASHBOARD_OUI_FILE")

# Sources to try, in order, until one returns 200. IEEE often serves
# 418/403 to anonymous user-agents -- the Wireshark "manuf" file is a
# parallel community-maintained mirror of the same data, in a slightly
# different format that ``_read_csv`` also understands.
_OUI_SOURCES: tuple[str, ...] = (
    "https://standards-oui.ieee.org/oui/oui.csv",
    "https://www.wireshark.org/download/automated/data/manuf",
    "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf",
)
# Browser-y UA so picky CDN front-ends don't 418 us.
_FETCH_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64; DNS-Dashboard) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
    ),
    "Accept": "text/csv, text/plain;q=0.9, */*;q=0.5",
}
_FETCH_TIMEOUT = 30.0

# Suffixes we trim off the org name to keep the UI compact. Trimmed in
# order, repeatedly, until no more match. (E.g. "Foo Co., Ltd." ->
# "Foo".)
_TRIM_SUFFIXES = (
    ", Inc.", " Inc.", ", Inc", " Inc",
    ", LLC", " LLC", ", L.L.C.", " L.L.C.",
    ", Ltd.", " Ltd.", ", Ltd", " Ltd",
    ", Co., Ltd.", " Co., Ltd.", ", Co. Ltd.", " Co. Ltd.",
    ", Co.,Ltd.", " Co.,Ltd.",
    " Corporation", " Corp.", " Corp",
    " Company",
    " GmbH", " GmbH & Co. KG", " S.A.", " B.V.", " AG", " AB", " SRL",
    " (HK)", " (Shenzhen)",
)

_HEX_RE = re.compile(r"[0-9a-fA-F]")

# Internal state.
_OUI_MAP: dict[str, str] | None = None
_LOAD_LOCK = threading.Lock()


def _shorten_org(org: str) -> str:
    s = (org or "").strip().strip('"').strip()
    changed = True
    while changed:
        changed = False
        for sfx in _TRIM_SUFFIXES:
            if s.lower().endswith(sfx.lower()):
                s = s[: -len(sfx)].rstrip(" ,.")
                changed = True
    # Collapse repeated whitespace.
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _read_csv(path: Path) -> dict[str, str]:
    """Parse the IEEE-style CSV at ``path`` into ``{prefix6: vendor}``.

    The file may use either the canonical IEEE column layout
    ("Registry,Assignment,Organization Name,Organization Address") or
    the older Wireshark "manuf" plain-text format. We sniff the header.
    """
    out: dict[str, str] = {}
    try:
        with path.open(newline="", encoding="utf-8", errors="replace") as fp:
            sample = fp.read(2048)
            fp.seek(0)
            if "Assignment" in sample and "Organization" in sample:
                reader = csv.DictReader(fp)
                for row in reader:
                    assignment = (row.get("Assignment") or "").strip().upper()
                    org = (row.get("Organization Name") or "").strip()
                    if len(assignment) >= 6 and org:
                        out[assignment[:6]] = _shorten_org(org)
            else:
                # Fallback: expect "AA-BB-CC<TAB>Vendor" or "AABBCC,Vendor".
                for line in fp:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = re.split(r"[\t,]", line, maxsplit=1)
                    if len(parts) != 2:
                        continue
                    prefix = "".join(c for c in parts[0] if _HEX_RE.match(c)).upper()
                    if len(prefix) >= 6:
                        out[prefix[:6]] = _shorten_org(parts[1])
    except Exception:  # noqa: BLE001
        log.exception("Failed to read OUI database at %s", path)
    return out


def _try_fetch_to_cache() -> Path | None:
    """Best-effort download of the OUI registry into the data dir.

    Tries each entry in ``_OUI_SOURCES`` in turn, with a browser-like
    ``User-Agent`` (otherwise IEEE's CDN tends to reply with 418 or
    403). Returns the cached path on success, ``None`` if every
    source fails.
    """
    try:
        import httpx  # local import: keep startup cheap when offline
    except ImportError:
        log.warning("httpx not available; cannot self-fetch OUI database")
        return None
    last_err: str | None = None
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    for url in _OUI_SOURCES:
        try:
            log.info("Fetching OUI registry from %s ...", url)
            with httpx.stream(
                "GET", url,
                timeout=_FETCH_TIMEOUT,
                follow_redirects=True,
                headers=_FETCH_HEADERS,
            ) as resp:
                resp.raise_for_status()
                tmp = _DATA_CACHE.with_suffix(".csv.tmp")
                with tmp.open("wb") as out:
                    for chunk in resp.iter_bytes():
                        out.write(chunk)
                tmp.replace(_DATA_CACHE)
            size = _DATA_CACHE.stat().st_size
            if size < 100_000:
                # Suspiciously small; probably an error page.
                log.warning("Downloaded OUI file from %s is only %d bytes; "
                            "discarding and trying next source", url, size)
                _DATA_CACHE.unlink(missing_ok=True)
                continue
            log.info("Saved OUI registry from %s (%d bytes)", url, size)
            return _DATA_CACHE
        except Exception as exc:  # noqa: BLE001
            last_err = str(exc)
            log.warning("OUI fetch from %s failed: %s", url, exc)
            continue
    log.warning("All OUI sources failed (last error: %s)", last_err)
    return None


def _resolve_source() -> Path | None:
    if _OVERRIDE:
        p = Path(_OVERRIDE)
        if p.exists():
            return p
        log.warning("DASHBOARD_OUI_FILE=%s does not exist", _OVERRIDE)

    if _DATA_CACHE.exists():
        return _DATA_CACHE
    if _DEFAULT_BUNDLE.exists():
        return _DEFAULT_BUNDLE

    fetched = _try_fetch_to_cache()
    return fetched


def _ensure_loaded() -> dict[str, str]:
    global _OUI_MAP
    if _OUI_MAP is not None:
        return _OUI_MAP
    with _LOAD_LOCK:
        if _OUI_MAP is not None:
            return _OUI_MAP
        src = _resolve_source()
        if src is None:
            log.warning("OUI database unavailable; vendor lookups disabled")
            _OUI_MAP = {}
            return _OUI_MAP
        loaded = _read_csv(src)
        log.info("Loaded %d OUI entries from %s", len(loaded), src)
        _OUI_MAP = loaded
        return _OUI_MAP


def vendor_for(mac: Optional[str]) -> Optional[str]:
    """Return the vendor for a MAC, or ``None`` if unknown.

    Accepts any common formatting (``AA:BB:CC:DD:EE:FF``,
    ``aa-bb-cc-dd-ee-ff``, ``aabb.ccdd.eeff``, ``aabbccddeeff``).
    Returns ``None`` for locally-administered (LAA / random) MACs --
    those have the second-lsb of the first octet set to 1, and lookups
    against the IEEE registry are meaningless.
    """
    if not mac:
        return None
    norm = "".join(c for c in mac if c.isalnum()).upper()
    if len(norm) < 6:
        return None
    # First-octet ``locally-administered`` bit (mask 0x02) -> randomised
    # MAC, no IEEE allocation.
    try:
        first = int(norm[:2], 16)
        if first & 0x02:
            return None
    except ValueError:
        return None
    db = _ensure_loaded()
    return db.get(norm[:6])


def is_loaded() -> bool:
    return _OUI_MAP is not None and len(_OUI_MAP) > 0


def reload() -> int:
    """Force-reload from disk (after a manual refresh). Returns count."""
    global _OUI_MAP
    with _LOAD_LOCK:
        src = _resolve_source()
        _OUI_MAP = _read_csv(src) if src else {}
        return len(_OUI_MAP)
