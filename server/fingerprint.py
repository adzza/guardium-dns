"""Lightweight domain-pattern device fingerprinting.

Given a sample of qnames a device has recently queried (from the
Technitium query log), guess what *kind* of device it is. Combined
with the MAC OUI vendor name, this gives the user something more
useful than ``192.168.4.140 / GoogleTV6347`` -- e.g. *"TCL Smart TV
(probably) -- vendor: Sercomm"*.

The matching is deliberately conservative:

- Each rule has a *tier*. Tier 1 ("specific") rules identify a
  device class -- "Samsung Smart TV", "Apple TV", "Xbox". Tier 2
  ("vendor-only") rules just point at the platform vendor when no
  more-specific match is possible -- "Apple device", "Android",
  "Windows PC".
- We count *distinct* qnames each rule matches (so a chatty domain
  can't drown out a more-specific one).
- The rule with the lowest tier (most specific) and the highest
  match count wins. Tier-2 hints only surface when no tier-1 rule
  fired.

The rules below are hand-curated for common consumer devices likely
to appear on a home network. Order doesn't matter for correctness,
only for maintainability.
"""
from __future__ import annotations

from typing import Iterable


# (substring_match, label, tier)
RULES: list[tuple[str, str, int]] = [
    # ---------- Smart TVs (tier 1) ---------------------------------
    # Samsung TV-specific cloud endpoints.
    ("samsungcloudsolution.com",  "Samsung Smart TV",   1),
    ("samsungosp.com",            "Samsung Smart TV",   1),
    ("samsungrm.net",             "Samsung Smart TV",   1),
    ("samsungotn.net",            "Samsung Smart TV",   1),
    # Generic Samsung -- could be a phone, watch, fridge, ...
    ("samsungelectronics.com",    "Samsung device",     2),

    ("tcl-tvplay.com",            "TCL Smart TV",       1),
    ("tclrtbe.com",               "TCL Smart TV",       1),
    ("tcleon.com",                "TCL Smart TV",       1),
    ("tclscanresult.com",         "TCL Smart TV",       1),

    ("lgsmartad.com",             "LG Smart TV",        1),
    ("lgwebos.com",               "LG Smart TV",        1),
    ("lgappstv.com",              "LG Smart TV",        1),
    ("lgtvonline.com",            "LG Smart TV",        1),
    ("lgtvsdp.com",               "LG Smart TV",        1),

    ("vewd.com",                  "Smart TV (Vewd)",    1),
    ("hbbtv.com",                 "Smart TV (HbbTV)",   1),
    ("viziocast.com",             "Vizio Smart TV",     1),
    ("hisense.com",               "Hisense Smart TV",   1),

    # ---------- Streaming sticks / boxes ---------------------------
    ("aod.itunes.apple.com",      "Apple TV",           1),
    ("appletv.itunes.apple.com",  "Apple TV",           1),
    ("tvplus.apple.com",          "Apple TV",           1),

    ("roku.com",                  "Roku",               1),
    ("rokulabs.net",              "Roku",               1),

    ("googlecast.tools",          "Chromecast",         1),
    ("chromecast.com",            "Chromecast",         1),

    ("amazonfiretv.com",          "Amazon Fire TV",     1),
    ("ftvgames.amazon.com",       "Amazon Fire TV",     1),

    # NVIDIA Shield specifically -- the cloud APIs only Shield boxes hit.
    ("shield.nvidia.com",         "NVIDIA Shield",      1),
    ("gfe.nvidia.com",            "NVIDIA / GeForce",   2),  # also gaming PCs
    ("geforce.com",               "NVIDIA / GeForce",   2),  # also gaming PCs
    ("nvidia.com",                "NVIDIA / GeForce",   3),  # weak: any NV box

    # ---------- Game consoles --------------------------------------
    ("xboxlive.com",              "Xbox",               1),
    ("xbox.com",                  "Xbox",               1),
    ("playstation.net",           "PlayStation",        1),
    ("scee.net",                  "PlayStation",        1),
    ("nintendo.net",              "Nintendo Switch",    1),

    # ---------- Smart home -----------------------------------------
    ("nest.com",                  "Google Nest",        1),
    ("nestlabs.com",              "Google Nest",        1),
    ("nestmtx.com",               "Google Nest",        1),
    ("dropcam.com",               "Google Nest Cam",    1),
    ("home.google.com",           "Google Home",        1),

    ("meethue.com",               "Philips Hue",        1),
    ("philips-hue.com",           "Philips Hue",        1),

    ("ring.com",                  "Ring",               1),
    ("ringgateway.com",           "Ring",               1),

    ("eufylife.com",              "Eufy",               1),
    ("wyzecam.com",               "Wyze Cam",           1),
    ("tuyaeu.com",                "Tuya / Smart Life",  1),
    ("tuyaus.com",                "Tuya / Smart Life",  1),
    ("tuyacn.com",                "Tuya / Smart Life",  1),
    ("lifx.co",                   "LIFX",               1),

    ("tplinkcloud.com",           "TP-Link / Tapo",     1),
    ("tplinkra.com",              "TP-Link / Tapo",     1),
    ("tplinkshield.com",          "TP-Link / Tapo",     1),

    ("smartthings.com",           "Samsung SmartThings", 1),
    ("hubitat.com",               "Hubitat hub",        1),

    # ---------- Audio ----------------------------------------------
    ("sonos.com",                 "Sonos",              1),
    ("sonosapi.com",              "Sonos",              1),
    ("sonosws.com",               "Sonos",              1),
    ("bose.com",                  "Bose speaker",       1),
    ("denon.com",                 "AV receiver",        2),
    ("marantz.com",               "AV receiver",        2),

    # ---------- Printers -------------------------------------------
    ("hpconnect.com",             "HP printer",         1),
    ("hpprintos.com",             "HP printer",         1),
    ("epsonconnect.com",          "Epson printer",      1),
    ("brother-print.com",         "Brother printer",    1),
    ("canon-jp.com",              "Canon printer",      1),

    # ---------- Storage / homelab ----------------------------------
    ("synology.com",              "Synology NAS",       1),
    ("qnap.com",                  "QNAP NAS",           1),
    ("proxmox.com",               "Proxmox host",       1),

    # ---------- Wearables / fitness --------------------------------
    ("garmin.com",                "Garmin device",      1),
    ("fitbit.com",                "Fitbit",             1),

    # ---------- Cars -----------------------------------------------
    ("tesla.com",                 "Tesla",              1),
    ("teslamotors.com",           "Tesla",              1),
    ("vw-cargroup.com",           "Volkswagen / Audi",  1),
    ("bmwgroup.com",              "BMW",                1),

    # ---------- Apple (vendor; tier 2 unless TV-specific above) ---
    ("icloud-content.com",        "Apple device",       2),
    ("icloud.com",                "Apple device",       2),
    ("itunes.apple.com",          "Apple device",       2),
    ("mzstatic.com",              "Apple device",       2),
    ("gs.apple.com",              "Apple device",       2),
    ("time.apple.com",            "Apple device",       2),
    ("apple.com",                 "Apple device",       2),

    # ---------- Android / ChromeOS / Google ------------------------
    ("mtalk.google.com",          "Android",            2),
    ("android.googleapis.com",    "Android",            2),
    ("time.android.com",          "Android",            2),
    ("connectivitycheck.gstatic.com", "Android",        2),

    # ---------- Windows --------------------------------------------
    ("windowsupdate.com",         "Windows PC",         2),
    ("update.microsoft.com",      "Windows PC",         2),
    ("events.data.microsoft.com", "Windows PC",         2),
    ("time.windows.com",          "Windows PC",         2),
    ("settings-win.data.microsoft.com", "Windows PC",   2),

    # ---------- Linux distros / package managers -------------------
    ("ubuntu.com",                "Linux box",          2),
    ("debian.org",                "Linux box",          2),
    ("snapcraft.io",              "Linux box",          2),
    ("packages.fedoraproject.org", "Linux box",         2),
    ("pypi.org",                  "Linux/dev box",      2),
    ("dl.k8s.io",                 "Linux/k8s host",     2),

    # ---------- Streaming traffic (tier 3 = weak hint) -------------
    ("nflxvideo.net",             "Streaming device",   3),
    ("googlevideo.com",           "Streaming device",   3),
]


async def identify_device(
    ip: str,
    *,
    mac: str | None,
    technitium,                       # TechnitiumClient
    sample_size: int = 200,
) -> dict[str, str | None]:
    """Compute the best-guess vendor (from MAC OUI) and device-type
    hint (from a sample of recent qnames) for one device.

    Network-bound work: a single Technitium ``/api/logs/query`` call.
    Returns ``{"vendor": ..., "hint": ...}`` -- either may be None.
    Never raises: failures degrade to ``None``.
    """
    from . import oui as _oui

    vendor = _oui.vendor_for(mac)
    hint: str | None = None
    try:
        resp = await technitium.query_logs(
            client_ip=ip, entries_per_page=sample_size,
        )
        qnames = [
            (e.get("qname") or "")
            for e in (resp.get("entries") or [])
        ]
        hint = hint_from_qnames(qnames)
    except Exception:  # noqa: BLE001
        # Fingerprinting is best-effort -- never bubble up to the
        # caller. The reconciler / API layer logs it.
        pass

    return {"vendor": vendor, "hint": hint}


def hint_from_qnames(qnames: Iterable[str]) -> str | None:
    """Return the best-guess device-type label for a sample of recently
    queried domain names. Returns ``None`` when nothing matched.

    The rule with the lowest tier (most specific) and the highest
    distinct-qname match count wins. Ties prefer earlier rules.
    """
    # rule_idx -> set of distinct qnames it matched
    matches: dict[int, set[str]] = {}
    for q in qnames:
        ql = (q or "").lower()
        if not ql:
            continue
        for idx, (needle, _label, _tier) in enumerate(RULES):
            if needle in ql:
                matches.setdefault(idx, set()).add(ql)
                # Don't break: a single qname might satisfy several
                # rules (e.g. "tvplus.apple.com" matches both the
                # Apple-TV-specific and the generic apple.com rule).
                # Counting separately is fine; the tier-then-count
                # ranking sorts it out.
    if not matches:
        return None
    best: tuple[int, int, int, str] | None = None  # (tier, -count, idx, label)
    for idx, qs in matches.items():
        _needle, label, tier = RULES[idx]
        key = (tier, -len(qs), idx, label)
        if best is None or key < best:
            best = key
    return best[3] if best else None
