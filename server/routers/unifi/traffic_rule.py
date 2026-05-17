"""Pure JSON builders for UniFi Traffic Rules.

Two rules are managed by Guardium:

- A **kill switch** rule (Stage 1): action ``BLOCK``,
  ``matching_target = "INTERNET"``, ``target_devices`` = the MACs
  whose effective profile is ``internet-off``.
- A **DoH/DoT block** rule (Stage 3): action ``BLOCK``,
  ``matching_target = "APP"``, ``app_ids`` = the DPI IDs we found in
  :mod:`.doh_apps`, ``target_devices`` = MACs on any managed profile
  other than ``unrestricted`` / ``internet-off``.

The v2 Traffic-Rule endpoint isn't officially documented; the schema
below is the intersection of:

- The UniFi web app's own request payloads (observed live).
- The Terraform ``resnickio/unifi`` provider's ``unifi_traffic_rule``
  resource definition.

We send a deliberately minimal payload -- only the fields the
controller has been observed to *require* -- and let the controller
fill in defaults for everything else. Anything we DO send must match
the firmware's expectations exactly, including casing.

Naming: every Guardium-managed rule starts with the prefix below so
the user can tell them apart at a glance in the UniFi UI, and so a
future tear-down can reliably find and delete them by name if the
cached ``_id`` is somehow lost.
"""
from __future__ import annotations

from typing import Any


MANAGED_RULE_PREFIX = "Guardium "
KILL_SWITCH_NAME = MANAGED_RULE_PREFIX + "Internet Off"
DOH_BLOCK_NAME = MANAGED_RULE_PREFIX + "Block Encrypted DNS"
MANAGED_DESCRIPTION = (
    "Managed by Guardium DNS. Do not edit by hand -- changes will be "
    "overwritten on the next reconcile tick."
)


def _target_devices(macs: list[str]) -> list[dict[str, str]]:
    """``target_devices`` array entries for a list of client MACs.

    Normalises MACs to lowercase ``aa:bb:cc:dd:ee:ff`` form. The
    controller is permissive but the Terraform provider's API
    fixtures all use this shape, which is what the UniFi UI itself
    POSTs when you build a rule by hand.
    """
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for raw in macs:
        if not raw:
            continue
        m = raw.replace("-", ":").strip().lower()
        if ":" not in m or m in seen:
            continue
        seen.add(m)
        out.append({"type": "CLIENT", "client_mac": m})
    return out


def _base_rule(name: str, *, enabled: bool = True) -> dict[str, Any]:
    """Common envelope shared by every managed rule."""
    return {
        "name": name,
        "description": MANAGED_DESCRIPTION,
        "enabled": enabled,
        "action": "BLOCK",
        "schedule": {
            # ALWAYS-on rule; Guardium does its own time-of-day
            # scheduling via Technitium so the router doesn't need to.
            "mode": "ALWAYS",
            "repeat_on_days": [],
            "time_all_day": False,
            "time_range_start": "09:00",
            "time_range_end": "17:00",
        },
        "bandwidth_limit": {
            "download_limit_kbps": 1024,
            "enabled": False,
            "upload_limit_kbps": 1024,
        },
        "ip_addresses": [],
        "ip_ranges": [],
        "network_ids": [],
        "regions": [],
        "match_opposite_protocol": False,
        "match_opposite_ports": False,
    }


def build_kill_switch_rule(
    macs: list[str],
    *,
    name: str = KILL_SWITCH_NAME,
    enabled: bool = True,
) -> dict[str, Any]:
    """JSON body for the Stage-1 'block all Internet' rule.

    Passing an empty ``macs`` list yields an *enabled-false* rule with
    an empty target set, which is what we want for the soft tear-down
    path (preserve the row so we keep the cached ``_id``, but make it
    a no-op).
    """
    devices = _target_devices(macs)
    rule = _base_rule(name, enabled=enabled and bool(devices))
    rule.update({
        "matching_target": "INTERNET",
        "target_devices": devices,
        "app_category_ids": [],
        "app_ids": [],
        "domains": [],
    })
    return rule


def build_doh_block_rule(
    macs: list[str],
    app_ids: list[str],
    *,
    name: str = DOH_BLOCK_NAME,
    enabled: bool = True,
) -> dict[str, Any]:
    """JSON body for the Stage-3 'block DoH/DoT' rule.

    Same tear-down semantics as :func:`build_kill_switch_rule`: empty
    macs OR empty app_ids -> disabled rule (so we don't accidentally
    block app traffic for every device on the network).
    """
    devices = _target_devices(macs)
    clean_app_ids = [str(x) for x in app_ids if x is not None]
    rule = _base_rule(
        name,
        enabled=enabled and bool(devices) and bool(clean_app_ids),
    )
    rule.update({
        "matching_target": "APP",
        "target_devices": devices,
        "app_ids": clean_app_ids,
        "app_category_ids": [],
        "domains": [],
    })
    return rule


def is_managed_rule(rule: dict[str, Any]) -> bool:
    """Heuristic: ``True`` if this looks like a rule Guardium created.

    Used during reconciliation to find an existing managed row when
    the cached ``_id`` setting is gone (process moved hosts, etc.).
    Matches on the rule name prefix -- a user is free to rename their
    own rules but the prefix ``"Guardium "`` is documented as reserved.
    """
    name = str(rule.get("name") or "")
    return name.startswith(MANAGED_RULE_PREFIX)
