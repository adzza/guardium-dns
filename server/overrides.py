"""Override-resolution engine.

Pure functions only. Given a snapshot of state (devices, people, base profiles,
schedules, quotas, manual overrides, current usage, wall clock) it returns:

    effective: dict[ip, profile_id]   # what each device's profile *should* be
    reasons:   dict[ip, OverrideTrace] # why -- for the UI

Everything is deterministic and side-effect free so the reconciler can run it
on every tick without ordering hazards. The reconciler is responsible for
turning ``effective`` into ``setNetworkGroupMap`` calls and for *creating*
override rows when schedules/quotas fire.

Source priority (highest wins):

    1. ``manual``        - user pressed pause/kill/etc.
    2. ``family-pause``  - whole-family transient pause
    3. ``quota``         - daily-quota exceeded
    4. ``schedule``      - bedtime / homework hours
    5. base profile      - the device's (or person's) configured baseline
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Iterable

# Sentinel meaning "internet-off"; we use the literal profile id so the
# reconciler maps it onto the existing managed group "internet-off".
INTERNET_OFF = "internet-off"

# Source priority - higher number wins. Mirrors the docstring above.
SOURCE_PRIORITY = {
    "manual":        100,
    "family-pause":   80,
    "quota":          60,
    "schedule":       40,
}


@dataclass
class OverrideTrace:
    """Why a particular device ended up with the profile it did."""
    profile_id: str | None
    source: str  # 'base' | 'manual' | 'schedule' | 'quota' | 'family-pause' | 'no-profile'
    detail: str | None = None
    expires_at: int | None = None
    person_id: int | None = None


def weekday_active(mask: int, weekday: int) -> bool:
    """Mon=0 .. Sun=6 against a 7-bit mask. 0 means 'no days', 0x7F means all."""
    return bool(mask & (1 << weekday))


def schedule_window_active(now_local: datetime, weekday_mask: int,
                            start_min: int, end_min: int) -> bool:
    """Is ``now_local`` inside the schedule's window?

    If ``end_min < start_min`` the window wraps past midnight (e.g. 22:00 -> 06:00).
    The starting weekday is the day-of-week that opens the window.
    """
    minute_now = now_local.hour * 60 + now_local.minute
    weekday_today = now_local.weekday()
    if start_min < end_min:
        # Same-day window.
        if not weekday_active(weekday_mask, weekday_today):
            return False
        return start_min <= minute_now < end_min
    if start_min == end_min:
        # Convention: zero-length window means disabled.
        return False
    # Overnight: window starts today, ends tomorrow.
    weekday_yesterday = (weekday_today - 1) % 7
    if weekday_active(weekday_mask, weekday_today) and minute_now >= start_min:
        return True
    if weekday_active(weekday_mask, weekday_yesterday) and minute_now < end_min:
        return True
    return False


@dataclass
class TargetState:
    """All inputs that decide what a device or person should be on right now."""
    base_profile_id: str | None
    schedules: list[dict] = field(default_factory=list)
    quotas: list[dict] = field(default_factory=list)
    overrides: list[dict] = field(default_factory=list)  # active rows from device_overrides
    daily_usage_minutes: int = 0


def _pick_active_schedule(schedules: Iterable[dict], now_local: datetime) -> dict | None:
    """Highest-id active schedule wins (assumes most-recently-added is most specific).
    Returns None if no schedule is active."""
    candidates = []
    for s in schedules:
        if not s.get("enabled"):
            continue
        if schedule_window_active(now_local, s["weekday_mask"], s["start_min"], s["end_min"]):
            candidates.append(s)
    if not candidates:
        return None
    return max(candidates, key=lambda s: s["id"])


def _quota_exceeded(quotas: Iterable[dict], usage_minutes: int,
                     now_local: datetime) -> dict | None:
    """Return the first enabled quota whose budget is exceeded today, else None."""
    weekday = now_local.weekday()
    for q in quotas:
        if not q.get("enabled"):
            continue
        if not weekday_active(q["weekday_mask"], weekday):
            continue
        if usage_minutes >= q["minutes_max"]:
            return q
    return None


def resolve_target(state: TargetState, *, now_local: datetime, now_utc: int,
                    person_id: int | None = None) -> OverrideTrace:
    """Resolve a single target (device OR person) to its effective profile."""
    # 1. manual / family-pause / quota / schedule overrides from the table -
    #    pre-recorded by either the user (manual / family-pause) or the
    #    reconciler itself (schedule / quota). Highest priority wins.
    active = [o for o in state.overrides if o["expires_at"] > now_utc]
    if active:
        active.sort(key=lambda o: (-SOURCE_PRIORITY.get(o["source"], 0), -o["id"]))
        top = active[0]
        return OverrideTrace(
            profile_id=top["profile_id"] if top["profile_id"] else INTERNET_OFF,
            source=top["source"],
            detail=top.get("note"),
            expires_at=top["expires_at"],
            person_id=person_id,
        )

    # 2. Live schedule check (the reconciler will *also* mirror this into a row,
    #    but that happens after this function returns; we still need to know
    #    "is a schedule active right now?" so we do it inline).
    sched = _pick_active_schedule(state.schedules, now_local)
    if sched is not None:
        return OverrideTrace(
            profile_id=sched["profile_id"] if sched["profile_id"] else INTERNET_OFF,
            source="schedule",
            detail=sched.get("name") or f"schedule#{sched['id']}",
            person_id=person_id,
        )

    # 3. Quota check.
    q = _quota_exceeded(state.quotas, state.daily_usage_minutes, now_local)
    if q is not None:
        return OverrideTrace(
            profile_id=q["profile_when_exceeded"] if q["profile_when_exceeded"] else INTERNET_OFF,
            source="quota",
            detail=q.get("name") or f"quota#{q['id']}",
            person_id=person_id,
        )

    # 4. Base profile (or unset).
    return OverrideTrace(
        profile_id=state.base_profile_id,
        source="base" if state.base_profile_id else "no-profile",
        person_id=person_id,
    )


def merge_person_into_device(device_trace: OverrideTrace,
                              person_trace: OverrideTrace | None) -> OverrideTrace:
    """If a device belongs to a person, the more-restrictive of the two wins.

    Restrictiveness order (most -> least): internet-off > kids > no-streaming
    > no-gaming > no-youtube > default > unrestricted > None. Source priority
    still beats baseline ordering: a manual person-pause beats the device's
    base unrestricted profile.
    """
    if person_trace is None:
        return device_trace

    # If the person has a non-base override, person wins outright.
    if person_trace.source not in ("base", "no-profile"):
        return person_trace

    # Otherwise pick the more-restrictive base.
    return _more_restrictive(device_trace, person_trace)


# Lower index in this list = more restrictive. Profiles outside the list are
# treated as "least restrictive" (after unrestricted).
_RESTRICTION_ORDER = [
    INTERNET_OFF,
    "kids",
    "no-streaming",
    "no-gaming",
    "no-youtube",
    "default",
    "unrestricted",
]


def _restriction_rank(profile_id: str | None) -> int:
    if profile_id is None:
        return len(_RESTRICTION_ORDER)  # least restrictive
    try:
        return _RESTRICTION_ORDER.index(profile_id)
    except ValueError:
        return len(_RESTRICTION_ORDER) - 1


def _more_restrictive(a: OverrideTrace, b: OverrideTrace) -> OverrideTrace:
    return a if _restriction_rank(a.profile_id) <= _restriction_rank(b.profile_id) else b


def local_today(now_local: datetime | None = None) -> str:
    d = (now_local or datetime.now()).date()
    return d.isoformat()


def end_of_local_day(now_local: datetime | None = None) -> int:
    """UTC seconds at the next local midnight."""
    now_local = now_local or datetime.now()
    next_midnight_local = datetime.combine(
        date.fromordinal(now_local.toordinal() + 1),
        datetime.min.time(),
    )
    # localtime -> epoch
    return int(time.mktime(next_midnight_local.timetuple()))
