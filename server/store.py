"""Local SQLite store for Guardium DNS.

Owns:
- `devices` (label, hostname-derived label, favourite, base profile)
- `people` (named family members with their own base profile)
- `person_devices` (which devices belong to which person)
- `device_overrides` (transient profile overrides with priority + expiry)
- `schedules` (recurring weekday windows that produce overrides)
- `quotas` (daily-minute caps that produce overrides when exceeded)
- `daily_usage` and `daily_app_usage` (5-minute sampler buckets)
- `audit` (administrator action log)

Every table uses simple SQLite types. Migrations are applied lazily on
startup so we never need an Alembic-style migration runner.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


_BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    ip                TEXT PRIMARY KEY,
    label             TEXT,
    notes             TEXT,
    favourite         INTEGER NOT NULL DEFAULT 0,
    fav_order         INTEGER NOT NULL DEFAULT 0,
    base_profile_id   TEXT,
    person_id         INTEGER,
    mac_address       TEXT,
    first_seen        INTEGER,
    last_seen         INTEGER
);

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS people (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    avatar          TEXT,
    color           TEXT,
    base_profile_id TEXT,
    sort_order      INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS device_overrides (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_kind TEXT NOT NULL,           -- 'device' | 'person'
    target_id   TEXT NOT NULL,           -- ip for device, str(person.id) for person
    profile_id  TEXT,                    -- null = "internet-off" overlay
    source      TEXT NOT NULL,           -- 'manual' | 'pause' | 'schedule' | 'quota' | 'family-pause'
    starts_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,        -- absolute UTC seconds
    created_by  TEXT,
    note        TEXT
);
CREATE INDEX IF NOT EXISTS idx_override_active ON device_overrides(target_kind, target_id, expires_at);

CREATE TABLE IF NOT EXISTS schedules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_kind TEXT NOT NULL,           -- 'device' | 'person' | 'all'
    target_id   TEXT,                    -- nullable for 'all'
    name        TEXT,                    -- optional human label e.g. "Bedtime"
    weekday_mask INTEGER NOT NULL,       -- 7-bit mask (Mon=0 ... Sun=6)
    start_min   INTEGER NOT NULL,        -- 0..1439, local time
    end_min     INTEGER NOT NULL,        -- 0..1439 (may wrap past midnight if < start)
    profile_id  TEXT,                    -- profile to apply (null = internet-off)
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS quotas (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_kind TEXT NOT NULL,           -- 'device' | 'person'
    target_id   TEXT NOT NULL,
    name        TEXT,
    weekday_mask INTEGER NOT NULL,
    minutes_max INTEGER NOT NULL,
    profile_when_exceeded TEXT,          -- profile to swap to (null=internet-off)
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS daily_usage (
    target_kind TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    date_local  TEXT NOT NULL,           -- YYYY-MM-DD in server local TZ
    active_minutes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (target_kind, target_id, date_local)
);

CREATE TABLE IF NOT EXISTS daily_app_usage (
    target_kind TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    date_local  TEXT NOT NULL,
    app_id      TEXT NOT NULL,
    active_minutes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (target_kind, target_id, date_local, app_id)
);

CREATE TABLE IF NOT EXISTS audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    actor   TEXT,
    ip      TEXT,
    action  TEXT,
    detail  TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts DESC);
"""


def _migrate(cx: sqlite3.Connection) -> None:
    """Apply column-level migrations idempotently for upgrade paths."""
    existing = {row["name"] for row in cx.execute("PRAGMA table_info(devices)").fetchall()}
    if "favourite" not in existing:
        cx.execute("ALTER TABLE devices ADD COLUMN favourite INTEGER NOT NULL DEFAULT 0")
    if "fav_order" not in existing:
        cx.execute("ALTER TABLE devices ADD COLUMN fav_order INTEGER NOT NULL DEFAULT 0")
    if "base_profile_id" not in existing:
        cx.execute("ALTER TABLE devices ADD COLUMN base_profile_id TEXT")
    if "person_id" not in existing:
        cx.execute("ALTER TABLE devices ADD COLUMN person_id INTEGER")
    if "mac_address" not in existing:
        cx.execute("ALTER TABLE devices ADD COLUMN mac_address TEXT")
    # Fingerprint enrichment (vendor from OUI; device-type hint from
    # DNS query patterns). All optional.
    if "vendor" not in existing:
        cx.execute("ALTER TABLE devices ADD COLUMN vendor TEXT")
    if "fingerprint_hint" not in existing:
        cx.execute("ALTER TABLE devices ADD COLUMN fingerprint_hint TEXT")
    if "fingerprint_inferred_at" not in existing:
        cx.execute("ALTER TABLE devices ADD COLUMN fingerprint_inferred_at INTEGER")

    cx.execute("CREATE INDEX IF NOT EXISTS idx_dev_fav ON devices(favourite, fav_order)")
    cx.execute("CREATE INDEX IF NOT EXISTS idx_dev_person ON devices(person_id)")
    cx.execute("CREATE INDEX IF NOT EXISTS idx_dev_mac ON devices(mac_address)")


class Store:
    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as cx:
            cx.executescript(_BASE_SCHEMA)
            _migrate(cx)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        cx = sqlite3.connect(self._path, isolation_level=None)
        cx.row_factory = sqlite3.Row
        try:
            yield cx
        finally:
            cx.close()

    # ------------------------------------------------------------------ devices

    def upsert_device(self, ip: str, *, label: str | None = None, notes: str | None = None) -> None:
        now = int(time.time())
        with self._lock, self._connect() as cx:
            cx.execute(
                """
                INSERT INTO devices(ip, label, notes, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    label = COALESCE(excluded.label, devices.label),
                    notes = COALESCE(excluded.notes, devices.notes),
                    last_seen = excluded.last_seen
                """,
                (ip, label, notes, now, now),
            )

    def touch_device(self, ip: str) -> None:
        now = int(time.time())
        with self._lock, self._connect() as cx:
            cx.execute(
                """
                INSERT INTO devices(ip, first_seen, last_seen)
                VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen
                """,
                (ip, now, now),
            )

    def update_label(self, ip: str, label: str | None, notes: str | None = None) -> None:
        now = int(time.time())
        with self._lock, self._connect() as cx:
            cx.execute(
                """
                INSERT INTO devices(ip, label, notes, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    label = excluded.label,
                    notes = excluded.notes,
                    last_seen = excluded.last_seen
                """,
                (ip, label, notes, now, now),
            )

    def set_device_mac(self, ip: str, mac: str | None) -> None:
        now = int(time.time())
        normalised = mac.lower().replace("-", ":") if mac else None
        with self._lock, self._connect() as cx:
            cx.execute(
                """INSERT INTO devices(ip, mac_address, first_seen, last_seen)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(ip) DO UPDATE SET
                       mac_address = excluded.mac_address,
                       last_seen = excluded.last_seen""",
                (ip, normalised, now, now),
            )

    def set_device_fingerprint(
        self,
        ip: str,
        *,
        vendor: str | None = None,
        hint: str | None = None,
        clear: bool = False,
    ) -> None:
        """Persist the inferred vendor / device-type hint for a device.
        If ``clear`` is true, both fields are nulled regardless of the
        ``vendor`` and ``hint`` arguments.
        """
        now = int(time.time())
        if clear:
            vendor = None
            hint = None
        with self._lock, self._connect() as cx:
            cx.execute(
                """INSERT INTO devices(ip, vendor, fingerprint_hint,
                           fingerprint_inferred_at, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(ip) DO UPDATE SET
                       vendor = excluded.vendor,
                       fingerprint_hint = excluded.fingerprint_hint,
                       fingerprint_inferred_at = excluded.fingerprint_inferred_at,
                       last_seen = excluded.last_seen""",
                (ip, vendor, hint, now, now, now),
            )

    def devices_needing_fingerprint(self, *, max_age_seconds: int) -> list[dict]:
        """Return rows whose fingerprint is missing or older than
        ``max_age_seconds``. Used by the background refresher so we
        don't pummel Technitium with redundant log queries.
        """
        cutoff = int(time.time()) - max_age_seconds
        with self._connect() as cx:
            rows = cx.execute(
                """SELECT * FROM devices
                   WHERE fingerprint_inferred_at IS NULL
                      OR fingerprint_inferred_at < ?
                   ORDER BY last_seen DESC""",
                (cutoff,),
            ).fetchall()
        return [dict(r) for r in rows]

    def follow_device_to_new_ip(self, mac: str, new_ip: str) -> dict[str, Any]:
        """Migrate a device row anchored to ``mac`` from its current IP to
        ``new_ip``. Used when the router tells us the same MAC has just
        appeared on a different DHCP lease.

        All device-keyed state (overrides, schedules, quotas, daily usage)
        moves with the row. Any pre-existing **blank** row at ``new_ip``
        (one created by the sampler when it first saw queries from that
        IP, before we knew the MAC) is replaced. If the new IP already had
        its own configured row, the *old* row's profile/person/label win
        — those were anchored to the device by MAC.

        No-op when the MAC is unknown or already lives at ``new_ip``.
        Returns ``{"migrated": True, "old_ip": ..., "merged_blank_new":
        bool}`` on success, ``{"migrated": False}`` otherwise.
        """
        if not mac or not new_ip:
            return {"migrated": False}
        norm_mac = mac.lower().replace("-", ":")
        now = int(time.time())
        with self._lock, self._connect() as cx:
            cx.execute("BEGIN")
            try:
                row = cx.execute(
                    "SELECT * FROM devices WHERE mac_address = ? AND ip != ?",
                    (norm_mac, new_ip),
                ).fetchone()
                if not row:
                    cx.execute("COMMIT")
                    return {"migrated": False}
                old_ip = row["ip"]
                existing_new = cx.execute(
                    "SELECT * FROM devices WHERE ip = ?", (new_ip,),
                ).fetchone()

                # OLD row wins (it's the MAC-anchored truth). Fall back to
                # whatever the BLANK new-ip row had only when the old row
                # didn't have that field set.
                def _pick(field: str) -> Any:
                    val = row[field]
                    if val in (None, "", 0):
                        if existing_new is not None and existing_new[field] not in (None, "", 0):
                            return existing_new[field]
                    return val

                label                   = _pick("label")
                notes                   = _pick("notes")
                base_profile_id         = _pick("base_profile_id")
                person_id               = _pick("person_id")
                vendor                  = _pick("vendor")
                fingerprint_hint        = _pick("fingerprint_hint")
                fingerprint_inferred_at = _pick("fingerprint_inferred_at")
                favourite               = row["favourite"] or (existing_new["favourite"] if existing_new else 0)
                fav_order               = row["fav_order"] or (existing_new["fav_order"] if existing_new else 0)
                first_seen              = row["first_seen"] or (existing_new["first_seen"] if existing_new else now)

                # Drop both old and existing-new rows, then insert the
                # merged row at new_ip. This avoids PK collisions and
                # cleanly handles the (common) "blank sampler row at
                # new_ip" case.
                cx.execute("DELETE FROM devices WHERE ip = ?", (new_ip,))
                cx.execute("DELETE FROM devices WHERE ip = ?", (old_ip,))
                cx.execute(
                    """INSERT INTO devices(ip, label, notes, favourite, fav_order,
                           base_profile_id, person_id, mac_address,
                           vendor, fingerprint_hint, fingerprint_inferred_at,
                           first_seen, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (new_ip, label, notes, favourite, fav_order,
                     base_profile_id, person_id, norm_mac,
                     vendor, fingerprint_hint, fingerprint_inferred_at,
                     first_seen, now),
                )

                # Move device-keyed records (no unique constraints on
                # target_id, so plain UPDATEs are safe).
                cx.execute(
                    """UPDATE device_overrides SET target_id = ?
                       WHERE target_kind='device' AND target_id = ?""",
                    (new_ip, old_ip),
                )
                cx.execute(
                    """UPDATE schedules SET target_id = ?
                       WHERE target_kind='device' AND target_id = ?""",
                    (new_ip, old_ip),
                )
                cx.execute(
                    """UPDATE quotas SET target_id = ?
                       WHERE target_kind='device' AND target_id = ?""",
                    (new_ip, old_ip),
                )

                # Daily usage has a UNIQUE PK on (kind, id, date), so we
                # have to merge by sum rather than UPDATE.
                old_usage = cx.execute(
                    """SELECT date_local, active_minutes FROM daily_usage
                       WHERE target_kind='device' AND target_id = ?""",
                    (old_ip,),
                ).fetchall()
                for r in old_usage:
                    cx.execute(
                        """INSERT INTO daily_usage(target_kind, target_id, date_local, active_minutes)
                           VALUES ('device', ?, ?, ?)
                           ON CONFLICT(target_kind, target_id, date_local) DO UPDATE SET
                               active_minutes = active_minutes + excluded.active_minutes""",
                        (new_ip, r["date_local"], int(r["active_minutes"])),
                    )
                cx.execute(
                    "DELETE FROM daily_usage WHERE target_kind='device' AND target_id = ?",
                    (old_ip,),
                )

                old_app = cx.execute(
                    """SELECT date_local, app_id, active_minutes FROM daily_app_usage
                       WHERE target_kind='device' AND target_id = ?""",
                    (old_ip,),
                ).fetchall()
                for r in old_app:
                    cx.execute(
                        """INSERT INTO daily_app_usage(target_kind, target_id, date_local, app_id, active_minutes)
                           VALUES ('device', ?, ?, ?, ?)
                           ON CONFLICT(target_kind, target_id, date_local, app_id) DO UPDATE SET
                               active_minutes = active_minutes + excluded.active_minutes""",
                        (new_ip, r["date_local"], r["app_id"], int(r["active_minutes"])),
                    )
                cx.execute(
                    "DELETE FROM daily_app_usage WHERE target_kind='device' AND target_id = ?",
                    (old_ip,),
                )

                cx.execute("COMMIT")
            except Exception:
                cx.execute("ROLLBACK")
                raise

        return {
            "migrated": True,
            "mac": norm_mac,
            "old_ip": old_ip,
            "new_ip": new_ip,
            "merged_blank_new": existing_new is not None,
        }

    def set_device_base_profile(self, ip: str, profile_id: str | None) -> None:
        now = int(time.time())
        with self._lock, self._connect() as cx:
            cx.execute(
                """INSERT INTO devices(ip, base_profile_id, first_seen, last_seen)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(ip) DO UPDATE SET
                       base_profile_id = excluded.base_profile_id,
                       last_seen = excluded.last_seen""",
                (ip, profile_id, now, now),
            )

    def get_device(self, ip: str) -> dict | None:
        with self._connect() as cx:
            row = cx.execute("SELECT * FROM devices WHERE ip = ?", (ip,)).fetchone()
        return dict(row) if row else None

    def all_devices(self) -> list[dict]:
        with self._connect() as cx:
            rows = cx.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
        return [dict(r) for r in rows]

    def set_favourite(self, ip: str, favourite: bool) -> None:
        now = int(time.time())
        with self._lock, self._connect() as cx:
            existing = cx.execute("SELECT 1 FROM devices WHERE ip = ?", (ip,)).fetchone()
            order = 0
            if favourite:
                row = cx.execute(
                    "SELECT COALESCE(MAX(fav_order), 0) AS m FROM devices WHERE favourite = 1"
                ).fetchone()
                order = (row["m"] if row else 0) + 1
            if existing:
                cx.execute(
                    "UPDATE devices SET favourite = ?, fav_order = ?, last_seen = ? WHERE ip = ?",
                    (1 if favourite else 0, order, now, ip),
                )
            else:
                cx.execute(
                    """INSERT INTO devices(ip, favourite, fav_order, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, ?)""",
                    (ip, 1 if favourite else 0, order, now, now),
                )

    # ------------------------------------------------------------------- people

    def all_people(self) -> list[dict]:
        with self._connect() as cx:
            rows = cx.execute("SELECT * FROM people ORDER BY sort_order, name").fetchall()
        return [dict(r) for r in rows]

    def get_person(self, person_id: int) -> dict | None:
        with self._connect() as cx:
            row = cx.execute("SELECT * FROM people WHERE id = ?", (person_id,)).fetchone()
        return dict(row) if row else None

    def create_person(self, *, name: str, avatar: str | None, color: str | None,
                      base_profile_id: str | None = None) -> dict:
        now = int(time.time())
        with self._lock, self._connect() as cx:
            row = cx.execute("SELECT COALESCE(MAX(sort_order),0) AS m FROM people").fetchone()
            order = (row["m"] if row else 0) + 1
            cur = cx.execute(
                """INSERT INTO people(name, avatar, color, base_profile_id, sort_order, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (name, avatar, color, base_profile_id, order, now),
            )
            new_id = cur.lastrowid
            return dict(cx.execute("SELECT * FROM people WHERE id = ?", (new_id,)).fetchone())

    def update_person(self, person_id: int, **fields: Any) -> dict | None:
        if not fields:
            return self.get_person(person_id)
        cols = []
        vals: list[Any] = []
        for col in ("name", "avatar", "color", "base_profile_id", "sort_order"):
            if col in fields:
                cols.append(f"{col} = ?")
                vals.append(fields[col])
        if not cols:
            return self.get_person(person_id)
        vals.append(person_id)
        with self._lock, self._connect() as cx:
            cx.execute(f"UPDATE people SET {', '.join(cols)} WHERE id = ?", vals)
        return self.get_person(person_id)

    def delete_person(self, person_id: int) -> None:
        with self._lock, self._connect() as cx:
            cx.execute("UPDATE devices SET person_id = NULL WHERE person_id = ?", (person_id,))
            cx.execute("DELETE FROM people WHERE id = ?", (person_id,))
            cx.execute(
                "DELETE FROM device_overrides WHERE target_kind = 'person' AND target_id = ?",
                (str(person_id),),
            )
            cx.execute(
                "DELETE FROM schedules WHERE target_kind = 'person' AND target_id = ?",
                (str(person_id),),
            )
            cx.execute(
                "DELETE FROM quotas WHERE target_kind = 'person' AND target_id = ?",
                (str(person_id),),
            )

    def attach_device_to_person(self, ip: str, person_id: int | None) -> None:
        now = int(time.time())
        with self._lock, self._connect() as cx:
            cx.execute(
                """INSERT INTO devices(ip, person_id, first_seen, last_seen)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(ip) DO UPDATE SET
                       person_id = excluded.person_id,
                       last_seen = excluded.last_seen""",
                (ip, person_id, now, now),
            )

    def devices_for_person(self, person_id: int) -> list[dict]:
        with self._connect() as cx:
            rows = cx.execute(
                "SELECT * FROM devices WHERE person_id = ? ORDER BY favourite DESC, label",
                (person_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ----------------------------------------------------------------- overrides

    def add_override(self, *, target_kind: str, target_id: str, profile_id: str | None,
                     source: str, starts_at: int, expires_at: int,
                     created_by: str | None = None, note: str | None = None) -> int:
        with self._lock, self._connect() as cx:
            # Drop any existing same-source override for this target (one wins per source).
            cx.execute(
                """DELETE FROM device_overrides
                   WHERE target_kind = ? AND target_id = ? AND source = ?""",
                (target_kind, target_id, source),
            )
            cur = cx.execute(
                """INSERT INTO device_overrides
                   (target_kind, target_id, profile_id, source, starts_at, expires_at, created_by, note)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (target_kind, target_id, profile_id, source, starts_at, expires_at, created_by, note),
            )
            return cur.lastrowid

    def clear_overrides(self, *, target_kind: str, target_id: str,
                        sources: list[str] | None = None) -> int:
        with self._lock, self._connect() as cx:
            if sources:
                placeholders = ",".join(["?"] * len(sources))
                cur = cx.execute(
                    f"""DELETE FROM device_overrides
                        WHERE target_kind = ? AND target_id = ? AND source IN ({placeholders})""",
                    [target_kind, target_id, *sources],
                )
            else:
                cur = cx.execute(
                    "DELETE FROM device_overrides WHERE target_kind = ? AND target_id = ?",
                    (target_kind, target_id),
                )
            return cur.rowcount

    def active_overrides(self, now: int) -> list[dict]:
        with self._connect() as cx:
            rows = cx.execute(
                "SELECT * FROM device_overrides WHERE expires_at > ? ORDER BY id",
                (now,),
            ).fetchall()
        return [dict(r) for r in rows]

    def purge_expired_overrides(self, now: int) -> int:
        with self._lock, self._connect() as cx:
            cur = cx.execute(
                "DELETE FROM device_overrides WHERE expires_at <= ?",
                (now,),
            )
            return cur.rowcount

    # ----------------------------------------------------------------- schedules

    def all_schedules(self) -> list[dict]:
        with self._connect() as cx:
            rows = cx.execute("SELECT * FROM schedules ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def create_schedule(self, *, target_kind: str, target_id: str | None, name: str | None,
                        weekday_mask: int, start_min: int, end_min: int,
                        profile_id: str | None, enabled: bool = True) -> dict:
        now = int(time.time())
        with self._lock, self._connect() as cx:
            cur = cx.execute(
                """INSERT INTO schedules
                   (target_kind, target_id, name, weekday_mask, start_min, end_min,
                    profile_id, enabled, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (target_kind, target_id, name, weekday_mask, start_min, end_min,
                 profile_id, 1 if enabled else 0, now),
            )
            new_id = cur.lastrowid
            return dict(cx.execute("SELECT * FROM schedules WHERE id = ?", (new_id,)).fetchone())

    def update_schedule(self, schedule_id: int, **fields: Any) -> dict | None:
        if not fields:
            return self.get_schedule(schedule_id)
        cols = []
        vals: list[Any] = []
        for col in ("target_kind", "target_id", "name", "weekday_mask",
                    "start_min", "end_min", "profile_id", "enabled"):
            if col in fields:
                cols.append(f"{col} = ?")
                v = fields[col]
                if col == "enabled":
                    v = 1 if v else 0
                vals.append(v)
        if not cols:
            return self.get_schedule(schedule_id)
        vals.append(schedule_id)
        with self._lock, self._connect() as cx:
            cx.execute(f"UPDATE schedules SET {', '.join(cols)} WHERE id = ?", vals)
        return self.get_schedule(schedule_id)

    def get_schedule(self, schedule_id: int) -> dict | None:
        with self._connect() as cx:
            row = cx.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
        return dict(row) if row else None

    def delete_schedule(self, schedule_id: int) -> None:
        with self._lock, self._connect() as cx:
            cx.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))

    # -------------------------------------------------------------------- quotas

    def all_quotas(self) -> list[dict]:
        with self._connect() as cx:
            rows = cx.execute("SELECT * FROM quotas ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def create_quota(self, *, target_kind: str, target_id: str, name: str | None,
                     weekday_mask: int, minutes_max: int,
                     profile_when_exceeded: str | None = None,
                     enabled: bool = True) -> dict:
        now = int(time.time())
        with self._lock, self._connect() as cx:
            cur = cx.execute(
                """INSERT INTO quotas
                   (target_kind, target_id, name, weekday_mask, minutes_max,
                    profile_when_exceeded, enabled, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (target_kind, target_id, name, weekday_mask, minutes_max,
                 profile_when_exceeded, 1 if enabled else 0, now),
            )
            new_id = cur.lastrowid
            return dict(cx.execute("SELECT * FROM quotas WHERE id = ?", (new_id,)).fetchone())

    def update_quota(self, quota_id: int, **fields: Any) -> dict | None:
        if not fields:
            return self.get_quota(quota_id)
        cols = []
        vals: list[Any] = []
        for col in ("target_kind", "target_id", "name", "weekday_mask",
                    "minutes_max", "profile_when_exceeded", "enabled"):
            if col in fields:
                cols.append(f"{col} = ?")
                v = fields[col]
                if col == "enabled":
                    v = 1 if v else 0
                vals.append(v)
        if not cols:
            return self.get_quota(quota_id)
        vals.append(quota_id)
        with self._lock, self._connect() as cx:
            cx.execute(f"UPDATE quotas SET {', '.join(cols)} WHERE id = ?", vals)
        return self.get_quota(quota_id)

    def get_quota(self, quota_id: int) -> dict | None:
        with self._connect() as cx:
            row = cx.execute("SELECT * FROM quotas WHERE id = ?", (quota_id,)).fetchone()
        return dict(row) if row else None

    def delete_quota(self, quota_id: int) -> None:
        with self._lock, self._connect() as cx:
            cx.execute("DELETE FROM quotas WHERE id = ?", (quota_id,))

    # ---------------------------------------------------------------- daily usage

    def add_active_minutes(self, target_kind: str, target_id: str, date_local: str,
                            minutes: int) -> None:
        with self._lock, self._connect() as cx:
            cx.execute(
                """INSERT INTO daily_usage(target_kind, target_id, date_local, active_minutes)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(target_kind, target_id, date_local) DO UPDATE SET
                       active_minutes = active_minutes + excluded.active_minutes""",
                (target_kind, target_id, date_local, minutes),
            )

    def add_app_active_minutes(self, target_kind: str, target_id: str, date_local: str,
                                app_id: str, minutes: int) -> None:
        with self._lock, self._connect() as cx:
            cx.execute(
                """INSERT INTO daily_app_usage(target_kind, target_id, date_local, app_id, active_minutes)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(target_kind, target_id, date_local, app_id) DO UPDATE SET
                       active_minutes = active_minutes + excluded.active_minutes""",
                (target_kind, target_id, date_local, app_id, minutes),
            )

    def get_daily_usage(self, target_kind: str, target_id: str, date_local: str) -> int:
        with self._connect() as cx:
            row = cx.execute(
                """SELECT active_minutes FROM daily_usage
                   WHERE target_kind = ? AND target_id = ? AND date_local = ?""",
                (target_kind, target_id, date_local),
            ).fetchone()
        return int(row["active_minutes"]) if row else 0

    def get_daily_usages(self, date_local: str) -> dict[tuple[str, str], int]:
        with self._connect() as cx:
            rows = cx.execute(
                "SELECT target_kind, target_id, active_minutes FROM daily_usage WHERE date_local = ?",
                (date_local,),
            ).fetchall()
        return {(r["target_kind"], r["target_id"]): int(r["active_minutes"]) for r in rows}

    def get_app_usages(self, target_kind: str, target_id: str, date_local: str) -> list[dict]:
        with self._connect() as cx:
            rows = cx.execute(
                """SELECT app_id, active_minutes FROM daily_app_usage
                   WHERE target_kind = ? AND target_id = ? AND date_local = ?
                   ORDER BY active_minutes DESC""",
                (target_kind, target_id, date_local),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ settings

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self._connect() as cx:
            row = cx.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str | None) -> None:
        now = int(time.time())
        with self._lock, self._connect() as cx:
            if value is None:
                cx.execute("DELETE FROM settings WHERE key = ?", (key,))
            else:
                cx.execute(
                    """INSERT INTO settings(key, value, updated_at)
                       VALUES (?, ?, ?)
                       ON CONFLICT(key) DO UPDATE SET
                           value = excluded.value,
                           updated_at = excluded.updated_at""",
                    (key, value, now),
                )

    def all_settings(self, prefix: str | None = None) -> dict[str, str]:
        with self._connect() as cx:
            if prefix:
                rows = cx.execute(
                    "SELECT key, value FROM settings WHERE key LIKE ?",
                    (f"{prefix}%",),
                ).fetchall()
            else:
                rows = cx.execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}

    # --------------------------------------------------------------------- audit

    def log_audit(self, *, actor: str | None, ip: str | None, action: str,
                  detail: str | None = None) -> None:
        with self._lock, self._connect() as cx:
            cx.execute(
                "INSERT INTO audit(ts, actor, ip, action, detail) VALUES (?, ?, ?, ?, ?)",
                (int(time.time()), actor, ip, action, detail),
            )

    def recent_audit(self, limit: int = 50) -> list[dict]:
        with self._connect() as cx:
            rows = cx.execute(
                "SELECT id, ts, actor, ip, action, detail FROM audit ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # --------------------------------------------------------------------- raw

    def export_state(self) -> dict[str, Any]:
        """Dump everything as JSON (debugging / backup)."""
        with self._connect() as cx:
            tables = ["devices", "people", "device_overrides", "schedules",
                      "quotas", "daily_usage", "daily_app_usage", "audit",
                      "settings"]
            return {t: [dict(r) for r in cx.execute(f"SELECT * FROM {t}").fetchall()] for t in tables}
