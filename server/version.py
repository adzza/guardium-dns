"""Version + update-check plumbing.

Surfaces two pieces of information to the dashboard UI:

1. **Installed** — what code Guardium DNS is actually running. Read from
   ``/var/lib/dns-dashboard/version.json`` if ``guardium-update`` has
   stamped it, otherwise ``git rev-parse HEAD`` inside the install dir,
   otherwise marked "unknown".

2. **Latest** — what's on the configured GitHub branch. Fetched lazily
   on first request and refreshed by a background task; the result is
   cached in the store's ``settings`` table so the UI sees data
   immediately on page load without waiting for a network round-trip.

Everything is best-effort. Network failures, missing files, etc. just
mean "couldn't check" -- they never bubble up to the user as an error
banner.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx

from .store import Store


log = logging.getLogger("dns-dashboard.version")

# How long between GitHub polls during normal operation. Public, unauth'd
# GitHub API allows 60 requests/hr per source IP; we burn 4 calls/day
# with this default.
DEFAULT_POLL_INTERVAL_SECONDS = 6 * 60 * 60

# Settings keys (in the SQLite store, not the env file).
_KEY_LATEST_CACHE = "update.latest_cache"   # JSON {channel, sha, message, ...}
_KEY_LAST_CHECKED = "update.last_checked"   # epoch seconds
_KEY_LAST_ERROR   = "update.last_error"     # string | empty
_KEY_DISMISSED    = "update.dismissed_sha"  # SHA the user told us to stop nagging about

# Default repo + channel. Overridable per-install via env vars on the
# service unit (read from /etc/dns-dashboard.env by systemd).
DEFAULT_REPO = "adzza/guardium-dns"
DEFAULT_CHANNEL = "main"


@dataclass(frozen=True)
class InstalledVersion:
    sha: str | None
    short_sha: str | None
    branch: str | None
    tag: str | None
    message: str | None
    committed_at: int | None
    updated_at: int | None
    source: str  # "version-json" | "git" | "unknown"


@dataclass(frozen=True)
class LatestVersion:
    sha: str
    short_sha: str
    message: str
    author: str | None
    committed_at: int | None
    html_url: str | None


# ---------------------------------------------------------------- installed

def _install_dir() -> Path:
    # Fallback chain: explicit env var > the dir this file lives in > /opt.
    env = os.environ.get("GUARDIUM_INSTALL_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve().parents[1]
    if (here / "deploy" / "install.sh").exists():
        return here
    return Path("/opt/dns-dashboard")


def _data_dir() -> Path:
    return Path(os.environ.get("DASHBOARD_DATA_DIR", "/var/lib/dns-dashboard"))


def _read_version_json() -> InstalledVersion | None:
    path = _data_dir() / "version.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except Exception:  # noqa: BLE001
        log.warning("version.json present but unreadable", exc_info=True)
        return None
    return InstalledVersion(
        sha=data.get("sha"),
        short_sha=data.get("shortSha") or (data.get("sha") or "")[:7] or None,
        branch=data.get("branch"),
        tag=data.get("tag"),
        message=data.get("message"),
        committed_at=data.get("committedAt"),
        updated_at=data.get("updatedAt"),
        source="version-json",
    )


def _read_git_head() -> InstalledVersion | None:
    install_dir = _install_dir()
    if not (install_dir / ".git").exists():
        return None
    try:
        sha = subprocess.check_output(
            ["git", "-C", str(install_dir), "rev-parse", "HEAD"],
            text=True, timeout=2,
        ).strip()
        branch = subprocess.check_output(
            ["git", "-C", str(install_dir), "rev-parse", "--abbrev-ref", "HEAD"],
            text=True, timeout=2,
        ).strip()
        message = subprocess.check_output(
            ["git", "-C", str(install_dir), "log", "-1", "--format=%s"],
            text=True, timeout=2,
        ).strip()
        committed_at = int(subprocess.check_output(
            ["git", "-C", str(install_dir), "log", "-1", "--format=%ct"],
            text=True, timeout=2,
        ).strip())
    except Exception:  # noqa: BLE001
        log.debug("git rev-parse failed", exc_info=True)
        return None
    tag_path = install_dir / "VERSION"
    tag = tag_path.read_text().strip() if tag_path.exists() else None
    return InstalledVersion(
        sha=sha, short_sha=sha[:7], branch=branch, tag=tag,
        message=message, committed_at=committed_at, updated_at=None,
        source="git",
    )


def installed_version() -> InstalledVersion:
    """Best-effort guess of what's currently running. Never raises."""
    v = _read_version_json()
    if v is not None:
        return v
    v = _read_git_head()
    if v is not None:
        return v
    return InstalledVersion(
        sha=None, short_sha=None, branch=None, tag=None,
        message=None, committed_at=None, updated_at=None, source="unknown",
    )


# ---------------------------------------------------------------- config

def _config() -> tuple[str, str]:
    """Read (repo, channel) from env, falling back to defaults."""
    repo = os.environ.get("GITHUB_REPO", DEFAULT_REPO) or DEFAULT_REPO
    channel = os.environ.get("UPDATE_CHANNEL", DEFAULT_CHANNEL) or DEFAULT_CHANNEL
    return repo, channel


# ---------------------------------------------------------------- latest

async def fetch_latest(channel: str, repo: str) -> LatestVersion:
    """One unauthenticated GET against the GitHub commits API. Raises on failure."""
    url = f"https://api.github.com/repos/{repo}/commits/{channel}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "guardium-dns-updater",
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url, headers=headers)
    if resp.status_code == 404:
        raise RuntimeError(
            f"GitHub returned 404 for {repo}@{channel}. "
            "Check the repo name and that the branch exists."
        )
    resp.raise_for_status()
    data = resp.json()
    sha = data.get("sha") or ""
    commit = data.get("commit") or {}
    message = (commit.get("message") or "").splitlines()[0] if commit.get("message") else ""
    author = ((commit.get("author") or {}).get("name")
              or (data.get("author") or {}).get("login"))
    committed_at = None
    if commit.get("author") and commit["author"].get("date"):
        try:
            from datetime import datetime
            committed_at = int(datetime.fromisoformat(
                commit["author"]["date"].replace("Z", "+00:00")
            ).timestamp())
        except Exception:  # noqa: BLE001
            committed_at = None
    return LatestVersion(
        sha=sha,
        short_sha=sha[:7] if sha else "",
        message=message,
        author=author,
        committed_at=committed_at,
        html_url=data.get("html_url"),
    )


# ---------------------------------------------------------------- cache I/O

def load_cache(store: Store) -> dict[str, Any]:
    raw = store.get_setting(_KEY_LATEST_CACHE)
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:  # noqa: BLE001
        return {}


def save_cache(store: Store, channel: str, repo: str,
                latest: LatestVersion, *, ts: int | None = None) -> None:
    ts = ts or int(time.time())
    payload = {
        "channel": channel,
        "repo": repo,
        "ts": ts,
        **{k: v for k, v in asdict(latest).items()},
    }
    store.set_setting(_KEY_LATEST_CACHE, json.dumps(payload))
    store.set_setting(_KEY_LAST_CHECKED, str(ts))
    store.set_setting(_KEY_LAST_ERROR, "")


def save_error(store: Store, err: str) -> None:
    store.set_setting(_KEY_LAST_CHECKED, str(int(time.time())))
    store.set_setting(_KEY_LAST_ERROR, err)


def dismissed_sha(store: Store) -> str | None:
    val = store.get_setting(_KEY_DISMISSED)
    return val or None


def set_dismissed_sha(store: Store, sha: str | None) -> None:
    store.set_setting(_KEY_DISMISSED, sha or "")


# ---------------------------------------------------------------- public payload

def build_payload(store: Store) -> dict[str, Any]:
    """The dict the UI sees from /api/version. Pure -- no network."""
    repo, channel = _config()
    installed = installed_version()
    cache = load_cache(store)
    last_checked = store.get_setting(_KEY_LAST_CHECKED)
    last_error = store.get_setting(_KEY_LAST_ERROR) or None
    dismissed = dismissed_sha(store)

    latest = None
    update_available = False
    commits_behind: int | None = None
    if cache and cache.get("channel") == channel:
        latest = {
            "sha": cache.get("sha"),
            "shortSha": cache.get("short_sha") or (cache.get("sha") or "")[:7],
            "message": cache.get("message"),
            "author": cache.get("author"),
            "committedAt": cache.get("committed_at"),
            "htmlUrl": cache.get("html_url"),
        }
        if installed.sha and latest["sha"] and installed.sha != latest["sha"]:
            update_available = True

    update_command = "sudo guardium-update"
    compare_url = None
    if installed.sha and latest and latest.get("sha"):
        compare_url = f"https://github.com/{repo}/compare/{installed.sha}...{latest['sha']}"

    return {
        "installed": {
            "sha": installed.sha,
            "shortSha": installed.short_sha,
            "branch": installed.branch,
            "tag": installed.tag,
            "message": installed.message,
            "committedAt": installed.committed_at,
            "updatedAt": installed.updated_at,
            "source": installed.source,
        },
        "latest": latest,
        "channel": channel,
        "repo": repo,
        "updateAvailable": update_available and (dismissed != latest["sha"] if latest else False),
        "updateAvailableRaw": update_available,
        "dismissedSha": dismissed,
        "commitsBehind": commits_behind,
        "lastChecked": int(last_checked) if last_checked else None,
        "lastError": last_error,
        "compareUrl": compare_url,
        "updateCommand": update_command,
        "remoteCommand": "ssh root@<your-guardium-host> 'guardium-update'",
    }


# ---------------------------------------------------------------- poller

class VersionChecker:
    """Background task: poll GitHub every ``interval_seconds`` and cache the result."""

    def __init__(self, store: Store, *, interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS) -> None:
        self._store = store
        self._interval = interval_seconds
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._kick = asyncio.Event()

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="version-checker")
        log.info("Version checker started (interval=%ss)", self._interval)

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        self._kick.set()
        try:
            await asyncio.wait_for(self._task, timeout=5)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            self._task.cancel()
        self._task = None

    def kick(self) -> None:
        """Force an immediate poll (e.g. when the user hits 'Check now')."""
        self._kick.set()

    async def check_now(self) -> dict[str, Any]:
        """Run one poll synchronously and return the resulting payload."""
        repo, channel = _config()
        try:
            latest = await fetch_latest(channel, repo)
            save_cache(self._store, channel, repo, latest)
        except Exception as exc:  # noqa: BLE001
            log.warning("version check failed: %s", exc)
            save_error(self._store, str(exc))
        return build_payload(self._store)

    async def _run(self) -> None:
        # Always do an immediate one-shot so the dashboard has fresh data
        # within seconds of service start, not hours.
        try:
            await self.check_now()
        except Exception:  # noqa: BLE001
            log.exception("initial version check failed")
        while not self._stop.is_set():
            self._kick.clear()
            # Wait for either the next interval or an explicit kick.
            wait_tasks = (
                asyncio.create_task(self._stop.wait()),
                asyncio.create_task(self._kick.wait()),
            )
            try:
                await asyncio.wait_for(
                    asyncio.wait(wait_tasks, return_when=asyncio.FIRST_COMPLETED),
                    timeout=self._interval,
                )
            except asyncio.TimeoutError:
                pass
            for t in wait_tasks:
                if not t.done():
                    t.cancel()
            if self._stop.is_set():
                break
            try:
                await self.check_now()
            except Exception:  # noqa: BLE001
                log.exception("version check failed")
