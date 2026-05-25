#!/usr/bin/env bash
# guardium-update -- pull the latest Guardium DNS code, run migrations,
# restart the service, and auto-roll-back on health-check failure.
#
# Invoked by the user (as root, on the Guardium DNS host):
#     guardium-update
#     guardium-update --check
#     guardium-update --channel main
#     guardium-update --no-rollback   (for debugging a bad release)
#
# Reads UPDATE_CHANNEL and GITHUB_REPO from /etc/dns-dashboard.env so the
# operator can switch tracks without editing this script.
#
# If /opt/dns-dashboard isn't a git checkout (e.g. it was rsync'd by an
# older deployment), the first run bootstraps it into one against
# origin/$channel. Data files at /var/lib/dns-dashboard/ are never touched.
set -euo pipefail

INSTALL_DIR="${GUARDIUM_INSTALL_DIR:-/opt/dns-dashboard}"
DATA_DIR="${GUARDIUM_DATA_DIR:-/var/lib/dns-dashboard}"
ENV_FILE="${GUARDIUM_ENV_FILE:-/etc/dns-dashboard.env}"
LOG_FILE="/var/log/guardium-update.log"
DEFAULT_REPO="adzza/guardium-dns"
DEFAULT_CHANNEL="main"
HEALTH_URL="http://127.0.0.1:8080/api/health"

usage() {
  cat <<'EOF'
guardium-update -- update Guardium DNS to the latest commit on the configured channel.

Options:
  --check              Show current vs latest, don't apply anything.
  --channel <name>     Override the channel for this run (e.g. main, feat/unifi-integration).
  --no-rollback        Don't auto-revert if the new version fails its health check.
  -h, --help           Show this help.

Reads UPDATE_CHANNEL and GITHUB_REPO from /etc/dns-dashboard.env if present.
Defaults: channel=main, repo=adzza/guardium-dns.
EOF
}

log()   { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG_FILE"; }
die()   { log "ERROR: $*"; exit 1; }
need()  { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

CHECK_ONLY=0
NO_ROLLBACK=0
CLI_CHANNEL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)        CHECK_ONLY=1 ;;
    --no-rollback)  NO_ROLLBACK=1 ;;
    --channel)      shift; CLI_CHANNEL="${1:-}" ;;
    -h|--help)      usage; exit 0 ;;
    *)              usage >&2; die "unknown argument: $1" ;;
  esac
  shift
done

if [[ $EUID -ne 0 ]]; then
  die "guardium-update must run as root (try: sudo guardium-update)"
fi

need git
need curl
need systemctl

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# Pull channel + repo from the env file (sourced safely; env file is
# shell-quoted key=value lines per install.sh).
CHANNEL="$DEFAULT_CHANNEL"
REPO="$DEFAULT_REPO"
if [[ -r "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set +u; source "$ENV_FILE"; set -u
  [[ -n "${UPDATE_CHANNEL:-}" ]] && CHANNEL="$UPDATE_CHANNEL"
  [[ -n "${GITHUB_REPO:-}" ]]    && REPO="$GITHUB_REPO"
fi
[[ -n "$CLI_CHANNEL" ]] && CHANNEL="$CLI_CHANNEL"

REMOTE_URL="https://github.com/${REPO}.git"
API_URL="https://api.github.com/repos/${REPO}/commits/${CHANNEL}"

[[ -d "$INSTALL_DIR" ]] || die "install dir not found: $INSTALL_DIR"

cd "$INSTALL_DIR"

# Bootstrap into a real git checkout if needed. Safe because all stateful
# data lives in $DATA_DIR; everything in $INSTALL_DIR is meant to be a
# verbatim copy of the repo.
if [[ ! -d .git ]]; then
  log "no git history at $INSTALL_DIR; bootstrapping checkout against $REMOTE_URL ($CHANNEL)"
  git init -q
  git remote add origin "$REMOTE_URL"
  git fetch --quiet --depth 50 origin "$CHANNEL" \
    || die "git fetch failed -- check network and that branch '$CHANNEL' exists on $REPO"
  # Hard reset to remote: file contents on disk become the working copy.
  git reset -q --hard "origin/$CHANNEL"
fi

OLD_SHA="$(git rev-parse HEAD)"
OLD_SHORT="$(git rev-parse --short HEAD)"

log "==> checking ${REPO}@${CHANNEL}"
log "    installed: ${OLD_SHORT} (${OLD_SHA})"

git fetch --quiet origin "$CHANNEL" \
  || die "git fetch failed -- check network and that branch '$CHANNEL' exists on $REPO"

NEW_SHA="$(git rev-parse "origin/$CHANNEL")"
NEW_SHORT="$(git rev-parse --short "origin/$CHANNEL")"
log "    latest:    ${NEW_SHORT} (${NEW_SHA})"

if [[ "$OLD_SHA" == "$NEW_SHA" ]]; then
  log "==> already up to date."
  exit 0
fi

# Always-true: at least one commit between OLD and NEW.
BEHIND="$(git rev-list --count "${OLD_SHA}..${NEW_SHA}" || echo '?')"
LATEST_MSG="$(git log -1 --format='%s' "origin/$CHANNEL")"
log "    ${BEHIND} commit(s) behind. latest: \"${LATEST_MSG}\""

if (( CHECK_ONLY )); then
  log "==> --check only; not applying."
  exit 0
fi

log "==> applying update"
# Wipe any drifted files but spare $DATA_DIR / .venv (they live at
# different paths). `git reset --hard` only touches tracked files;
# untracked files like the .venv directory survive.
git checkout -q "$CHANNEL" 2>/dev/null || git checkout -q -B "$CHANNEL" "origin/$CHANNEL"
git reset -q --hard "origin/$CHANNEL"

# Re-run the installer to handle new deps, schema migrations, file
# ownership, etc. install.sh is idempotent.
log "==> running deploy/install.sh"
if ! bash "$INSTALL_DIR/deploy/install.sh" >>"$LOG_FILE" 2>&1; then
  log "ERROR: install.sh failed; attempting rollback"
  if (( NO_ROLLBACK )); then
    log "    --no-rollback set; leaving install dir at $NEW_SHORT for inspection"
    exit 2
  fi
  git reset -q --hard "$OLD_SHA"
  bash "$INSTALL_DIR/deploy/install.sh" >>"$LOG_FILE" 2>&1 || \
    log "rollback install.sh ALSO failed; manual intervention required"
  systemctl restart dns-dashboard.service || true
  die "update aborted; rolled back to $OLD_SHORT"
fi

log "==> restarting dns-dashboard.service"
systemctl restart dns-dashboard.service

log "==> waiting for /api/health (up to 30s)"
HEALTHY=0
for i in $(seq 1 60); do
  if curl -fsS -m 2 "$HEALTH_URL" >/dev/null 2>&1; then
    HEALTHY=1
    break
  fi
  sleep 0.5
done

if (( ! HEALTHY )); then
  if (( NO_ROLLBACK )); then
    log "WARN: health check failed but --no-rollback set; leaving service in current state."
  else
    log "ERROR: health check failed after restart; rolling back to $OLD_SHORT"
    git reset -q --hard "$OLD_SHA"
    bash "$INSTALL_DIR/deploy/install.sh" >>"$LOG_FILE" 2>&1 || true
    systemctl restart dns-dashboard.service || true
    die "rollback complete; failing service. Check 'journalctl -u dns-dashboard' and $LOG_FILE."
  fi
fi

# Stamp version.json so the dashboard surfaces the new version immediately.
VERSION_FILE="$DATA_DIR/version.json"
NEW_TS="$(date +%s)"
NEW_COMMITTED="$(git log -1 --format='%ct' "$NEW_SHA")"
NEW_AUTHOR="$(git log -1 --format='%an' "$NEW_SHA")"
VERSION_TAG="$(cat "$INSTALL_DIR/VERSION" 2>/dev/null || echo unknown)"

# JSON via a tiny python shim so we don't have to worry about quoting in
# the commit message ourselves. python3 is guaranteed by install.sh.
python3 - "$VERSION_FILE" "$NEW_SHA" "$NEW_SHORT" "$CHANNEL" "$LATEST_MSG" \
        "$NEW_AUTHOR" "$NEW_COMMITTED" "$NEW_TS" "$VERSION_TAG" <<'PY'
import json, os, sys
path, sha, short_sha, branch, message, author, committed_at, updated_at, tag = sys.argv[1:]
payload = {
    "sha": sha,
    "shortSha": short_sha,
    "branch": branch,
    "message": message,
    "author": author,
    "committedAt": int(committed_at),
    "updatedAt": int(updated_at),
    "tag": tag.strip() or "unknown",
}
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w") as f:
    json.dump(payload, f, indent=2)
os.chmod(path, 0o644)
PY

log "==> update complete: ${OLD_SHORT} -> ${NEW_SHORT} (${BEHIND} commit(s))"
log "    Dashboard URL: http://$(hostname -I | awk '{print $1}'):8080/"
