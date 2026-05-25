#!/usr/bin/env bash
# Idempotent installer for Guardium DNS.
#
# Run this script *on the target server*, as root. It:
#   1. ensures Python 3 + venv tooling are present;
#   2. creates a dedicated `dns-dashboard` system user;
#   3. owns /opt/dns-dashboard and /var/lib/dns-dashboard;
#   4. creates a Python venv at /opt/dns-dashboard/.venv and installs deps;
#   5. writes /etc/dns-dashboard.env (only if missing);
#   6. installs and starts the systemd unit.
#
# It does NOT touch the Technitium service.
set -euo pipefail

INSTALL_DIR="/opt/dns-dashboard"
DATA_DIR="/var/lib/dns-dashboard"
LOG_DIR="/var/log/dns-dashboard"
ENV_FILE="/etc/dns-dashboard.env"
SERVICE_USER="dns-dashboard"
SERVICE_FILE="/etc/systemd/system/dns-dashboard.service"

DEFAULT_TOKEN="${DASHBOARD_BOOT_TOKEN:-}"

echo "==> Installing Guardium DNS to ${INSTALL_DIR}"

if [[ $EUID -ne 0 ]]; then
  echo "must run as root" >&2
  exit 1
fi

apt_install_if_missing() {
  local missing=()
  for pkg in "$@"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done
  if (( ${#missing[@]} )); then
    echo "==> apt install ${missing[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
  fi
}

apt_install_if_missing python3 python3-venv python3-pip ca-certificates git curl

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  echo "==> creating system user ${SERVICE_USER}"
  useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$DATA_DIR" "$LOG_DIR"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"

# venv
if [[ ! -x "$INSTALL_DIR/.venv/bin/python" ]]; then
  echo "==> creating venv"
  sudo -u "$SERVICE_USER" python3 -m venv "$INSTALL_DIR/.venv"
fi

echo "==> installing python deps"
sudo -u "$SERVICE_USER" "$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
sudo -u "$SERVICE_USER" "$INSTALL_DIR/.venv/bin/pip" install --quiet -r "$INSTALL_DIR/server/requirements.txt"

# env file
if [[ ! -f "$ENV_FILE" ]]; then
  echo "==> writing $ENV_FILE"
  cat >"$ENV_FILE" <<EOF
TECHNITIUM_URL=http://127.0.0.1:5380
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=8080
DASHBOARD_DATA_DIR=$DATA_DIR
DASHBOARD_WEB_DIR=$INSTALL_DIR/web
TECHNITIUM_SERVICE_TOKEN=${DEFAULT_TOKEN}

# Which GitHub branch the dashboard checks for updates against, and where
# 'guardium-update' pulls from. Override either of these to ride a beta
# channel or a fork. Default: stable.
UPDATE_CHANNEL=main
GITHUB_REPO=adzza/guardium-dns
EOF
  chmod 600 "$ENV_FILE"
  chown root:"$SERVICE_USER" "$ENV_FILE"
  chmod 640 "$ENV_FILE"
else
  # Backfill missing keys on upgrade installs so older env files pick up
  # the new update-channel knobs without manual editing.
  if ! grep -q '^UPDATE_CHANNEL=' "$ENV_FILE"; then
    echo "==> appending UPDATE_CHANNEL to $ENV_FILE"
    printf '\n# Update channel + source repo (added by installer).\nUPDATE_CHANNEL=main\nGITHUB_REPO=adzza/guardium-dns\n' >>"$ENV_FILE"
  fi
fi

# Install the updater CLI (idempotent symlink overwrite).
echo "==> installing /usr/local/bin/guardium-update"
install -m 755 "$INSTALL_DIR/deploy/guardium-update.sh" /usr/local/bin/guardium-update

# systemd
echo "==> installing systemd unit"
install -m 644 "$INSTALL_DIR/deploy/dns-dashboard.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable dns-dashboard.service
systemctl restart dns-dashboard.service

echo "==> waiting for dashboard to come up"
for i in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8080/api/health >/dev/null 2>&1; then
    echo "==> dashboard is up"
    break
  fi
  sleep 0.5
done
systemctl --no-pager --lines=8 status dns-dashboard.service || true
echo
echo "==> done. Dashboard URL:  http://$(hostname -I | awk '{print $1}'):8080/"
