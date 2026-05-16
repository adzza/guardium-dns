#!/usr/bin/env bash
# Push the Guardium DNS project to a remote server and run install.sh on it.
#
# Usage:
#     ./deploy.sh user@host [SSH_OPTS...]
#
# Example:
#     ./deploy.sh root@dns.lan.example
#     ./deploy.sh -i ~/.ssh/id_ed25519 root@10.0.0.5
#
# Optional environment variables:
#     SSH_FLAGS    extra flags passed to ssh / rsync (e.g. -i ~/.dnsdash/id_ed25519)
#     BOOT_TOKEN   Technitium service token to pre-seed in /etc/dns-dashboard.env
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 user@host [extra ssh args...]" >&2
  exit 1
fi

TARGET="$1"; shift
SSH_FLAGS=( "${SSH_FLAGS:-}" "$@" )
SSH_FLAGS=( ${SSH_FLAGS[@]:-} )

SSH=( ssh ${SSH_FLAGS[@]:-} )
RSYNC_SSH="ssh ${SSH_FLAGS[*]:-}"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> rsync $PROJECT_DIR -> $TARGET:/opt/dns-dashboard"
rsync -az --delete \
  -e "$RSYNC_SSH" \
  --exclude '.venv' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '.git' \
  --exclude '.DS_Store' \
  "$PROJECT_DIR/" "$TARGET:/opt/dns-dashboard/"

echo "==> running installer on remote"
"${SSH[@]}" "$TARGET" "DASHBOARD_BOOT_TOKEN='${BOOT_TOKEN:-}' bash /opt/dns-dashboard/deploy/install.sh"

echo "==> deploy finished"
