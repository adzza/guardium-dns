#!/usr/bin/env bash
# One-shot script to add a Conditional Forwarder zone in Technitium so that
# reverse-DNS queries for the LAN subnet are answered by the ASUS router's
# built-in dnsmasq. With this in place every client on the network can do:
#
#     dig -x 192.168.4.83
#
# ...and get the device's DHCP hostname back, courtesy of the router. The
# dashboard does NOT depend on this -- it queries the gateway directly. But
# this is a nice-to-have for the rest of the network.
#
# Idempotent: if the zone already exists, we just refresh its forwarder record.
#
# Usage:
#     LAN_REVERSE_ZONE=4.168.192.in-addr.arpa LAN_GATEWAY=192.168.4.1 \
#         TECHNITIUM_TOKEN=... bash setup-reverse-forwarder.sh
#
# All three vars have sensible defaults read from /etc/dns-dashboard.env when
# present.
set -euo pipefail

if [[ -f /etc/dns-dashboard.env ]]; then
  # shellcheck disable=SC1091
  source /etc/dns-dashboard.env
fi

TECHNITIUM_URL="${TECHNITIUM_URL:-http://127.0.0.1:5380}"
TOKEN="${TECHNITIUM_TOKEN:-${TECHNITIUM_SERVICE_TOKEN:-}}"
ZONE="${LAN_REVERSE_ZONE:-4.168.192.in-addr.arpa}"
GW="${LAN_GATEWAY:-192.168.4.1}"

if [[ -z "$TOKEN" ]]; then
  echo "TECHNITIUM_TOKEN (or TECHNITIUM_SERVICE_TOKEN) must be set" >&2
  exit 1
fi

api() {
  curl -fsSG "${TECHNITIUM_URL}$1" \
    --data-urlencode "token=$TOKEN" \
    "${@:2}"
}

echo "==> ensuring conditional forwarder zone $ZONE -> $GW"

CREATE_RESP=$(curl -sG "${TECHNITIUM_URL}/api/zones/create" \
  --data-urlencode "token=$TOKEN" \
  --data-urlencode "zone=$ZONE" \
  --data-urlencode "type=Forwarder" \
  --data-urlencode "protocol=Udp" \
  --data-urlencode "forwarder=$GW" || true)

if echo "$CREATE_RESP" | grep -q '"status":"ok"'; then
  echo "    created zone"
elif echo "$CREATE_RESP" | grep -q 'already exists'; then
  echo "    zone already exists -- updating forwarder"
  # Delete existing FWD record(s), then add a fresh one.
  curl -sfG "${TECHNITIUM_URL}/api/zones/records/delete" \
    --data-urlencode "token=$TOKEN" \
    --data-urlencode "domain=$ZONE" \
    --data-urlencode "zone=$ZONE" \
    --data-urlencode "type=FWD" \
    --data-urlencode "forwarder=$GW" \
    --data-urlencode "protocol=Udp" >/dev/null || true
  curl -sfG "${TECHNITIUM_URL}/api/zones/records/add" \
    --data-urlencode "token=$TOKEN" \
    --data-urlencode "domain=$ZONE" \
    --data-urlencode "zone=$ZONE" \
    --data-urlencode "type=FWD" \
    --data-urlencode "forwarder=$GW" \
    --data-urlencode "protocol=Udp" \
    --data-urlencode "ttl=60" >/dev/null
else
  echo "    create failed: $CREATE_RESP" >&2
  exit 1
fi

echo "==> done. Test (Technitium answers reverse DNS for the LAN):"
TEST_IP="${LAN_TEST_IP:-${GW}}"
dig @127.0.0.1 -x "$TEST_IP" +short +time=2 +tries=1 || true
