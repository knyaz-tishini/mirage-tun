#!/bin/bash
# Manual TUN smoke test — requires:
# 1. mirage2web client running (SOCKS5:19480, HTTP:19481)
# 2. mirage2tun service running (API:4498)
# 3. Run as admin (TUN needs admin)
#
# WARNING: This will activate TUN and route ALL traffic through relay.
# Your VPN connection will break during the test.

set -e

API="http://127.0.0.1:4498"
EXPECTED_IP="45.59.119.139"

echo "=== mirage2tun smoke test ==="

# 1. Check service health
echo "[1/7] Checking service health..."
curl -sf "$API/health" || { echo "FAIL: service not running"; exit 1; }
echo " OK"

# 2. Check status
echo "[2/7] Checking status..."
STATUS=$(curl -sf "$API/status")
echo "  $STATUS"

# 3. Activate TUN
echo "[3/7] Activating TUN..."
curl -sf -X POST "$API/tun/start" \
  -H "Content-Type: application/json" \
  -d '{"socks5_addr":"127.0.0.1:19480","relay_addrs":["91.218.245.247","45.59.119.139"]}' \
  || { echo "FAIL: tun/start failed"; exit 1; }
echo " OK"

# 4. Wait for routes to settle
echo "[4/7] Waiting 3s for routes..."
sleep 3

# 5. Check exit IP
echo "[5/7] Checking exit IP..."
EXIT_IP=$(curl -sf --max-time 10 http://ifconfig.me 2>/dev/null || echo "TIMEOUT")
echo "  Exit IP: $EXIT_IP"
if [ "$EXIT_IP" = "$EXPECTED_IP" ]; then
  echo "  PASS: correct relay exit IP"
else
  echo "  FAIL: expected $EXPECTED_IP got $EXIT_IP"
fi

# 6. Check DNS
echo "[6/7] Checking DNS resolution..."
DNS_RESULT=$(nslookup google.com 2>/dev/null | head -5 || echo "FAIL")
echo "  $DNS_RESULT"

# 7. Deactivate TUN
echo "[7/7] Deactivating TUN..."
curl -sf -X POST "$API/tun/stop" || echo "WARN: tun/stop failed"
echo " OK"

echo ""
echo "=== smoke test complete ==="
