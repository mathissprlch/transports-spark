#!/usr/bin/env bash
set -euo pipefail
#
# Test PSK resumption against a peer server.
#
# Usage:
#   scripts/test-psk-resumption.sh [PEER]
#
# PEER = openssl (default), gnutls, mbedtls
#
# Phase 1: cert-ec handshake → save ticket
# Phase 2: psk-resume handshake using saved ticket

PEER=${1:-openssl}
TICKET=/tmp/spark-tls-resume-ticket.bin
PORT=$((30000 + RANDOM % 10000))
FIXTURES=$(dirname "$0")/../crates/tls_core/tests/fixtures/interop/ec
TLS_CLI=$(dirname "$0")/../crates/examples/bin/tls_cli

echo "=== PSK Resumption test against $PEER on port $PORT ==="

# --- Phase 1: cert-ec handshake to get a ticket ---

echo "Phase 1: cert-ec handshake (get ticket)..."

case $PEER in
  openssl)
    openssl s_server -tls1_3 -accept $PORT \
      -cert "$FIXTURES/leaf.pem" -key "$FIXTURES/leaf-key.pem" \
      -www -quiet &
    ;;
  gnutls)
    gnutls-serv --port=$PORT \
      --x509certfile="$FIXTURES/leaf.pem" \
      --x509keyfile="$FIXTURES/leaf-key.pem" \
      --disable-client-cert &
    ;;
  mbedtls)
    ssl_server2 server_port=$PORT \
      crt_file="$FIXTURES/leaf.pem" \
      key_file="$FIXTURES/leaf-key.pem" \
      force_version=tls13 &
    ;;
  *)
    echo "Unknown peer: $PEER"; exit 1
    ;;
esac
SRV_PID=$!
sleep 0.5

TRUST_DER="${FIXTURES}/root.der"
"$TLS_CLI" client --connect "127.0.0.1:$PORT" \
  --mode cert-ec --trust "$TRUST_DER" \
  --hostname localhost \
  --save-ticket "$TICKET"
PHASE1=$?

kill $SRV_PID 2>/dev/null || true
wait $SRV_PID 2>/dev/null || true

if [ $PHASE1 -ne 0 ]; then
  echo "FAIL: Phase 1 (cert-ec) failed with exit $PHASE1"
  exit 1
fi

if [ ! -f "$TICKET" ]; then
  echo "FAIL: no ticket file saved at $TICKET"
  exit 1
fi
echo "Phase 1: OK (ticket saved: $(wc -c < "$TICKET") bytes)"

# --- Phase 2: psk-resume handshake using ticket ---

echo "Phase 2: psk-resume handshake..."
PORT2=$((PORT + 1))

case $PEER in
  openssl)
    openssl s_server -tls1_3 -accept $PORT2 \
      -cert "$FIXTURES/leaf.pem" -key "$FIXTURES/leaf-key.pem" \
      -www -quiet &
    ;;
  gnutls)
    gnutls-serv --port=$PORT2 \
      --x509certfile="$FIXTURES/leaf.pem" \
      --x509keyfile="$FIXTURES/leaf-key.pem" \
      --disable-client-cert &
    ;;
  mbedtls)
    ssl_server2 server_port=$PORT2 \
      crt_file="$FIXTURES/leaf.pem" \
      key_file="$FIXTURES/leaf-key.pem" \
      force_version=tls13 &
    ;;
esac
SRV_PID=$!
sleep 0.5

"$TLS_CLI" client --connect "127.0.0.1:$PORT2" \
  --mode psk-resume --load-ticket "$TICKET"
PHASE2=$?

kill $SRV_PID 2>/dev/null || true
wait $SRV_PID 2>/dev/null || true

rm -f "$TICKET"

if [ $PHASE2 -ne 0 ]; then
  echo "FAIL: Phase 2 (psk-resume) failed with exit $PHASE2"
  exit 1
fi

echo "=== PASS: PSK resumption against $PEER ==="
