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
# Phase 1: cert-ec handshake → save ticket (against running server)
# Phase 2: psk-resume handshake using saved ticket (same server)
#
# The server MUST stay running between phases so it retains the
# ticket encryption key that was used to issue the NewSessionTicket.
# Starting a fresh server for Phase 2 would give a different key
# and the server would reject the ticket (falling back to cert-mode
# while our client expects PSK → bad_record_mac).

PEER=${1:-openssl}
TICKET=/tmp/spark-tls-resume-ticket.bin
PORT=$((30000 + RANDOM % 10000))
FIXTURES=$(dirname "$0")/../crates/tls_core/tests/fixtures/interop/ec
TLS_CLI=$(dirname "$0")/../crates/examples/bin/tls_cli

echo "=== PSK Resumption test against $PEER on port $PORT ==="

# --- Start ONE server for both phases ---

GO_SRV=$(dirname "$0")/../crates/examples/bin/go_peer_server

case $PEER in
  openssl)
    openssl s_server -tls1_3 -accept $PORT \
      -cert "$FIXTURES/leaf.pem" -key "$FIXTURES/leaf.key" \
      -www -quiet &
    ;;
  gnutls)
    echo "SKIP: gnutls-serv does not retain ticket keys across connections in default mode"
    exit 2
    ;;
  mbedtls)
    echo "SKIP: mbedtls ssl_server2 waits for app-data before flushing NST"
    exit 2
    ;;
  go)
    echo "SKIP: Go go_peer_server NST capture timing issue under investigation"
    exit 2
    ;;
  rustls)
    echo "SKIP: rustls tlsserver-mio echo idles for app-data; no resumption c2s"
    exit 2
    ;;
  boringssl)
    echo "SKIP: bssl half-RTT NST coalescing blocks resumption c2s"
    exit 2
    ;;
  *)
    echo "Unknown peer: $PEER"; exit 1
    ;;
esac
SRV_PID=$!
sleep 0.8

cleanup() { kill $SRV_PID 2>/dev/null || true; wait $SRV_PID 2>/dev/null || true; rm -f "$TICKET"; }
trap cleanup EXIT

# --- Phase 1: cert-ec handshake to get a ticket ---

echo "Phase 1: cert-ec handshake (get ticket)..."

TRUST_DER="${FIXTURES}/root.der"
"$TLS_CLI" client --connect "127.0.0.1:$PORT" \
  --mode cert-ec --trust "$TRUST_DER" \
  --hostname localhost \
  --save-ticket "$TICKET"
PHASE1=$?

if [ $PHASE1 -ne 0 ]; then
  echo "FAIL: Phase 1 (cert-ec) failed with exit $PHASE1"
  exit 1
fi

if [ ! -f "$TICKET" ]; then
  echo "FAIL: no ticket file saved at $TICKET"
  exit 1
fi
echo "Phase 1: OK (ticket saved: $(wc -c < "$TICKET") bytes)"

sleep 0.3

# --- Phase 2: psk-resume handshake using ticket (same server) ---

echo "Phase 2: psk-resume handshake..."

"$TLS_CLI" client --connect "127.0.0.1:$PORT" \
  --mode psk-resume --load-ticket "$TICKET"
PHASE2=$?

if [ $PHASE2 -ne 0 ]; then
  echo "FAIL: Phase 2 (psk-resume) failed with exit $PHASE2"
  exit 1
fi

echo "=== PASS: PSK resumption against $PEER ==="
