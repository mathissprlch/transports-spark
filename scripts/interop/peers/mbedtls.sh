#!/usr/bin/env bash
# scripts/interop/peers/mbedtls.sh — peer driver for mbedTLS.
#
# Tested against `ssl_client2` / `ssl_server2` from `brew install mbedtls`.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
EC="$REPO/crates/tls_core/tests/fixtures/interop/ec"

PSK_HEX="$(printf '42%.0s' {1..32})"
PSK_IDENT="Test"

peer_server() {
    local port="$1" mode="$2"
    case "$mode" in
        psk)
            exec ssl_server2 \
                server_addr=127.0.0.1 server_port="$port" \
                tls13_kex_modes=psk_ephemeral \
                psk_identity="$PSK_IDENT" \
                psk="$PSK_HEX" \
                force_version=tls13 \
                exchanges=1
            ;;
        cert-ec)
            exec ssl_server2 \
                server_addr=127.0.0.1 server_port="$port" \
                crt_file="$EC/leaf.pem" \
                key_file="$EC/leaf.key" \
                ca_file="$EC/root.pem" \
                force_version=tls13 \
                exchanges=1
            ;;
        *)  echo "mbedtls: unsupported MODE $mode" >&2; exit 2 ;;
    esac
}

peer_client() {
    local host="$1" port="$2" mode="$3"
    case "$mode" in
        psk)
            exec ssl_client2 \
                server_addr="$host" server_port="$port" \
                tls13_kex_modes=psk_ephemeral \
                psk_identity="$PSK_IDENT" \
                psk="$PSK_HEX" \
                force_version=tls13 \
                exchanges=1
            ;;
        cert-ec)
            exec ssl_client2 \
                server_addr="$host" server_port="$port" \
                ca_file="$EC/root.pem" \
                force_version=tls13 \
                exchanges=1
            ;;
        *)  echo "mbedtls: unsupported MODE $mode" >&2; exit 2 ;;
    esac
}

case "${1:-}" in
    peer_server) shift; peer_server "$@" ;;
    peer_client) shift; peer_client "$@" ;;
    *) echo "usage: $0 {peer_server|peer_client} ..." >&2; exit 2 ;;
esac
