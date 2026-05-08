#!/usr/bin/env bash
# scripts/interop/peers/go.sh — peer driver for Go crypto/tls.
#
# Wraps small Go programs at scripts/interop/peers/go-helpers/.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
EC="$REPO/crates/tls_core/tests/fixtures/interop/ec"
HELPERS="$REPO/scripts/interop/peers/go-helpers"

PSK_HEX="$(printf '42%.0s' {1..32})"
PSK_IDENT="Test"

peer_server() {
    local port="$1" mode="$2"
    case "$mode" in
        psk)
            # NOTE: Go crypto/tls does NOT expose external-PSK API
            # in standard library (https://github.com/golang/go/issues/47643).
            # PSK column for Go is therefore unavailable until either
            # we vendor a third-party crypto/tls fork or skip PSK
            # against Go.  Cert-mode is fully supported.
            echo "go: PSK not supported by stdlib crypto/tls" >&2
            exit 127
            ;;
        cert-ec)
            exec go run "$HELPERS/server.go" \
                --addr "127.0.0.1:$port" \
                --cert "$EC/leaf.pem" --key "$EC/leaf.key"
            ;;
        *)  echo "go: unsupported MODE $mode" >&2; exit 2 ;;
    esac
}

peer_client() {
    local host="$1" port="$2" mode="$3"
    case "$mode" in
        psk)
            echo "go: PSK not supported by stdlib crypto/tls" >&2
            exit 127
            ;;
        cert-ec)
            exec go run "$HELPERS/client.go" \
                --addr "$host:$port" --root "$EC/root.pem"
            ;;
        *)  echo "go: unsupported MODE $mode" >&2; exit 2 ;;
    esac
}

case "${1:-}" in
    peer_server) shift; peer_server "$@" ;;
    peer_client) shift; peer_client "$@" ;;
    *) echo "usage: $0 {peer_server|peer_client} ..." >&2; exit 2 ;;
esac
