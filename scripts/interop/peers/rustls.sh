#!/usr/bin/env bash
# scripts/interop/peers/rustls.sh — peer driver for rustls.
#
# Uses tlsclient-mio / tlsserver-mio from the rustls examples
# crate (`cargo install … rustls-examples`).
#
# IMPORTANT: rustls's example CLIs do NOT expose external-PSK.
# rustls the LIBRARY supports it, but tlsclient-mio/tlsserver-mio
# only take cert-mode flags (--auth-key, --auth-certs).  This
# driver therefore returns 127 ("not supported") for PSK and only
# implements cert-ec.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
EC="$REPO/crates/tls_core/tests/fixtures/interop/ec"

peer_server() {
    local port="$1" mode="$2"
    case "$mode" in
        psk)
            echo "rustls: external PSK not exposed by rustls-mio examples" >&2
            exit 127
            ;;
        cert-ec)
            # tlsserver-mio requires a subcommand: echo / http / forward.
            # We use 'echo' to mirror our other peer drivers.
            exec tlsserver-mio \
                --port "$port" \
                --certs "$EC/leaf.pem" \
                --key "$EC/leaf.key" \
                echo
            ;;
        *)  echo "rustls: unsupported MODE $mode" >&2; exit 2 ;;
    esac
}

peer_client() {
    local host="$1" port="$2" mode="$3"
    case "$mode" in
        psk)
            echo "rustls: external PSK not exposed by rustls-mio examples" >&2
            exit 127
            ;;
        cert-ec)
            # tlsclient-mio reads from stdin and sends to server,
            # then prints what server sent back to stdout.
            exec tlsclient-mio \
                --port "$port" \
                --cafile "$EC/root.pem" \
                "$host"
            ;;
        *)  echo "rustls: unsupported MODE $mode" >&2; exit 2 ;;
    esac
}

case "${1:-}" in
    peer_server) shift; peer_server "$@" ;;
    peer_client) shift; peer_client "$@" ;;
    *) echo "usage: $0 {peer_server|peer_client} ..." >&2; exit 2 ;;
esac
