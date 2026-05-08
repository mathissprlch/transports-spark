#!/usr/bin/env bash
# scripts/interop/peers/boringssl.sh — peer driver for BoringSSL.
#
# Uses `bssl client` / `bssl server` (NOTE: not `s_client`/`s_server`
# — bssl uses subcommand-style CLI).
#
# IMPORTANT — PSK incompatibility: bssl's `-psk-hex` implements
# RFC 9258 "Imported External PSK" (2022), NOT RFC 8446 §4.2.11
# legacy external PSK that openssl / mbedtls / we use.  RFC 9258
# adds a context-binding KDF step on top of the raw PSK, producing
# a different binder than RFC 8446 alone.  bssl will reject our
# binder with PSK_IDENTITY_NOT_FOUND.  Implementing RFC 9258 import
# is a v0.6 candidate (the spec is small but adds key-schedule
# work).  Until then, PSK against bssl is documented incompatible
# and the driver returns 127 to keep the matrix honest.
#
# Cert-mode (cert-ec) works fine because BoringSSL follows RFC
# 8446 §4.4.2 / §4.4.3 verbatim there.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
EC="$REPO/crates/tls_core/tests/fixtures/interop/ec"

PSK_HEX="$(printf '42%.0s' {1..32})"
PSK_IDENT="Test"

peer_server() {
    local port="$1" mode="$2"
    case "$mode" in
        psk)
            echo "boringssl: -psk-hex is RFC 9258 (Imported PSK)," \
                 "incompatible with our RFC 8446 external PSK." >&2
            exit 127
            ;;
        cert-ec)
            exec bssl server \
                -accept "$port" \
                -cert "$EC/leaf.pem" -key "$EC/leaf.key" \
                -min-version tls1.3 -max-version tls1.3
            ;;
        *)  echo "boringssl: unsupported MODE $mode" >&2; exit 2 ;;
    esac
}

peer_client() {
    local host="$1" port="$2" mode="$3"
    case "$mode" in
        psk)
            echo "boringssl: -psk-hex is RFC 9258 (Imported PSK)," \
                 "incompatible with our RFC 8446 external PSK." >&2
            exit 127
            ;;
        cert-ec)
            exec bssl client \
                -connect "$host:$port" \
                -root-certs "$EC/root.pem" \
                -min-version tls1.3 -max-version tls1.3
            ;;
        *)  echo "boringssl: unsupported MODE $mode" >&2; exit 2 ;;
    esac
}

case "${1:-}" in
    peer_server) shift; peer_server "$@" ;;
    peer_client) shift; peer_client "$@" ;;
    *) echo "usage: $0 {peer_server|peer_client} ..." >&2; exit 2 ;;
esac
