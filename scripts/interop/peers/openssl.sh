#!/usr/bin/env bash
# scripts/interop/peers/openssl.sh — peer driver for openssl (3.x).
#
# A peer driver exposes two commands the matrix script invokes:
#
#   peer_server PORT MODE CIPHER          - launch this peer as server
#   peer_client HOST PORT MODE CIPHER     - launch this peer as client
#
# It does NOT decide the matrix layout — that's run_matrix.sh's job.
#
# MODE is one of: psk | cert-ec | cert-rsa
# CIPHER is the openssl ciphersuite name (TLS_CHACHA20_POLY1305_SHA256, …)

set -uo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
EC="$REPO/crates/tls_core/tests/fixtures/interop/ec"

PSK_HEX="$(printf '42%.0s' {1..32})"
PSK_IDENT="Test"

peer_server() {
    local port="$1" mode="$2" cipher="${3:-}"
    local cipher_arg=()
    [[ -n "$cipher" ]] && cipher_arg=(-ciphersuites "$cipher")
    case "$mode" in
        psk)
            exec openssl s_server -tls1_3 -accept "$port" \
                -psk "$PSK_HEX" -psk_identity "$PSK_IDENT" \
                -nocert -naccept 1 -quiet \
                "${cipher_arg[@]}" \
                < <(printf 'echo-from-openssl-psk')
            ;;
        cert-ec)
            exec openssl s_server -tls1_3 -accept "$port" \
                -cert "$EC/leaf.pem" -key "$EC/leaf.key" \
                -CAfile "$EC/root.pem" -naccept 1 -quiet \
                "${cipher_arg[@]}"
            ;;
        *)  echo "openssl: unsupported MODE $mode" >&2; exit 2 ;;
    esac
}

peer_client() {
    local host="$1" port="$2" mode="$3" cipher="${4:-}"
    local cipher_arg=()
    [[ -n "$cipher" ]] && cipher_arg=(-ciphersuites "$cipher")
    case "$mode" in
        psk)
            exec openssl s_client -tls1_3 -connect "$host:$port" \
                -psk "$PSK_HEX" -psk_identity "$PSK_IDENT" \
                -quiet "${cipher_arg[@]}"
            ;;
        cert-ec)
            exec openssl s_client -tls1_3 -connect "$host:$port" \
                -CAfile "$EC/root.pem" -verify_return_error \
                -quiet "${cipher_arg[@]}"
            ;;
        *)  echo "openssl: unsupported MODE $mode" >&2; exit 2 ;;
    esac
}

case "${1:-}" in
    peer_server) shift; peer_server "$@" ;;
    peer_client) shift; peer_client "$@" ;;
    *) echo "usage: $0 {peer_server|peer_client} ..." >&2; exit 2 ;;
esac
