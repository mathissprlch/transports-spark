#!/usr/bin/env bash
# scripts/interop/peers/gnutls.sh — peer driver for GnuTLS.
#
# Tested against gnutls-cli/serv 3.x.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
EC="$REPO/crates/tls_core/tests/fixtures/interop/ec"

PSK_HEX="$(printf '42%.0s' {1..32})"
PSK_IDENT="Test"
PSK_FILE="/tmp/spark-tls-gnutls-psk.txt"

# GnuTLS PSK file format: "identity:hex_psk"
ensure_psk_file() {
    printf '%s:%s\n' "$PSK_IDENT" "$PSK_HEX" > "$PSK_FILE"
}

peer_server() {
    local port="$1" mode="$2"
    ensure_psk_file
    case "$mode" in
        psk)
            exec gnutls-serv --port "$port" \
                --pskpasswd "$PSK_FILE" \
                --priority "NONE:+VERS-TLS1.3:+AEAD:+SHA256:+AES-128-GCM:+CHACHA20-POLY1305:+ECDHE-PSK:+CURVE-X25519:+GROUP-X25519:+CTYPE-X509:+SIGN-RSA-SHA256:+SIGN-ECDSA-SHA256" \
                --echo
            ;;
        cert-ec)
            exec gnutls-serv --port "$port" \
                --x509certfile "$EC/leaf.pem" \
                --x509keyfile "$EC/leaf.key" \
                --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3" \
                --echo
            ;;
        *)  echo "gnutls: unsupported MODE $mode" >&2; exit 2 ;;
    esac
}

peer_client() {
    local host="$1" port="$2" mode="$3"
    ensure_psk_file
    case "$mode" in
        psk)
            exec gnutls-cli "$host" --port "$port" \
                --pskusername "$PSK_IDENT" \
                --pskkey "$PSK_HEX" \
                --priority "NONE:+VERS-TLS1.3:+AEAD:+SHA256:+AES-128-GCM:+CHACHA20-POLY1305:+ECDHE-PSK:+CURVE-X25519:+GROUP-X25519:+CTYPE-X509:+SIGN-RSA-SHA256:+SIGN-ECDSA-SHA256"
            ;;
        cert-ec)
            exec gnutls-cli "$host" --port "$port" \
                --x509cafile "$EC/root.pem" \
                --priority "NORMAL:-VERS-ALL:+VERS-TLS1.3"
            ;;
        *)  echo "gnutls: unsupported MODE $mode" >&2; exit 2 ;;
    esac
}

case "${1:-}" in
    peer_server) shift; peer_server "$@" ;;
    peer_client) shift; peer_client "$@" ;;
    *) echo "usage: $0 {peer_server|peer_client} ..." >&2; exit 2 ;;
esac
