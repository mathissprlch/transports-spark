#!/usr/bin/env bash
# scripts/interop/openssl_client.sh — drive `openssl s_client -tls1_3`
# against a TLS 1.3 server (ours or another openssl).
#
# Usage:
#   openssl_client.sh HOST PORT MODE [CIPHER] [GROUPS] [SIGALG] [ALPN]
#
# MODE = "psk" or "cert"
#   psk  : 32 bytes of 0x42 PSK, identity "Test", -nocert
#   cert : verifies server cert against EC root (or RSA root if SIGALG
#          looks RSA-PSS); -servername localhost.
#
# stdin: payload to send to the server, then EOF.
# stdout: openssl logs + server reply.
set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-4433}"
MODE="${3:-psk}"
CIPHER="${4:-}"
GROUPS="${5:-X25519}"
SIGALG="${6:-}"
ALPN="${7:-}"

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
EC="$REPO/crates/tls_core/tests/fixtures/interop/ec"
RSA="$REPO/crates/tls_core/tests/fixtures/interop/rsa"

PSK_HEX="$(printf '42%.0s' {1..32})"
PSK_IDENT="Test"

CIPHER_ARG=()
if [[ -n "$CIPHER" ]]; then
    CIPHER_ARG=(-ciphersuites "$CIPHER")
fi

GROUPS_ARG=()
if [[ -n "$GROUPS" ]]; then
    GROUPS_ARG=(-groups "$GROUPS")
fi

SIGALG_ARG=()
if [[ -n "$SIGALG" ]]; then
    SIGALG_ARG=(-sigalgs "$SIGALG")
fi

ALPN_ARG=()
if [[ -n "$ALPN" ]]; then
    ALPN_ARG=(-alpn "$ALPN")
fi

case "$MODE" in
    psk)
        exec openssl s_client -tls1_3 -connect "$HOST:$PORT" \
            -psk "$PSK_HEX" -psk_identity "$PSK_IDENT" \
            -servername localhost \
            "${CIPHER_ARG[@]}" "${GROUPS_ARG[@]}" \
            -quiet
        ;;
    cert-ec)
        exec openssl s_client -tls1_3 -connect "$HOST:$PORT" \
            -CAfile "$EC/root.pem" \
            -servername localhost \
            "${CIPHER_ARG[@]}" "${GROUPS_ARG[@]}" "${SIGALG_ARG[@]}" \
            "${ALPN_ARG[@]}"
        ;;
    cert-rsa)
        exec openssl s_client -tls1_3 -connect "$HOST:$PORT" \
            -CAfile "$RSA/root.pem" \
            -servername localhost \
            "${CIPHER_ARG[@]}" "${GROUPS_ARG[@]}" "${SIGALG_ARG[@]}" \
            "${ALPN_ARG[@]}"
        ;;
    *)
        echo "unknown MODE: $MODE  (psk|cert-ec|cert-rsa)" >&2
        exit 2
        ;;
esac
