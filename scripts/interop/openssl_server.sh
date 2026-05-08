#!/usr/bin/env bash
# scripts/interop/openssl_server.sh — start an openssl s_server for
# the Tier D interop matrix.
#
# Usage:
#   openssl_server.sh PORT MODE [CIPHER] [GROUPS] [SIGALG]
#
# MODE = "psk" or "cert"
#   psk  : --psk-only PSK_HEX = 32 bytes of 0x42 (matches our driver)
#          identity = "Test"
#   cert : EC fixture (ecdsa_secp256r1_sha256), bound on PORT
#
# Optional knobs (CIPHER / GROUPS / SIGALG) override the defaults
# negotiated by openssl 3.x; the matrix driver passes them per cell.
#
# Output (stdout): openssl logs, including handshake details, until
# the client closes / 5-second idle timeout.
set -euo pipefail

PORT="${1:-4433}"
MODE="${2:-psk}"
CIPHER="${3:-}"
GROUPS="${4:-X25519}"
SIGALG="${5:-}"

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
EC="$REPO/crates/tls_core/tests/fixtures/interop/ec"
RSA="$REPO/crates/tls_core/tests/fixtures/interop/rsa"

PSK_HEX="$(printf '42%.0s' {1..32})"   # 32 bytes of 0x42
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

case "$MODE" in
    psk)
        # PSK-only.  -nocert suppresses the cert chain so openssl
        # negotiates psk_dhe_ke (mode 3) — what our Tls13_Driver
        # speaks.  No -allow_no_dhe_kex (mode 1 is out of scope).
        exec openssl s_server -tls1_3 -accept "$PORT" \
            -psk "$PSK_HEX" -psk_identity "$PSK_IDENT" \
            -nocert -www \
            "${CIPHER_ARG[@]}" "${GROUPS_ARG[@]}"
        ;;
    cert-ec)
        exec openssl s_server -tls1_3 -accept "$PORT" \
            -cert "$EC/leaf.pem" -key "$EC/leaf.key" \
            -CAfile "$EC/root.pem" \
            "${CIPHER_ARG[@]}" "${GROUPS_ARG[@]}" "${SIGALG_ARG[@]}"
        ;;
    cert-rsa)
        exec openssl s_server -tls1_3 -accept "$PORT" \
            -cert "$RSA/leaf.pem" -key "$RSA/leaf.key" \
            -CAfile "$RSA/root.pem" \
            "${CIPHER_ARG[@]}" "${GROUPS_ARG[@]}" "${SIGALG_ARG[@]}"
        ;;
    *)
        echo "unknown MODE: $MODE  (psk|cert-ec|cert-rsa)" >&2
        exit 2
        ;;
esac
