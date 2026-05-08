#!/usr/bin/env bash
# scripts/interop/gen_pki.sh — generate Tier D interop PKI fixtures.
#
# Produces:
#   crates/tls_core/tests/fixtures/interop/ec/{root,leaf}.{key,pem}
#   crates/tls_core/tests/fixtures/interop/rsa/{root,leaf}.{key,pem}
#
# The EC fixture (P-256 + ecdsa_secp256r1_sha256) is what openssl
# s_server uses for the cert-mode interop cells; the RSA-PSS fixture
# is for the rsa_pss_rsae_sha256 cell.  Both leaf certs cover SAN =
# DNS:localhost, IP:127.0.0.1.
#
# Note (Tier D scope): cert-mode interop is currently *not* possible
# against our Ada Tls13_Driver, which is PSK-only.  The fixtures are
# generated for completeness of the openssl-side scripts and so that
# the openssl s_server can still run under a real cert (openssl needs
# one even when serving a PSK cipher unless `-nocert` is given).

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$REPO/crates/tls_core/tests/fixtures/interop"
EC="$OUT/ec"
RSA="$OUT/rsa"

mkdir -p "$EC" "$RSA"

echo "==> ECDSA-P256 root + leaf"
openssl ecparam -name prime256v1 -genkey -noout -out "$EC/root.key"
openssl req -x509 -new -key "$EC/root.key" -sha256 -days 3650 \
        -subj "/CN=Spark Interop EC Root" -out "$EC/root.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "$EC/leaf.key"
openssl req -new -key "$EC/leaf.key" -subj "/CN=localhost" -out "$EC/leaf.csr"
cat > "$EC/leaf.ext" <<'EOF'
[v3_req]
subjectAltName=DNS:localhost,IP:127.0.0.1
keyUsage=digitalSignature
extendedKeyUsage=serverAuth,clientAuth
EOF
openssl x509 -req -in "$EC/leaf.csr" -CA "$EC/root.pem" -CAkey "$EC/root.key" \
        -CAcreateserial -out "$EC/leaf.pem" -days 365 -sha256 \
        -extensions v3_req -extfile "$EC/leaf.ext" 2>/dev/null
rm -f "$EC/leaf.csr" "$EC/leaf.ext" "$EC/root.srl"

echo "==> RSA-2048 (rsa_pss_rsae_sha256) root + leaf"
openssl genrsa -out "$RSA/root.key" 2048 2>/dev/null
openssl req -x509 -new -key "$RSA/root.key" -sha256 -days 3650 \
        -subj "/CN=Spark Interop RSA Root" -out "$RSA/root.pem"
openssl genrsa -out "$RSA/leaf.key" 2048 2>/dev/null
openssl req -new -key "$RSA/leaf.key" -subj "/CN=localhost" -out "$RSA/leaf.csr"
cat > "$RSA/leaf.ext" <<'EOF'
[v3_req]
subjectAltName=DNS:localhost,IP:127.0.0.1
keyUsage=digitalSignature
extendedKeyUsage=serverAuth,clientAuth
EOF
# Sign with -sigopt for rsa_pss_rsae_sha256 mapping at handshake time.
openssl x509 -req -in "$RSA/leaf.csr" -CA "$RSA/root.pem" -CAkey "$RSA/root.key" \
        -CAcreateserial -out "$RSA/leaf.pem" -days 365 -sha256 \
        -extensions v3_req -extfile "$RSA/leaf.ext" 2>/dev/null
rm -f "$RSA/leaf.csr" "$RSA/leaf.ext" "$RSA/root.srl"

echo
echo "Generated under $OUT:"
find "$OUT" -type f | sort
