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

echo "==> DER + raw-scalar derivatives (consumed by Ada tls_cli)"
# Cert PEM → DER bytes (one X.509 v3 cert each).
openssl x509 -in "$EC/root.pem" -outform DER -out "$EC/root.der"
openssl x509 -in "$EC/leaf.pem" -outform DER -out "$EC/leaf.der"
openssl x509 -in "$RSA/root.pem" -outform DER -out "$RSA/root.der"
openssl x509 -in "$RSA/leaf.pem" -outform DER -out "$RSA/leaf.der"

# EC private scalar — extract the raw 32-byte big-endian integer
# from the SEC1 EC private-key DER.  Layout (for prime256v1):
#   SEQUENCE {
#     INTEGER 1,
#     OCTET STRING (32 bytes)  <- the scalar
#     [0] OID prime256v1,
#     [1] BIT STRING public key
#   }
# The 32-byte scalar starts at offset 7 (2 bytes SEQUENCE header,
# 3 bytes INTEGER 1, 2 bytes OCTET STRING tag+len).  Verified
# offset against `openssl asn1parse -in leaf.key`.
openssl ec -in "$EC/leaf.key" -outform DER 2>/dev/null \
  | dd bs=1 skip=7 count=32 of="$EC/leaf.priv" 2>/dev/null

# RSA private key — full DER (RFC 8017 RSAPrivateKey ASN.1).  Our
# driver Init_Cert_Server takes only the 32-byte EC scalar today;
# RSA-server signing is a v0.5.x extension.  We still emit the DER
# for completeness so peer tools can be offered RSA fixtures.
openssl rsa -in "$RSA/leaf.key" -outform DER \
        -out "$RSA/leaf.key.der" 2>/dev/null

echo
echo "Generated under $OUT:"
find "$OUT" -type f | sort
