# tls_core test fixtures — real-PKI test data

This directory holds real DER X.509 certificates and the related private
keys + signatures the cert-mode handshake test scenarios in
`tls_core_tests.adb` exercise. These are checked into the repository so
the tests are stable across machines without requiring `openssl` at
build time. **The keys here are non-secret test material.**

## Files

| File | Purpose |
|---|---|
| `root.key` | ECDSA-P256 private key for the test root CA |
| `root.pem` / `root.der` | Self-signed root cert (CN=Test Root CA) |
| `leaf.key` | ECDSA-P256 private key for the test leaf cert |
| `leaf.pem` / `leaf.der` | leaf cert (CN=localhost), SAN = DNS:localhost, DNS:test.example.com, IP:127.0.0.1 |
| `signed_content.bin` | RFC 8446 §4.4.3 signed-content for a synthetic 32×0xAA transcript |
| `leaf.sig` | DER ECDSA-Sig-Value of `signed_content.bin` under `leaf.key` |

Both certs use `ecdsa-with-SHA256` as their signatureAlgorithm. The leaf
includes a v3 SubjectAltName extension with three entries.

## Regeneration

```sh
cd crates/tls_core/tests/fixtures
openssl ecparam -name prime256v1 -genkey -noout -out root.key
openssl req -x509 -new -key root.key -sha256 -days 3650 -out root.pem \
        -subj "/CN=Test Root CA"
openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
openssl req -new -key leaf.key -out leaf.csr -subj "/CN=localhost"
printf '%s\n' '[v3_req]' \
        'subjectAltName=DNS:localhost,DNS:test.example.com,IP:127.0.0.1' \
        > leaf.ext
openssl x509 -req -in leaf.csr -CA root.pem -CAkey root.key \
        -CAcreateserial -out leaf.pem -days 365 -sha256 \
        -extensions v3_req -extfile leaf.ext
openssl x509 -in root.pem -outform DER -out root.der
openssl x509 -in leaf.pem -outform DER -out leaf.der

python3 -c "
import sys
prefix = b' ' * 64 + b'TLS 1.3, server CertificateVerify' + b'\\x00'
transcript = bytes([0xAA] * 32)
sys.stdout.buffer.write(prefix + transcript)
" > signed_content.bin
openssl dgst -sha256 -sign leaf.key -out leaf.sig signed_content.bin
```

After regeneration, re-export the byte arrays into
`tls_core_tests.adb` (the embedded constants are auto-generated; see
the script under `# fmt:` comment near the cert scenario).
