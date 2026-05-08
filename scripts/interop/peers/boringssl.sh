#!/usr/bin/env bash
# scripts/interop/peers/boringssl.sh — peer driver for BoringSSL.
#
# Status: stub.  Requires `bssl` binary built from BoringSSL source:
#
#     git clone https://boringssl.googlesource.com/boringssl
#     cd boringssl && cmake -B build && cmake --build build
#     install build/tool/bssl  (or add to PATH)
#
# Once available, replace this stub.  bssl's CLI:
#   bssl s_client -psk HEX -psk-identity ID -connect host:port
#   bssl s_server -psk HEX -psk-identity ID -accept port

set -uo pipefail

case "${1:-}" in
    peer_server|peer_client)
        echo "boringssl peer not installed (build bssl from source)" >&2
        exit 127
        ;;
    *)
        echo "usage: $0 {peer_server|peer_client} ..." >&2; exit 2 ;;
esac
