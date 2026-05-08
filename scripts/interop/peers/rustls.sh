#!/usr/bin/env bash
# scripts/interop/peers/rustls.sh — peer driver for rustls (Rust).
#
# Status: stub.  Requires `tlsclient` / `tlsserver` from rustls-mio
# example crate.  Install:
#
#     cargo install --git https://github.com/rustls/rustls-mio \
#                   --bin tlsclient --bin tlsserver
#
# Or build from a local rustls checkout.  Once available on PATH,
# replace this stub with the openssl.sh-shaped driver.

set -uo pipefail

case "${1:-}" in
    peer_server|peer_client)
        echo "rustls peer not installed (cargo install rustls-mio binaries)" >&2
        exit 127
        ;;
    *)
        echo "usage: $0 {peer_server|peer_client} ..." >&2; exit 2 ;;
esac
