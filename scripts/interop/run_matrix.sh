#!/usr/bin/env bash
# scripts/interop/run_matrix.sh — Tier D multi-peer interop matrix.
#
# Drives our `tls_cli` binary (Ada side) against each available
# peer (openssl, gnutls, mbedtls, rustls, go, boringssl).
#
# Each peer is a driver script under peers/<peer>.sh that exposes
# `peer_server PORT MODE [CIPHER]` and `peer_client HOST PORT MODE [CIPHER]`.
# The matrix script knows nothing about per-peer CLI quirks — that's
# isolated to the driver.  Adding a new peer = drop a new file in
# peers/ and run the matrix.
#
# Cells are defined inline below: PSK chacha20 + PSK aes128 +
# (when wired) cert-ec — both directions per cell.
#
# Usage:
#   run_matrix.sh                  — run all available peers
#   run_matrix.sh --peer openssl   — run one peer column
#   run_matrix.sh --quick          — psk-chacha20 cells only
#   run_matrix.sh --peer go --quick — combine flags
#
# Output: a Markdown table with one row per (peer, cell, direction).
# Per-cell logs land under /tmp/spark-tls-interop/<timestamp>/.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PEER_DIR="$REPO/scripts/interop/peers"
TLS_CLI="$REPO/crates/examples/bin/tls_cli"

if [[ ! -x "$TLS_CLI" ]]; then
    echo "error: build the tls_cli binary first" >&2
    echo "       make matrix-build  (or alr -C crates/examples build)" >&2
    exit 1
fi

# Default: all peers, all cells.
PEERS_REQ="${PEERS:-}"
QUICK=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --peer)  PEERS_REQ="$2"; shift 2 ;;
        --quick) QUICK=1; shift ;;
        --help|-h)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# Resolve peer list.
if [[ -z "$PEERS_REQ" ]]; then
    PEERS=(openssl gnutls mbedtls rustls go boringssl)
else
    IFS=',' read -ra PEERS <<< "$PEERS_REQ"
fi

TS="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="/tmp/spark-tls-interop/$TS"
mkdir -p "$LOG_DIR"

NEXT_PORT=14430
alloc_port() { local p="$NEXT_PORT"; NEXT_PORT=$((NEXT_PORT + 1)); echo "$p"; }

cleanup_port() {
    local p="$1"
    pkill -f "accept $p" 2>/dev/null || true
    pkill -f "server_port=$p" 2>/dev/null || true
    pkill -f "tls_cli .* --bind .*:$p" 2>/dev/null || true
    pkill -f "gnutls-serv .* --port $p" 2>/dev/null || true
}

PSK_HEX="$(printf '42%.0s' {1..32})"
PSK_FILE="$LOG_DIR/psk32.bin"
printf '\x42%.0s' {1..32} > "$PSK_FILE"

# ----------------------------------------------------------------
# Markdown table emit helpers.
# ----------------------------------------------------------------

print_row() {
    printf "| %-10s | %-26s | %-7s | %s |\n" "$1" "$2" "$3" "$4"
}

print_row_header() {
    printf "| %-10s | %-26s | %-7s | %s |\n" \
        "Peer" "Cell" "Result" "Notes / log"
    printf "|%s|%s|%s|%s|\n" \
        "------------" "----------------------------" "---------" \
        "-------------"
}

# ----------------------------------------------------------------
# Per-peer-availability probe.
# ----------------------------------------------------------------

peer_available() {
    local peer="$1"
    local sh="$PEER_DIR/$peer.sh"
    [[ -x "$sh" ]] || return 1
    case "$peer" in
        openssl)   command -v openssl >/dev/null ;;
        gnutls)    command -v gnutls-cli >/dev/null \
                   && command -v gnutls-serv >/dev/null ;;
        mbedtls)   command -v ssl_client2 >/dev/null \
                   && command -v ssl_server2 >/dev/null ;;
        rustls)    command -v tlsclient-mio >/dev/null \
                   && command -v tlsserver-mio >/dev/null ;;
        go)        command -v go >/dev/null ;;
        boringssl) command -v bssl >/dev/null ;;
        *) return 1 ;;
    esac
}

# ----------------------------------------------------------------
# Cell runners.  Each takes (peer, cell-name, mode, cipher).
# ----------------------------------------------------------------

ada_cli_vs_peer_srv() {
    local peer="$1" cell="$2" mode="$3" cipher="${4:-}"
    local port; port="$(alloc_port)"
    local srv_log="$LOG_DIR/${peer}-${cell}-c2s-srv.log"
    local cli_log="$LOG_DIR/${peer}-${cell}-c2s-cli.log"

    "$PEER_DIR/$peer.sh" peer_server "$port" "$mode" "$cipher" \
        > "$srv_log" 2>&1 &
    local srv_pid=$!
    sleep 0.7
    # If the peer's driver said the mode isn't supported (exit 127),
    # the server process is already gone — mark N/A and skip the
    # client launch.  Distinguishes "peer doesn't speak this mode"
    # from "peer rejected our handshake."
    if ! kill -0 "$srv_pid" 2>/dev/null; then
        wait "$srv_pid" 2>/dev/null
        local rc=$?
        cleanup_port "$port"
        if [[ $rc -eq 127 ]]; then
            print_row "$peer" "$cell-c2s" "N/A" \
                "peer does not implement this mode"
            return
        fi
    fi

    case "$mode" in
        psk)
            "$TLS_CLI" client \
                --connect "127.0.0.1:$port" \
                --mode psk-dhe-ke \
                --psk-file "$PSK_FILE" --psk-id Test \
                --send "echo-from-ada-cli" --recv-len 17 \
                --quiet \
                > "$cli_log" 2>&1
            ;;
        cert-ec)
            "$TLS_CLI" client \
                --connect "127.0.0.1:$port" \
                --mode cert-ec \
                --hostname localhost \
                --send "echo-from-ada-cli" --recv-len 17 \
                --quiet \
                > "$cli_log" 2>&1
            ;;
    esac
    local cli_rc=$?
    kill "$srv_pid" 2>/dev/null || true
    wait "$srv_pid" 2>/dev/null || true
    cleanup_port "$port"

    if [[ $cli_rc -eq 0 ]]; then
        print_row "$peer" "$cell-c2s" "PASS" "$cli_log"
    else
        local why
        why="$(grep -m1 -E 'tls_cli: ERROR|alert|error:|fatal|FAIL' \
                "$cli_log" "$srv_log" 2>/dev/null \
                | head -1 | tr -d '\n' | head -c 100)"
        print_row "$peer" "$cell-c2s" "FAIL" "${why:-rc=$cli_rc, see $cli_log}"
    fi
}

peer_cli_vs_ada_srv() {
    local peer="$1" cell="$2" mode="$3" cipher="${4:-}"
    local port; port="$(alloc_port)"
    local srv_log="$LOG_DIR/${peer}-${cell}-s2c-srv.log"
    local cli_log="$LOG_DIR/${peer}-${cell}-s2c-cli.log"

    case "$mode" in
        psk)
            "$TLS_CLI" server \
                --bind "127.0.0.1:$port" \
                --mode psk-dhe-ke \
                --psk-file "$PSK_FILE" --psk-id Test \
                --echo \
                --quiet \
                > "$srv_log" 2>&1 &
            ;;
        cert-ec)
            "$TLS_CLI" server \
                --bind "127.0.0.1:$port" \
                --mode cert-ec \
                --echo \
                --quiet \
                > "$srv_log" 2>&1 &
            ;;
    esac
    local srv_pid=$!
    sleep 0.7

    printf 'echo-from-peer\n' \
        | "$PEER_DIR/$peer.sh" peer_client 127.0.0.1 "$port" "$mode" "$cipher" \
            > "$cli_log" 2>&1
    local cli_rc=$?
    sleep 0.3
    kill "$srv_pid" 2>/dev/null || true
    wait "$srv_pid" 2>/dev/null || true
    cleanup_port "$port"

    if [[ $cli_rc -eq 127 ]]; then
        print_row "$peer" "$cell-s2c" "N/A" \
            "peer does not implement this mode"
    elif [[ $cli_rc -eq 0 ]] && grep -q "tls_cli: OK" "$srv_log"; then
        print_row "$peer" "$cell-s2c" "PASS" "$cli_log"
    else
        local why
        why="$(grep -m1 -E 'tls_cli: ERROR|alert|error:|fatal|FAIL' \
                "$srv_log" "$cli_log" 2>/dev/null \
                | head -1 | tr -d '\n' | head -c 100)"
        print_row "$peer" "$cell-s2c" "FAIL" "${why:-rc=$cli_rc, see $srv_log}"
    fi
}

# ----------------------------------------------------------------
# Top-level run.
# ----------------------------------------------------------------

echo
echo "## Tier D matrix run — $TS"
echo "log dir: $LOG_DIR"
echo "peers requested: ${PEERS[*]}"
[[ $QUICK -eq 1 ]] && echo "mode: --quick (psk-chacha20 only)"
echo
print_row_header

# Always run the Ada-vs-Ada sanity baseline once, regardless of peer.
{
    port="$(alloc_port)"
    "$TLS_CLI" server \
        --bind "127.0.0.1:$port" \
        --mode psk-dhe-ke \
        --psk-file "$PSK_FILE" --psk-id Test \
        --echo --quiet \
        > "$LOG_DIR/aa-srv.log" 2>&1 &
    srv_pid=$!
    sleep 0.5
    "$TLS_CLI" client \
        --connect "127.0.0.1:$port" \
        --mode psk-dhe-ke \
        --psk-file "$PSK_FILE" --psk-id Test \
        --send "ada-vs-ada" --recv-len 10 --quiet \
        > "$LOG_DIR/aa-cli.log" 2>&1
    cli_rc=$?
    wait "$srv_pid" 2>/dev/null || true
    cleanup_port "$port"
    if [[ $cli_rc -eq 0 ]]; then
        print_row "ada-ada" "psk-chacha20-aa" "PASS" "sanity baseline"
    else
        print_row "ada-ada" "psk-chacha20-aa" "FAIL" "$LOG_DIR/aa-cli.log"
    fi
}

for peer in "${PEERS[@]}"; do
    if ! peer_available "$peer"; then
        print_row "$peer" "(all)" "SKIP" "binary not installed (see peers/$peer.sh)"
        continue
    fi

    # PSK + chacha20 — both directions
    ada_cli_vs_peer_srv "$peer" "psk-chacha20" "psk" "TLS_CHACHA20_POLY1305_SHA256"
    peer_cli_vs_ada_srv "$peer" "psk-chacha20" "psk" "TLS_CHACHA20_POLY1305_SHA256"

    if [[ $QUICK -eq 1 ]]; then
        continue
    fi

    # PSK + aes128 — both directions
    ada_cli_vs_peer_srv "$peer" "psk-aes128"   "psk" "TLS_AES_128_GCM_SHA256"
    peer_cli_vs_ada_srv "$peer" "psk-aes128"   "psk" "TLS_AES_128_GCM_SHA256"

    # cert-ec — both directions (driver wired in D-4; tls_cli CLI
    # plumbing currently stubs cert mode, so these will FAIL with a
    # clear "CLI plumbing pending" diagnostic until the cert flags
    # land in tls_cli.adb).
    ada_cli_vs_peer_srv "$peer" "cert-ec"      "cert-ec" ""
    peer_cli_vs_ada_srv "$peer" "cert-ec"      "cert-ec" ""
done

echo
echo "Logs: $LOG_DIR"
