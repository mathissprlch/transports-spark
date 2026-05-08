#!/usr/bin/env bash
# scripts/interop/run_matrix.sh — Tier D external interop matrix.
#
# For each (peer, direction, cell) tuple defined below, this script:
#
#   1. Spawns the appropriate peer (openssl s_server / s_client, or
#      our Ada tls_interop_{client,server}).
#   2. Runs the opposite peer against it.
#   3. Captures stdout + stderr + exit codes.
#   4. Decides PASS/FAIL based on exit codes.
#   5. Emits a one-row Markdown summary.
#
# Output: a Markdown table on stdout suitable for inclusion in
# docs/v0.5-interop-matrix.md.  Per-cell logs go under
# /tmp/spark-tls-interop/<timestamp>/.
#
# This harness does NOT pretend to fix the underlying impl.  When a
# cell fails, the LOG contains the peer's diagnostic so the matrix
# doc can quote the root cause honestly per CLAUDE.md §6.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
ADA_CLI="$REPO/crates/examples/bin/tls_interop_client"
ADA_SRV="$REPO/crates/examples/bin/tls_interop_server"
OSS_CLI="$REPO/scripts/interop/openssl_client.sh"
OSS_SRV="$REPO/scripts/interop/openssl_server.sh"

if [[ ! -x "$ADA_CLI" ]] || [[ ! -x "$ADA_SRV" ]]; then
    echo "error: build crates/examples first  (alr -C crates/examples build)" >&2
    exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="/tmp/spark-tls-interop/$TS"
mkdir -p "$LOG_DIR"

# Each cell gets a unique port to avoid TIME_WAIT collisions.
NEXT_PORT=14430
alloc_port() { local p="$NEXT_PORT"; NEXT_PORT=$((NEXT_PORT + 1)); echo "$p"; }

cleanup_port() {
    local p="$1"
    pkill -f "s_server.*-accept $p" 2>/dev/null || true
    pkill -f "tls_interop_server.*--port $p" 2>/dev/null || true
}

# Print a markdown row.
print_row() {
    printf "| %-26s | %-7s | %-6s | %s |\n" "$1" "$2" "$3" "$4"
}

print_row_header() {
    printf "| %-26s | %-7s | %-6s | %s |\n" "Cell" "Peer" "Result" "Notes / log"
    printf "|%s|%s|%s|%s|\n" \
        "----------------------------" "---------" "--------" "-------------"
}

# Run "Ada client vs openssl server" with the given args.
# Args: $1=cell-name $2=cipher $3=extra-server-args
ada_cli_vs_oss_srv() {
    local cell="$1" cipher="$2"
    local port; port="$(alloc_port)"
    local srv_log="$LOG_DIR/${cell}-srv.log" cli_log="$LOG_DIR/${cell}-cli.log"

    "$OSS_SRV" "$port" psk "$cipher" > "$srv_log" 2>&1 &
    local srv_pid=$!
    sleep 0.6
    "$ADA_CLI" --host 127.0.0.1 --port "$port" > "$cli_log" 2>&1
    local cli_rc=$?
    kill "$srv_pid" 2>/dev/null || true
    wait "$srv_pid" 2>/dev/null || true
    cleanup_port "$port"

    if [[ $cli_rc -eq 0 ]]; then
        print_row "$cell" "openssl" "PASS"   "ada-cli ok; logs $cli_log"
    else
        # Prefer peer's diagnostic (openssl knows precisely why it
        # rejected our handshake) — fall back to our own log.
        local why
        why="$(grep -m1 -E 'tls_psk_do_binder|alert|error:|SSL[ _]routines' \
                "$srv_log" 2>/dev/null \
                | sed -E 's/^[^:]*:error:[^:]*:SSL routines://; s/:[^:]*:[0-9]+:$//' \
                | head -c 110 | tr '\n' ' ' || true)"
        if [[ -z "$why" ]]; then
            why="$(grep -m1 -E 'FAIL:|exception' "$cli_log" \
                    | head -c 110 | tr '\n' ' ' || true)"
        fi
        print_row "$cell" "openssl" "FAIL"   "${why:-no diag}"
    fi
}

# Run "openssl client vs Ada server" with the given args.
# Args: $1=cell-name $2=cipher
oss_cli_vs_ada_srv() {
    local cell="$1" cipher="$2"
    local port; port="$(alloc_port)"
    local srv_log="$LOG_DIR/${cell}-srv.log" cli_log="$LOG_DIR/${cell}-cli.log"

    "$ADA_SRV" --host 127.0.0.1 --port "$port" > "$srv_log" 2>&1 &
    local srv_pid=$!
    sleep 0.6

    # Feed the openssl client a tiny payload so it has something to
    # send post-handshake; the Ada server echoes it back.
    printf 'echo-from-openssl-cli' \
        | "$OSS_CLI" 127.0.0.1 "$port" psk "$cipher" \
            > "$cli_log" 2>&1
    local cli_rc=$?
    sleep 0.5
    kill "$srv_pid" 2>/dev/null || true
    wait "$srv_pid" 2>/dev/null || true
    cleanup_port "$port"

    # Decision: server reaches Done iff the Ada server log says so.
    if grep -q "tls_interop_server: OK" "$srv_log"; then
        print_row "$cell" "openssl" "PASS"   "ada-srv ok; logs $srv_log"
    else
        local why
        why="$(grep -m1 -E 'FAIL:|state =' "$srv_log" \
                | head -c 110 | tr '\n' ' ' || true)"
        if [[ -z "$why" ]]; then
            why="$(grep -m1 -E 'tls_psk_do_binder|alert|error:|SSL[ _]routines' \
                    "$cli_log" 2>/dev/null \
                    | head -c 110 | tr '\n' ' ' || true)"
        fi
        print_row "$cell" "openssl" "FAIL"   "${why:-no diag}"
    fi
}

# Sanity baseline — Ada-vs-Ada PSK (already exercised by Tcp_Loopback_Scenario;
# this duplicates that check at the binary level).
ada_vs_ada_psk() {
    local cell="$1"
    local port; port="$(alloc_port)"
    local srv_log="$LOG_DIR/${cell}-srv.log" cli_log="$LOG_DIR/${cell}-cli.log"

    "$ADA_SRV" --host 127.0.0.1 --port "$port" > "$srv_log" 2>&1 &
    local srv_pid=$!
    sleep 0.6
    "$ADA_CLI" --host 127.0.0.1 --port "$port" > "$cli_log" 2>&1
    local cli_rc=$?
    wait "$srv_pid" 2>/dev/null || true
    cleanup_port "$port"
    if [[ $cli_rc -eq 0 ]] && grep -q "tls_interop_server: OK" "$srv_log"; then
        print_row "$cell" "ada-ada"  "PASS"   "self-test (sanity baseline)"
    else
        print_row "$cell" "ada-ada"  "FAIL"   "rc=$cli_rc; check $srv_log/$cli_log"
    fi
}

echo
echo "## Tier D matrix run — $TS"
echo "log dir: $LOG_DIR"
echo
print_row_header

# Sanity (must pass — same path as Tcp_Loopback_Scenario unit test).
ada_vs_ada_psk          "psk-x25519-chacha20-aa"

# Cell 1: PSK + x25519 + chacha20-poly1305-sha256, both directions.
ada_cli_vs_oss_srv      "psk-x25519-chacha20-c2s" \
                        "TLS_CHACHA20_POLY1305_SHA256"
oss_cli_vs_ada_srv      "psk-x25519-chacha20-s2c" \
                        "TLS_CHACHA20_POLY1305_SHA256"

# Cell 2: PSK + x25519 + AES-128-GCM-SHA256, both directions.
ada_cli_vs_oss_srv      "psk-x25519-aes128-c2s" \
                        "TLS_AES_128_GCM_SHA256"
oss_cli_vs_ada_srv      "psk-x25519-aes128-s2c" \
                        "TLS_AES_128_GCM_SHA256"

# Cell 3: PSK + x25519 + AES-256-GCM-SHA384.  Driver's key-schedule
# path is SHA-256-only at this slice (see Tls13_Driver.ads wall-hit
# note); openssl restricting to AES-256-SHA384 will force handshake
# failure on our side.  Cell expected to FAIL — root cause documented.
ada_cli_vs_oss_srv      "psk-x25519-aes256-c2s" \
                        "TLS_AES_256_GCM_SHA384"
oss_cli_vs_ada_srv      "psk-x25519-aes256-s2c" \
                        "TLS_AES_256_GCM_SHA384"

# Cert-mode cells (skipped — no Init_Cert_* path on Tls13_Driver).
print_row "cert-ec-c2s" "openssl" "DEFER" "Tls13_Driver is PSK-only (see matrix doc)"
print_row "cert-ec-s2c" "openssl" "DEFER" "Tls13_Driver is PSK-only"
print_row "cert-rsa-c2s" "openssl" "DEFER" "Tls13_Driver is PSK-only"

# HRR / ALPN / SNI cells (TODO — needs additional driver-level
# ALPN extension handling and an HRR-aware client init in the harness).
print_row "hrr-named-group"  "openssl" "DEFER" "HRR requires Init_Psk_Client_Hrr_Aware wiring"
print_row "alpn-h2"          "openssl" "DEFER" "ALPN extension not in Tls13_Driver hello surface"
print_row "sni-localhost"    "openssl" "DEFER" "SNI extension not in Tls13_Driver hello surface"

echo
echo "Logs: $LOG_DIR"
