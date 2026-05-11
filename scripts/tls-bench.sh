#!/usr/bin/env bash
set -uo pipefail

# tls-bench.sh — TLS 1.3 performance benchmark against real peers.
#
# Runs handshake latency and bulk throughput scenarios against openssl
# (and optionally other peers), reports per-run results, mean, and
# std dev. Designed to be re-run after each optimisation pass.
#
# Usage:
#   scripts/tls-bench.sh [--runs N] [--bytes N] [--peer PEER] [--quick]
#
# Defaults: 5 runs, 10 MiB throughput, openssl peer, all scenarios.
# --quick: 3 runs, 1 MiB throughput, handshake only.
#
# Requires: BUILD_MODE=release build of tls_cli + tls_perf_bench,
#           openssl (or specified peer) in PATH.

RUNS=5
BYTES=$((10 * 1048576))
PEER=openssl
QUICK=false
OPT_LEVEL=2
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$REPO/crates/examples/bin/tls_cli"
FIXTURES="$REPO/crates/tls_core/tests/fixtures/interop/ec"
WARMUP_FRAC=0  # no warmup discard for now — measure everything

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs)   RUNS="$2"; shift 2;;
    --bytes)  BYTES="$2"; shift 2;;
    --peer)   PEER="$2"; shift 2;;
    --quick)  QUICK=true; RUNS=3; BYTES=$((1 * 1048576)); shift;;
    --opt)    OPT_LEVEL="$2"; shift 2;;
    -h|--help)
      echo "Usage: tls-bench.sh [--runs N] [--bytes N] [--peer PEER] [--quick]"
      exit 0;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

# -- helpers --

stats() {
  # Read values from stdin (one per line), print: mean stddev min max
  awk '{
    sum += $1; sumsq += $1*$1; n++;
    if (n==1 || $1<min) min=$1;
    if (n==1 || $1>max) max=$1;
    vals[n] = $1;
  } END {
    mean = sum/n;
    var = sumsq/n - mean*mean;
    if (var < 0) var = 0;
    sd = sqrt(var);
    printf "%.3f %.3f %.3f %.3f", mean, sd, min, max;
  }'
}

pick_port() {
  echo $(( (RANDOM % 20000) + 20000 ))
}

echo "=== SPARK TLS 1.3 Performance Benchmark ==="
echo ""
echo "Date:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Host:     $(uname -n) ($(uname -m))"
echo "OS:       $(uname -s) $(uname -r)"
echo "Peer:     $PEER ($(command -v $PEER 2>/dev/null || echo 'not found'))"
echo "Runs:     $RUNS"
echo "Payload:  $((BYTES / 1048576)) MiB"
echo "Build:    BUILD_MODE=release -O${OPT_LEVEL} -gnatn"
echo ""

# =====================================================================
# Scenario 1: Crypto primitive micro-bench (in-process, no TCP)
# =====================================================================
echo "## Scenario 1: Crypto Primitives (in-process, -O2)"
echo ""
"$REPO/crates/tls_core/tests/bin/tls_perf_bench" 2>&1 | grep -v "^===" | sed 's/^/  /'
echo ""

# =====================================================================
# Scenario 2: Handshake latency (cert-ec, Ada client → peer server)
# =====================================================================
echo "## Scenario 2: Handshake Latency (cert-ec, c2s)"
echo ""

PORT=$(pick_port)
PEER_LOG="/tmp/tls-bench-peer-$$.log"
RESULTS_HS=()

# Start peer server
echo "  | Run | Handshake (ms) |"
echo "  |-----|----------------|"

for R in $(seq 1 "$RUNS"); do
  PORT=$(pick_port)
  case "$PEER" in
    openssl)
      openssl s_server -accept "$PORT" -cert "$FIXTURES/leaf.pem" \
        -key "$FIXTURES/leaf.key" -tls1_3 -quiet \
        -naccept 1 -num_tickets 0 \
        >/dev/null 2>&1 &
      ;;
    *) echo "  Peer $PEER not wired"; break;;
  esac
  PEER_PID=$!
  sleep 0.3
  T0=$(python3 -c "import time; print(int(time.time()*1e9))")
  "$CLI" client --connect "127.0.0.1:$PORT" --mode cert-ec \
    --trust "$FIXTURES/root.der" --hostname localhost \
    --quiet 2>/dev/null || true
  T1=$(python3 -c "import time; print(int(time.time()*1e9))")
  MS=$(python3 -c "print(f'{($T1 - $T0) / 1e6:.1f}')")
  RESULTS_HS+=("$MS")
  echo "  |  $R  | $MS |"
  kill "$PEER_PID" 2>/dev/null; wait "$PEER_PID" 2>/dev/null || true
done

STATS_HS=$(printf '%s\n' "${RESULTS_HS[@]}" | stats)
read -r HS_MEAN HS_SD HS_MIN HS_MAX <<< "$STATS_HS"
echo ""
echo "  Mean: ${HS_MEAN} ms  Std Dev: ${HS_SD} ms  Min: ${HS_MIN} ms  Max: ${HS_MAX} ms"
echo ""

if $QUICK; then
  echo "(--quick: skipping throughput scenario)"
  echo ""
  echo "=== Done ==="
  exit 0
fi

# =====================================================================
# Scenario 3: Bulk throughput (Ada client → peer server, cert-ec)
# =====================================================================
echo "## Scenario 3: Bulk Throughput (cert-ec, c2s, $((BYTES/1048576)) MiB)"
echo ""

RESULTS_TP=()

echo "  | Run | MiB/s |"
echo "  |-----|-------|"

for R in $(seq 1 "$RUNS"); do
  PORT=$(pick_port)
  case "$PEER" in
    openssl)
      openssl s_server -accept "$PORT" -cert "$FIXTURES/leaf.pem" \
        -key "$FIXTURES/leaf.key" -tls1_3 -quiet \
        -naccept 1 \
        >/dev/null 2>&1 &
      ;;
  esac
  PEER_PID=$!
  sleep 0.3
  LINE=$("$CLI" client --connect "127.0.0.1:$PORT" --mode cert-ec \
    --trust "$FIXTURES/root.der" --hostname localhost \
    --bench-throughput --bench-bytes "$BYTES" --quiet 2>&1 \
    | grep "BENCH_THROUGHPUT:" || echo "BENCH_THROUGHPUT: 0 B in 0 s = 0 MiB/s")
  MIBS=$(echo "$LINE" | grep -oE '[0-9]+ MiB/s' | awk '{print $1}')
  MIBS=${MIBS:-0}
  RESULTS_TP+=("$MIBS")
  echo "  |  $R  | $MIBS |"
  kill "$PEER_PID" 2>/dev/null; wait "$PEER_PID" 2>/dev/null || true
done

if [[ ${#RESULTS_TP[@]} -gt 0 ]]; then
  STATS_TP=$(printf '%s\n' "${RESULTS_TP[@]}" | stats)
  read -r TP_MEAN TP_SD TP_MIN TP_MAX <<< "$STATS_TP"
  echo ""
  echo "  Mean: ${TP_MEAN} MiB/s  Std Dev: ${TP_SD} MiB/s  Min: ${TP_MIN} MiB/s  Max: ${TP_MAX} MiB/s"
fi
echo ""

echo "=== Done ==="
