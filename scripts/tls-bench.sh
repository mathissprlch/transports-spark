#!/usr/bin/env bash
set -uo pipefail

# tls-bench.sh — TLS 1.3 performance benchmark: SPARK Ada vs peers.
#
# Measures handshake latency and bulk throughput for both:
#   (a) Ada client → peer server  (our stack under test)
#   (b) peer client → peer server (reference / baseline)
# Reports per-run values, mean, std dev for both.

RUNS=5
BYTES=$((10 * 1048576))
PEER=openssl
QUICK=false
OPT_LEVEL=2
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$REPO/crates/examples/bin/tls_cli"
FIXTURES="$REPO/crates/tls_core/tests/fixtures/interop/ec"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs)   RUNS="$2"; shift 2;;
    --bytes)  BYTES="$2"; shift 2;;
    --peer)   PEER="$2"; shift 2;;
    --opt)    OPT_LEVEL="$2"; shift 2;;
    --quick)  QUICK=true; RUNS=3; BYTES=$((1 * 1048576)); shift;;
    -h|--help)
      echo "Usage: tls-bench.sh [--runs N] [--bytes N] [--peer PEER] [--opt LEVEL] [--quick]"
      exit 0;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

now_ns() { python3 -c "import time; print(int(time.time()*1e9))"; }

stats() {
  awk '{
    sum += $1; sumsq += $1*$1; n++;
    if (n==1 || $1<min) min=$1;
    if (n==1 || $1>max) max=$1;
  } END {
    mean = sum/n;
    var = sumsq/n - mean*mean;
    if (var < 0) var = 0;
    sd = sqrt(var);
    printf "%.2f %.2f %.2f %.2f", mean, sd, min, max;
  }'
}

pick_port() { echo $(( (RANDOM % 20000) + 20000 )); }

PAYLOAD_MB=$((BYTES / 1048576))

echo "# SPARK TLS 1.3 Performance Report"
echo ""
echo "| Parameter | Value |"
echo "|-----------|-------|"
echo "| Date | $(date -u +%Y-%m-%dT%H:%M:%SZ) |"
echo "| Host | $(uname -n) ($(uname -m)) |"
echo "| OS | $(uname -s) $(uname -r) |"
echo "| Peer | $PEER ($(openssl version 2>/dev/null || echo '?')) |"
echo "| Runs | $RUNS |"
echo "| Payload | ${PAYLOAD_MB} MiB |"
echo "| Build | BUILD_MODE=release -O${OPT_LEVEL} -gnatn, logging stripped |"
echo ""

# =====================================================================
# 1. Crypto Primitives (in-process)
# =====================================================================
echo "## 1. Crypto Primitives (in-process, -O${OPT_LEVEL})"
echo ""
echo '```'
"$REPO/crates/tls_core/tests/bin/tls_perf_bench" 2>&1 | grep -v "^==="
echo '```'
echo ""

if $QUICK; then
  # ---- quick: handshake only, skip throughput ----
  echo "## 2. Handshake Latency (cert-ec c2s, --quick)"
  echo ""
  echo "| Run | Ada→openssl (ms) | openssl→openssl (ms) |"
  echo "|-----|------------------|----------------------|"
  ADA_HS=(); REF_HS=()
  for R in $(seq 1 "$RUNS"); do
    PORT=$(pick_port)
    openssl s_server -accept "$PORT" -cert "$FIXTURES/leaf.pem" \
      -key "$FIXTURES/leaf.key" -tls1_3 -quiet -naccept 1 \
      -num_tickets 0 >/dev/null 2>&1 &
    sleep 0.3
    T0=$(now_ns)
    "$CLI" client --connect "127.0.0.1:$PORT" --mode cert-ec \
      --trust "$FIXTURES/root.der" --hostname localhost \
      --quiet 2>/dev/null || true
    T1=$(now_ns)
    ADA_MS=$(python3 -c "print(f'{($T1-$T0)/1e6:.1f}')")
    ADA_HS+=("$ADA_MS")
    wait 2>/dev/null

    PORT2=$(pick_port)
    openssl s_server -accept "$PORT2" -cert "$FIXTURES/leaf.pem" \
      -key "$FIXTURES/leaf.key" -tls1_3 -quiet -naccept 1 \
      -num_tickets 0 >/dev/null 2>&1 &
    sleep 0.3
    T0=$(now_ns)
    echo | openssl s_client -connect "127.0.0.1:$PORT2" -tls1_3 \
      -CAfile "$FIXTURES/root.pem" -verify_return_error \
      -quiet >/dev/null 2>&1 || true
    T1=$(now_ns)
    REF_MS=$(python3 -c "print(f'{($T1-$T0)/1e6:.1f}')")
    REF_HS+=("$REF_MS")
    wait 2>/dev/null

    echo "| $R | $ADA_MS | $REF_MS |"
  done
  A_STATS=$(printf '%s\n' "${ADA_HS[@]}" | stats)
  R_STATS=$(printf '%s\n' "${REF_HS[@]}" | stats)
  read -r AM ASD _ _ <<< "$A_STATS"
  read -r RM RSD _ _ <<< "$R_STATS"
  echo ""
  echo "| | Ada→openssl | openssl→openssl |"
  echo "|------|-------------|-----------------|"
  echo "| Mean | ${AM} ms | ${RM} ms |"
  echo "| Std Dev | ${ASD} ms | ${RSD} ms |"
  echo ""
  echo "(--quick: throughput skipped)"
  exit 0
fi

# =====================================================================
# 2. Handshake Latency
# =====================================================================
echo "## 2. Handshake Latency (cert-ec c2s)"
echo ""
echo "| Run | Ada→openssl (ms) | openssl→openssl (ms) |"
echo "|-----|------------------|----------------------|"

ADA_HS=(); REF_HS=()
for R in $(seq 1 "$RUNS"); do
  # Ada client → openssl server
  PORT=$(pick_port)
  openssl s_server -accept "$PORT" -cert "$FIXTURES/leaf.pem" \
    -key "$FIXTURES/leaf.key" -tls1_3 -quiet -naccept 1 \
    -num_tickets 0 >/dev/null 2>&1 &
  sleep 0.3
  T0=$(now_ns)
  "$CLI" client --connect "127.0.0.1:$PORT" --mode cert-ec \
    --trust "$FIXTURES/root.der" --hostname localhost \
    --quiet 2>/dev/null || true
  T1=$(now_ns)
  ADA_MS=$(python3 -c "print(f'{($T1-$T0)/1e6:.1f}')")
  ADA_HS+=("$ADA_MS")
  wait 2>/dev/null

  # openssl client → openssl server (reference)
  PORT2=$(pick_port)
  openssl s_server -accept "$PORT2" -cert "$FIXTURES/leaf.pem" \
    -key "$FIXTURES/leaf.key" -tls1_3 -quiet -naccept 1 \
    -num_tickets 0 >/dev/null 2>&1 &
  sleep 0.3
  T0=$(now_ns)
  echo | openssl s_client -connect "127.0.0.1:$PORT2" -tls1_3 \
    -CAfile "$FIXTURES/root.pem" -verify_return_error \
    -quiet >/dev/null 2>&1 || true
  T1=$(now_ns)
  REF_MS=$(python3 -c "print(f'{($T1-$T0)/1e6:.1f}')")
  REF_HS+=("$REF_MS")
  wait 2>/dev/null

  echo "| $R | $ADA_MS | $REF_MS |"
done

A_STATS=$(printf '%s\n' "${ADA_HS[@]}" | stats)
R_STATS=$(printf '%s\n' "${REF_HS[@]}" | stats)
read -r AM ASD AMIN AMAX <<< "$A_STATS"
read -r RM RSD RMIN RMAX <<< "$R_STATS"
echo ""
echo "| Metric | Ada→openssl | openssl→openssl |"
echo "|--------|-------------|-----------------|"
echo "| Mean | ${AM} ms | ${RM} ms |"
echo "| Std Dev | ${ASD} ms | ${RSD} ms |"
echo "| Min | ${AMIN} ms | ${RMIN} ms |"
echo "| Max | ${AMAX} ms | ${RMAX} ms |"
echo ""

# =====================================================================
# 3. Bulk Throughput
# =====================================================================
echo "## 3. Bulk Throughput (cert-ec c2s, ${PAYLOAD_MB} MiB)"
echo ""
echo "| Run | Ada→openssl (MiB/s) | openssl→openssl (MiB/s) |"
echo "|-----|---------------------|-------------------------|"

ADA_TP=(); REF_TP=()
for R in $(seq 1 "$RUNS"); do
  # Ada client → openssl server
  PORT=$(pick_port)
  openssl s_server -accept "$PORT" -cert "$FIXTURES/leaf.pem" \
    -key "$FIXTURES/leaf.key" -tls1_3 -quiet -naccept 1 \
    >/dev/null 2>&1 &
  sleep 0.3
  LINE=$("$CLI" client --connect "127.0.0.1:$PORT" --mode cert-ec \
    --trust "$FIXTURES/root.der" --hostname localhost \
    --bench-throughput --bench-bytes "$BYTES" --quiet 2>&1 \
    | grep "BENCH_THROUGHPUT:" || echo "BENCH_THROUGHPUT: 0 MiB/s")
  ADA_MIBS=$(echo "$LINE" | grep -oE '[0-9]+ MiB/s' | awk '{print $1}')
  ADA_MIBS=${ADA_MIBS:-0}
  ADA_TP+=("$ADA_MIBS")
  wait 2>/dev/null

  # openssl → openssl reference: s_time measures throughput
  PORT2=$(pick_port)
  openssl s_server -accept "$PORT2" -cert "$FIXTURES/leaf.pem" \
    -key "$FIXTURES/leaf.key" -tls1_3 -quiet -naccept 1 \
    >/dev/null 2>&1 &
  sleep 0.3
  T0=$(now_ns)
  dd if=/dev/zero bs=4096 count=$((BYTES/4096)) 2>/dev/null | \
    openssl s_client -connect "127.0.0.1:$PORT2" -tls1_3 \
    -CAfile "$FIXTURES/root.pem" -quiet >/dev/null 2>&1 || true
  T1=$(now_ns)
  REF_MIBS=$(python3 -c "
elapsed = ($T1-$T0)/1e9
mib = $BYTES / 1048576
print(int(mib/max(elapsed,1e-9)))
")
  REF_TP+=("$REF_MIBS")
  wait 2>/dev/null

  echo "| $R | $ADA_MIBS | $REF_MIBS |"
done

A_STATS=$(printf '%s\n' "${ADA_TP[@]}" | stats)
R_STATS=$(printf '%s\n' "${REF_TP[@]}" | stats)
read -r AM ASD AMIN AMAX <<< "$A_STATS"
read -r RM RSD RMIN RMAX <<< "$R_STATS"
echo ""
echo "| Metric | Ada→openssl | openssl→openssl |"
echo "|--------|-------------|-----------------|"
echo "| Mean | ${AM} MiB/s | ${RM} MiB/s |"
echo "| Std Dev | ${ASD} MiB/s | ${RSD} MiB/s |"
echo "| Min | ${AMIN} MiB/s | ${RMIN} MiB/s |"
echo "| Max | ${AMAX} MiB/s | ${RMAX} MiB/s |"
echo ""
