#!/usr/bin/env bash
#  30-minute benchmark: Ada vs Go gRPC server + client.
#
#  Plan:
#    Server bench (~18 min): Go bench client drives per workload
#    against Ada server (greeter_mux_server in matching mode) and
#    Go server (handles all 4 RPCs). Each workload runs for 90 s
#    against each server. 6 workloads × 2 servers × 90 s = 18 min
#    + ~3 min for Ada server restarts between modes = ~21 min.
#
#    Client bench (~9 min): a long-running Go server is the fixed
#    target. Ada bench client (one-conn-per-call) and Go bench
#    client (persistent conn) each get 4 min, three name-length
#    variants × ~80 s each. = ~9 min.
#
#  Total: ~30 min wall. JSON results dumped under results/.

set -uo pipefail

#  Repo-relative paths so the bench is reproducible from a fresh
#  clone. Build the Go side once with `make -C bench` (or
#  `bench/build.sh`); build the Ada side with `alr build` in
#  `crates/examples`.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BIN="$SCRIPT_DIR/bin"
RES="$SCRIPT_DIR/results"
mkdir -p "$BIN" "$RES"
ADA_BIN="$REPO_ROOT/crates/examples/bin"

ADA_MUX="$ADA_BIN/greeter_mux_server"
ADA_BENCH="$ADA_BIN/greeter_bench_client"
GO_SRV="$BIN/go_server"
GO_CLI="$BIN/go_client"

for need in "$ADA_MUX" "$ADA_BENCH" "$GO_SRV" "$GO_CLI"; do
   if [[ ! -x "$need" ]]; then
      echo "FATAL: $need not built" >&2
      echo "    run: cd bench && ./build.sh" >&2
      echo "    and: (cd crates/examples && alr build)" >&2
      exit 2
   fi
done

# Per-workload duration on the server side.
DUR_SRV=${DUR_SRV:-90s}
# Per-workload duration on the client side.
DUR_CLI=${DUR_CLI:-80}

PORT_ADA=50061
PORT_GO=50062

date_iso() { date '+%Y-%m-%dT%H:%M:%S'; }
log() { echo "[$(date_iso)] $*" | tee -a $RES/run.log; }

cleanup() {
   pkill -f greeter_mux_server 2>/dev/null
   pkill -f go_server 2>/dev/null
   sleep 0.3
}
trap cleanup EXIT

cleanup
sleep 0.5

#############################################
# SERVER BENCHMARK
#############################################

run_ada_server_phase() {
   local mode=$1
   local workloads=$2
   local outfile=$3

   log "ada-server: starting mode=$mode port=$PORT_ADA"
   $ADA_MUX $mode $PORT_ADA >$RES/ada-srv-$mode.log 2>&1 &
   local pid=$!
   sleep 2.0

   log "ada-server: bench workloads=$workloads dur=$DUR_SRV"
   $GO_CLI -target 127.0.0.1:$PORT_ADA -dur $DUR_SRV \
           -tag "ada-server-$mode" -workloads "$workloads" \
           -out $outfile >$RES/ada-srv-$mode.client.log 2>&1
   log "ada-server: done $mode → $outfile"

   kill $pid 2>/dev/null; wait $pid 2>/dev/null
   sleep 0.5
}

run_go_server_phase() {
   local outfile=$1

   log "go-server: starting on port=$PORT_GO"
   $GO_SRV -port $PORT_GO >$RES/go-srv.log 2>&1 &
   local pid=$!
   sleep 1.5

   log "go-server: bench (all workloads) dur=$DUR_SRV each"
   $GO_CLI -target 127.0.0.1:$PORT_GO -dur $DUR_SRV \
           -tag "go-server" \
           -out $outfile >$RES/go-srv.client.log 2>&1
   log "go-server: done → $outfile"

   kill $pid 2>/dev/null; wait $pid 2>/dev/null
   sleep 0.5
}

log "=========================================="
log "PHASE: server benchmark"
log "=========================================="

run_ada_server_phase unary         "unary_4B,unary_1024B,unary_8192B" \
                                   $RES/ada-srv-unary.json
run_ada_server_phase server-stream "server_stream_5" \
                                   $RES/ada-srv-ss.json
run_ada_server_phase client-stream "client_stream_8" \
                                   $RES/ada-srv-cs.json
run_ada_server_phase bidi          "bidi_5" \
                                   $RES/ada-srv-bidi.json

run_go_server_phase $RES/go-srv.json

#############################################
# CLIENT BENCHMARK
#############################################

log "=========================================="
log "PHASE: client benchmark (Go server fixed)"
log "=========================================="

# Long-running Go server.
$GO_SRV -port $PORT_GO >$RES/client-bench-server.log 2>&1 &
GSPID=$!
sleep 1.5

# Ada bench client: 3 name-length variants.
for nl in 4 1024 8192; do
   log "client: ada-bench nl=$nl dur=${DUR_CLI}s"
   $ADA_BENCH 127.0.0.1:$PORT_GO $DUR_CLI $nl \
        >$RES/cli-ada-nl$nl.json 2>$RES/cli-ada-nl$nl.err
done

# Go bench client driving same target — only the unary workloads
# so we're directly comparing apples-to-apples with the Ada client.
log "client: go-bench unary_4B dur=$DUR_CLI"
$GO_CLI -target 127.0.0.1:$PORT_GO -dur ${DUR_CLI}s \
        -tag "go-client-unary" -workloads "unary_4B,unary_1024B,unary_8192B" \
        -out $RES/cli-go.json >$RES/cli-go.log 2>&1

kill $GSPID 2>/dev/null; wait $GSPID 2>/dev/null

log "=========================================="
log "ALL PHASES DONE"
log "=========================================="
ls -la $RES/*.json
