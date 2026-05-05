# transports-spark performance bench

Reproduces the v0.4 numbers in commit `b2009f3` and the orchestrator
output under `results/`. Two pieces:

  * **Server bench** — fixed Go bench client drives both the Ada
    `greeter_mux_server` (cycled through unary / server-stream /
    client-stream / bidi modes) and a Go gRPC server. Same workload
    set against each, results in `results/{ada,go}-srv-*.json`.
  * **Client bench** — fixed Go gRPC server is the target. Ada
    `greeter_bench_client` and Go bench client each take a turn,
    three name-length variants. Results in `results/cli-{ada,go}-*.json`.

Total wall ≈ 30 min at the default `DUR_SRV=90s DUR_CLI=80`.

## One-time setup

    bench/build.sh                                # builds Go server + bench client
    (cd crates/examples && BUILD_MODE=release alr build)   # Ada side (release mode)
    bench/scripts/gen_pb.sh                       # python stubs for mux concurrency tests

Need `go` ≥ 1.22, `protoc` + `protoc-gen-go` + `protoc-gen-go-grpc`,
`python3` with `grpcio` + `grpcio-tools`.

## Run the full bench

    bench/run_bench.sh

Override durations:

    DUR_SRV=30s DUR_CLI=30 bench/run_bench.sh     # quicker (~10 min)

## Quick tests

Python concurrent-call tests (need a matching mode of
`greeter_mux_server` running on port 50051):

    bench/scripts/mux_test.py        # 8 concurrent unary
    bench/scripts/mux_ss_test.py     # 4 concurrent server-stream
    bench/scripts/mux_cs_test.py     # 4 concurrent client-stream
    bench/scripts/mux_bidi_test.py   # 4 concurrent bidi

## Layout

    bench/
      go/                    Go module (server + bench client + protobuf stubs)
        server/main.go       grpc-go reference server
        client/main.go       grpc-go bench client w/ workload selector
        helloworldpb/        generated Go stubs
      scripts/
        gen_pb.sh            regenerates Python stubs
        mux_*.py             concurrent-call tests (Python grpcio)
        helloworld_*.py      generated Python stubs
      helloworld.proto       single-source proto for both sides
      build.sh               builds Go binaries
      run_bench.sh           the 30-min orchestrator
      bin/                   built Go binaries (gitignored)
      results/               JSON + log output (gitignored)
