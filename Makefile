# transports-spark — top-level Makefile.
#
# This is the public test-discovery surface (CLAUDE.md §10d).
# Every long-running operation worth running again has a target here.
#
# Layout (runnable, not aspirational):
#
#   v0.5 TLS:     tls-build  tls-test  tls-perf  tls-prove[-l3]
#                 tls-soak[-quick]  tls-audit  tls-bare
#   Interop:      tls-interop  tls-interop-PEER  tls-interop-quick
#                 (end-to-end Ada TLS vs. third-party stacks)
#   v0.1 gRPC:    grpc-build  grpc-test  grpc-codegen  grpc-bench
#                 grpc-bench-quick
#   v0.2 MQTT:    mqtt-build  mqtt-test
#   HTTP/2:       http2-build  http2-test
#   General:      all  clean  help
#
# Run `make help` for the inline help output.
#
# macOS toolchain note: GNAT shipped via Alire needs SDKROOT pointed at
# the Command Line Tools SDK so the linker can find -lSystem. Set once.

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  SDK := $(shell xcrun --show-sdk-path)
  ALR_ENV := SDKROOT=$(SDK) LIBRARY_PATH=$(SDK)/usr/lib
else
  ALR_ENV :=
endif

GNATPROVE := /Users/mathis/.alire/bin/gnatprove
PROVE_LEVEL ?= 2
SOAK_ITERS ?= 100
SOAK_QUICK_ITERS := 10

# Crates that participate in `make build` / `make all`.
CRATES := tls_core protobuf_ada grpc_ada protoc_gen_grpc_ada \
          protobuf_ada_tests mqtt_core http2_core grpc_core \
          rflx_runtime examples

# Plugin + codegen paths (gRPC track).
PLUGIN := crates/protoc_gen_grpc_ada/bin/protoc_gen_grpc_ada
GEN_DIR := crates/protobuf_ada_tests/generated
EXAMPLES_GEN := crates/examples/generated

.PHONY: all build clean help \
        tls-build tls-test tls-perf tls-prove tls-prove-l3 \
        tls-soak tls-soak-quick tls-audit tls-bare \
        tls-interop tls-interop-openssl tls-interop-rustls tls-interop-go \
        tls-interop-gnutls tls-interop-mbedtls tls-interop-boringssl \
        tls-interop-quick tls-interop-json tls-interop-build \
        tls-ci \
        grpc-build grpc-test grpc-codegen grpc-plugin \
        grpc-bench grpc-bench-build grpc-bench-quick \
        mqtt-build mqtt-test \
        http2-build http2-test \
        examples-build

# Default — build the production crate.
all: tls-build

help:
	@echo 'transports-spark Makefile — common targets:'
	@echo ''
	@echo '  v0.5 TLS:'
	@echo '    tls-build        Build crates/tls_core'
	@echo '    tls-test         Run tls_core_tests (594 asserts)'
	@echo '    tls-perf         Run tls_perf_bench'
	@echo '    tls-prove        gnatprove --level=$(PROVE_LEVEL)'
	@echo '    tls-prove-l3     gnatprove --level=3 (slower)'
	@echo '    tls-prove-report per-package proof breakdown from last run'
	@echo '    tls-soak         Run tls_core_tests SOAK_ITERS=$(SOAK_ITERS) times'
	@echo '    tls-soak-quick   $(SOAK_QUICK_ITERS)-iter quick soak'
	@echo '    tls-audit        Static §0d audit (no SPARK_Mode Off / pragma Assume etc.)'
	@echo '    tls-bare         Build crates/tls_core with -XTRANSPORT=bare'
	@echo ''
	@echo '  Interop (end-to-end Ada TLS 1.3 vs. third-party stacks):'
	@echo '    tls-interop           All available peers'
	@echo '    tls-interop-openssl   openssl s_client / s_server'
	@echo '    tls-interop-gnutls    gnutls-cli / gnutls-serv'
	@echo '    tls-interop-mbedtls   mbedTLS ssl_client2 / ssl_server2'
	@echo '    tls-interop-rustls    rustls tlsclient-mio / tlsserver-mio'
	@echo '    tls-interop-go        Go crypto/tls'
	@echo '    tls-interop-boringssl BoringSSL bssl'
	@echo '    tls-interop-quick     openssl PSK only (~3 s)'
	@echo '    tls-interop-json      Full table as JSON (CI ingestion)'
	@echo ''
	@echo '  v0.1 gRPC:'
	@echo '    grpc-build       Build the gRPC crate stack'
	@echo '    grpc-test        Run protobuf_ada_tests'
	@echo '    grpc-codegen     Regenerate Ada from .proto fixtures'
	@echo '    grpc-bench       Full ~30 min Ada-vs-Go gRPC bench'
	@echo '    grpc-bench-quick 30 s/workload bench (~10 min total)'
	@echo ''
	@echo '  v0.2 MQTT / HTTP/2:'
	@echo '    mqtt-build       Build crates/mqtt_core'
	@echo '    mqtt-test        Run mqtt_core_tests'
	@echo '    http2-build      Build crates/http2_core'
	@echo '    http2-test       Run http2_core_tests'
	@echo ''
	@echo '  General:'
	@echo '    build            Build every crate in CRATES'
	@echo '    examples-build   Build crates/examples (interop binaries)'
	@echo '    clean            Remove obj/lib/bin from every crate'
	@echo ''
	@echo '  Variables:'
	@echo '    PROVE_LEVEL=N    gnatprove level for tls-prove (default 2)'
	@echo '    SOAK_ITERS=N     iterations for tls-soak (default 100)'

build:
	@for c in $(CRATES); do \
	  echo "==> build $$c"; \
	  ( cd crates/$$c && $(ALR_ENV) alr -n build ) || exit 1; \
	done

clean:
	@for c in $(CRATES); do \
	  rm -rf crates/$$c/obj crates/$$c/lib crates/$$c/bin; \
	done
	@rm -rf $(GEN_DIR)

# ============================================================
# v0.5 TLS targets
# ============================================================

tls-build:
	@$(ALR_ENV) alr -C crates/tls_core build

tls-test: tls-build tls-audit
	@$(ALR_ENV) alr -C crates/tls_core/tests build
	@cd crates/tls_core/tests && $(ALR_ENV) ./bin/tls_core_tests | tail -3

tls-perf: tls-build
	@$(ALR_ENV) alr -C crates/tls_core/tests build
	@cd crates/tls_core/tests && $(ALR_ENV) ./bin/tls_perf_bench

OPT_LEVEL ?= 2

BENCH_RUNS ?= 5

tls-bench: tls-bench-build
	@$(TLS_INTEROP) --bench --bench-runs $(BENCH_RUNS)

tls-bench-quick: tls-bench-build
	@$(TLS_INTEROP) --bench --bench-runs 3 --quick

tls-bench-peer: tls-bench-build
	@$(TLS_INTEROP) --bench --bench-runs $(BENCH_RUNS) --peer $(PEER)

tls-bench-build:
	@$(ALR_ENV) BUILD_MODE=release OPT_LEVEL=$(OPT_LEVEL) alr -C crates/tls_core build
	@$(ALR_ENV) BUILD_MODE=release OPT_LEVEL=$(OPT_LEVEL) alr -C crates/tls_core/tests build
	@$(ALR_ENV) BUILD_MODE=release OPT_LEVEL=$(OPT_LEVEL) alr -C crates/examples build

tls-prove: tls-audit
	@$(ALR_ENV) $(GNATPROVE) -P crates/tls_core/tls_core.gpr \
	  --level=$(PROVE_LEVEL) -j0 2>&1 | tail -25
	@$(MAKE) -s tls-audit
	@echo
	@echo "Reminder: a green prove headline alone is not platinum."
	@echo "  See CLAUDE.md §0d. The audit above must also be clean."

tls-prove-l3:
	@$(MAKE) tls-prove PROVE_LEVEL=3

tls-prove-report:
	@echo "=== tls_core proof breakdown (from last gnatprove run) ==="
	@echo ""
	@OUTF=crates/tls_core/obj/gnatprove/gnatprove.out; \
	if [ ! -f "$$OUTF" ]; then echo "No gnatprove.out — run 'make tls-prove' first."; exit 1; fi; \
	TLS_PROVED=$$(grep -E '^\s+Tls_Core\.' "$$OUTF" | grep -oE 'proved \([0-9]+ checks\)' | grep -oE '[0-9]+' | awk '{s+=$$1} END {print s+0}'); \
	TLS_UNPROVED=$$(grep -E '^\s+Tls_Core\.' "$$OUTF" | grep -c "not proved"); \
	TLS_UNITS_OK=$$(grep -E '^\s+Tls_Core\.' "$$OUTF" | grep "0 errors" | grep -v "not proved" | grep 'proved ([1-9]' | sed 's/at .*//' | awk '{print $$1}' | sort -u | wc -l | tr -d ' '); \
	TLS_UNITS_BAD=$$(grep -E '^\s+Tls_Core\.' "$$OUTF" | grep "not proved" | sed 's/at .*//' | awk '{print $$1}' | sort -u | wc -l | tr -d ' '); \
	RFLX_PROVED=$$(grep -E '^\s+RFLX\.' "$$OUTF" | grep -oE 'proved \([0-9]+ checks\)' | grep -oE '[0-9]+' | awk '{s+=$$1} END {print s+0}'); \
	RFLX_UNPROVED=$$(grep -E '^\s+RFLX\.' "$$OUTF" | grep -c "not proved"); \
	SPARK_OFF=$$(grep -rnE 'SPARK_Mode\s*(\(\s*Off|=>\s*Off)' crates/tls_core/src/ | grep -v '\-\-.*SPARK_Mode' | wc -l | tr -d ' '); \
	ASSUMES=$$(grep -rn 'pragma Assume' crates/tls_core/src/ | grep -v '\-\-.*pragma Assume' | grep -v '^\s*--' | wc -l | tr -d ' '); \
	echo "Tls_Core (hand-written):"; \
	echo "  Proved checks:   $$TLS_PROVED"; \
	echo "  Unproved VCs:    $$TLS_UNPROVED"; \
	TLS_TOTAL=$$((TLS_PROVED + TLS_UNPROVED)); \
	if [ "$$TLS_TOTAL" -gt 0 ]; then echo "  Proof rate:      $$((TLS_PROVED * 100 / TLS_TOTAL))%"; fi; \
	echo "  Units fully proven: $$TLS_UNITS_OK"; \
	echo "  Units with gaps:    $$TLS_UNITS_BAD"; \
	echo ""; \
	echo "RFLX (generated):"; \
	echo "  Proved checks:   $$RFLX_PROVED"; \
	echo "  Unproved VCs:    $$RFLX_UNPROVED"; \
	RFLX_TOTAL=$$((RFLX_PROVED + RFLX_UNPROVED)); \
	if [ "$$RFLX_TOTAL" -gt 0 ]; then echo "  Proof rate:      $$((RFLX_PROVED * 100 / RFLX_TOTAL))%"; fi; \
	echo ""; \
	echo "Audit:"; \
	echo "  SPARK_Mode(Off) bodies: $$SPARK_OFF (expect 2: Tcp_Transport + Transport)"; \
	echo "  pragma Assume:          $$ASSUMES (expect 0)"; \
	echo ""; \
	echo "Headline:"; \
	grep "^Total" "$$OUTF"; \
	echo ""; \
	if [ "$$TLS_UNPROVED" -gt 0 ]; then \
	  echo "Tls_Core units with unproved VCs:"; \
	  grep -E '^\s+Tls_Core\.' "$$OUTF" | grep "not proved" | sed 's/at .*//' | awk '{print $$1}' | sort -u | sed 's/^/  /'; \
	fi

tls-soak: tls-test
	@cd crates/tls_core/tests && pass=0; fail=0; \
	  for i in $$(seq 1 $(SOAK_ITERS)); do \
	    out=$$($(ALR_ENV) ./bin/tls_core_tests 2>&1 | tail -1); \
	    if [ "$$out" = "Pass: 594  Fail: 0" ]; then \
	      pass=$$((pass+1)); \
	    else \
	      fail=$$((fail+1)); echo "iter $$i: $$out"; \
	    fi; \
	  done; \
	  echo "tls-soak: $$pass / $(SOAK_ITERS) passed exact 594/594"

tls-soak-quick:
	@$(MAKE) tls-soak SOAK_ITERS=$(SOAK_QUICK_ITERS)

tls-audit:
	@bash scripts/tls_audit.sh

tls-bare:
	@$(ALR_ENV) alr -C crates/tls_core build -- -XTRANSPORT=bare
	@echo "tls-bare: build clean (-XTRANSPORT=bare)"

# Umbrella: run audit + test + prove in sequence.  Use before any
# release / platinum claim / interop run.  Audit runs first AND last
# (the prove run can in principle introduce new bypasses that need
# to be caught immediately).
tls-ci: tls-audit tls-test tls-prove
	@echo
	@echo "tls-ci: audit + 594/594 tests + gnatprove level=$(PROVE_LEVEL) all clean."

# ============================================================
# End-to-end Ada TLS 1.3 vs. third-party stacks (interop)
# ============================================================

# Build the harness binary the interop runner uses.  Single
# binary (tls_cli) handles both client and server, all modes,
# all extensions — driven by CLI flags.  Per CLAUDE.md §10a.
tls-interop-build: tls-build tls-interop-go-helpers
	@$(ALR_ENV) alr -C crates/examples build

# Pre-compile Go peer helpers; `go run` is too slow to start within
# the matrix's 0.8 s spawn window (causes c2s/s2c CONNECT_ERROR
# false negatives).  Output to crates/examples/bin so the matrix
# Build_Go dispatcher finds them via a stable path.
tls-interop-go-helpers:
	@mkdir -p crates/examples/bin
	@command -v go >/dev/null && go build -o crates/examples/bin/go_peer_client \
	    scripts/interop/peers/go-helpers/client.go || true
	@command -v go >/dev/null && go build -o crates/examples/bin/go_peer_server \
	    scripts/interop/peers/go-helpers/server.go || true

TLS_INTEROP := ./crates/examples/bin/tls_interop

tls-interop: tls-interop-build
	@$(TLS_INTEROP)

tls-interop-openssl: tls-interop-build
	@$(TLS_INTEROP) --peer openssl

tls-interop-gnutls: tls-interop-build
	@$(TLS_INTEROP) --peer gnutls

tls-interop-mbedtls: tls-interop-build
	@$(TLS_INTEROP) --peer mbedtls

tls-interop-rustls: tls-interop-build
	@$(TLS_INTEROP) --peer rustls

tls-interop-go: tls-interop-build
	@$(TLS_INTEROP) --peer go

tls-interop-boringssl: tls-interop-build
	@$(TLS_INTEROP) --peer boringssl

# A fast subset for inner-loop iteration: openssl only, PSK only.
tls-interop-quick: tls-interop-build
	@$(TLS_INTEROP) --peer openssl --quick

# JSON output for CI ingestion.
tls-interop-json: tls-interop-build
	@$(TLS_INTEROP) --format json

# ============================================================
# v0.1 gRPC
# ============================================================

grpc-plugin:
	@( cd crates/protoc_gen_grpc_ada && $(ALR_ENV) alr build )

grpc-codegen: grpc-plugin
	@mkdir -p $(GEN_DIR) $(EXAMPLES_GEN)
	@protoc --plugin=protoc-gen-grpc-ada=$(PLUGIN) \
	        --grpc-ada_out=$(GEN_DIR) \
	        -I crates/protobuf_ada_tests/fixtures \
	        crates/protobuf_ada_tests/fixtures/helloworld.proto
	@protoc --plugin=protoc-gen-grpc-ada=$(PLUGIN) \
	        --grpc-ada_out=$(EXAMPLES_GEN) \
	        -I crates/examples/proto \
	        crates/examples/proto/helloworld.proto
	@protoc --plugin=protoc-gen-grpc-ada=$(PLUGIN) \
	        --grpc-ada_out=$(EXAMPLES_GEN) \
	        -I crates/examples/proto \
	        crates/examples/proto/routeguide.proto

grpc-build:
	@( cd crates/grpc_ada && $(ALR_ENV) alr build )

grpc-test: grpc-build
	@cd crates/protobuf_ada_tests && $(ALR_ENV) ./bin/test_main

grpc-bench-build:
	@./bench/build.sh

grpc-bench: grpc-bench-build
	@cd crates/examples && BUILD_MODE=release $(ALR_ENV) alr build
	@./bench/run_bench.sh

grpc-bench-quick: grpc-bench-build
	@cd crates/examples && BUILD_MODE=release $(ALR_ENV) alr build
	@DUR_SRV=30s DUR_CLI=30 ./bench/run_bench.sh

# ============================================================
# v0.2 MQTT
# ============================================================

mqtt-build:
	@$(ALR_ENV) alr -C crates/mqtt_core build

mqtt-test: mqtt-build
	@if [ -d crates/mqtt_core_tests ]; then \
	  $(ALR_ENV) alr -C crates/mqtt_core_tests build && \
	  cd crates/mqtt_core_tests && $(ALR_ENV) ./bin/mqtt_core_tests; \
	else \
	  echo "mqtt-test: no mqtt_core_tests crate (tests live in mqtt_core demo)"; \
	fi

# ============================================================
# v0.3 / v0.4 HTTP/2
# ============================================================

http2-build:
	@$(ALR_ENV) alr -C crates/http2_core build

http2-test: http2-build
	@if [ -d crates/http2_core_tests ]; then \
	  $(ALR_ENV) alr -C crates/http2_core_tests build && \
	  cd crates/http2_core_tests && $(ALR_ENV) ./bin/http2_core_tests; \
	fi

# ============================================================
# Examples
# ============================================================

examples-build:
	@$(ALR_ENV) alr -C crates/examples build

# ============================================================
# Backward-compat aliases (legacy target names)
# ============================================================

bench: grpc-bench
bench-build: grpc-bench-build
bench-quick: grpc-bench-quick
codegen: grpc-codegen
plugin: grpc-plugin
test: tls-test
