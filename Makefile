# transports-spark — top-level Makefile.
#
# This is the public test-discovery surface (docs/conventions.md §10d).
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

#  Default host install (Alire user prefix).  Override to plain
#  `gnatprove` on the Docker CI image where it sits on PATH:
#  `GNATPROVE=gnatprove make prove`.
GNATPROVE ?= /Users/mathis/.alire/bin/gnatprove
#  gnatformat (Ada formatter). Override to plain `gnatformat` on the
#  Docker CI image where it sits on PATH: `GNATFORMAT=gnatformat make ...`.
GNATFORMAT ?= /Users/mathis/.alire/bin/gnatformat
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
        tls-format tls-format-check \
        prove prove-quick prove-coverage \
        tls-soak tls-soak-quick tls-audit tls-bare \
        tls-interop tls-interop-openssl tls-interop-rustls tls-interop-go \
        tls-interop-gnutls tls-interop-mbedtls tls-interop-boringssl \
        tls-interop-quick tls-interop-json tls-interop-build \
        tls-ci \
        grpc-build grpc-test grpc-codegen grpc-plugin \
        grpc-bench grpc-bench-build grpc-bench-quick \
        mqtt-build mqtt-test \
        http2-build http2-test \
        examples-build \
        docker-image docker-test docker-prove docker-interop docker-ci docker-shell

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
	@echo '  Docker CI image (single Dockerfile, BuildKit cache):'
	@echo '    docker-image     Build transports-spark:ci image'
	@echo '    docker-test      Run tls-test inside the image'
	@echo '    docker-prove     Run prove-quick (level=1 sweep) inside the image'
	@echo '    docker-interop   Run tls-interop matrix inside the image'
	@echo '    docker-ci        Sequenced test + interop + prove-quick'
	@echo '    docker-shell     Interactive shell with source bind-mounted'
	@echo ''
	@echo '  Variables:'
	@echo '    PROVE_LEVEL=N    gnatprove level for tls-prove (default 2)'
	@echo '    SOAK_ITERS=N     iterations for tls-soak (default 100)'
	@echo '    DOCKER_IMAGE=tag override image tag (default transports-spark:ci)'

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
BENCH_BYTES ?= 1048576

tls-bench: tls-bench-build
	@$(TLS_INTEROP) --bench --bench-runs $(BENCH_RUNS) --bench-bytes $(BENCH_BYTES)

tls-bench-quick: tls-bench-build
	@$(TLS_INTEROP) --bench --bench-runs 3 --bench-bytes $(BENCH_BYTES) --quick

tls-bench-peer: tls-bench-build
	@$(TLS_INTEROP) --bench --bench-runs $(BENCH_RUNS) --bench-bytes $(BENCH_BYTES) --peer $(PEER)

tls-bench-build:
	@$(ALR_ENV) BUILD_MODE=release OPT_LEVEL=$(OPT_LEVEL) alr -C crates/tls_core build
	@$(ALR_ENV) BUILD_MODE=release OPT_LEVEL=$(OPT_LEVEL) alr -C crates/tls_core/tests build
	@$(ALR_ENV) BUILD_MODE=release OPT_LEVEL=$(OPT_LEVEL) alr -C crates/tls_interop build
	@$(ALR_ENV) BUILD_MODE=release OPT_LEVEL=$(OPT_LEVEL) alr -C crates/examples build

tls-prove: tls-audit
	@$(ALR_ENV) $(GNATPROVE) -P crates/tls_core/tls_core.gpr \
	  --level=$(PROVE_LEVEL) --proof-warnings=on --no-subprojects -j0 \
	  2>&1 | tail -25
	@$(MAKE) -s tls-audit
	@echo
	@echo "Reminder: a green prove headline alone is not platinum."
	@echo "  See docs/conventions.md §0d. The audit above must also be clean."

tls-prove-l3:
	@$(MAKE) tls-prove PROVE_LEVEL=3

# Format the hand-written tls_core sources with gnatformat (UTF-8).
# generated/ is left as RecordFlux emits it. Run via `alr exec` so the
# toolchain resolves; gnatformat must be given by absolute path.
TLS_FMT_SRC := $(shell find $(CURDIR)/crates/tls_core/src \( -name '*.ads' -o -name '*.adb' \) ! -name 'tls_core_config.ads')

tls-format:
	@$(ALR_ENV) alr -C crates/tls_core exec -- \
	  $(GNATFORMAT) -P $(CURDIR)/crates/tls_core/tls_core.gpr \
	  --charset utf-8 $(TLS_FMT_SRC)

# CI gate: exit 1 if any source is not already gnatformat-clean.
tls-format-check:
	@$(ALR_ENV) alr -C crates/tls_core exec -- \
	  $(GNATFORMAT) -P $(CURDIR)/crates/tls_core/tls_core.gpr \
	  --charset utf-8 --check $(TLS_FMT_SRC)
	@echo "gnatformat: all tls_core sources are formatted."

# Full-stack proof sweep via the workspace umbrella. -U makes
# gnatprove walk every with'd subproject; one process, one
# unified gnatprove/gnatprove.out at the repo root. GPR_PROJECT_PATH
# is composed of each crate's parent dir plus Alire's transitive-dep
# path (borrowed from tls_core's manifest).
PROVE_J ?= 0
PROVE_FULL_LEVEL ?= 4
LOCAL_CRATES := rflx_runtime logger protobuf_core http1_core tls_core tls_transport mqtt_core http2_core grpc_core

prove:
	@GPR_PROJECT_PATH="$$(echo $(addprefix $(CURDIR)/crates/,$(LOCAL_CRATES)) | tr ' ' ':'):$$(cd crates/tls_core && alr exec -- printenv GPR_PROJECT_PATH)" \
	  $(ALR_ENV) $(GNATPROVE) -P transports_spark.gpr -U \
	    --level=$(PROVE_FULL_LEVEL) --proof-warnings=on -j$(PROVE_J) 2>&1 | tail -25

# Iterative variant — level=1 (AoRTE triage), warnings off, same
# umbrella. Finishes in a few minutes on a warm cache; the right
# target during a SPARK-edit / re-prove inner loop. The full
# `make prove` is the release-readiness sweep.
prove-quick:
	@GPR_PROJECT_PATH="$$(echo $(addprefix $(CURDIR)/crates/,$(LOCAL_CRATES)) | tr ' ' ':'):$$(cd crates/tls_core && alr exec -- printenv GPR_PROJECT_PATH)" \
	  $(ALR_ENV) $(GNATPROVE) -P transports_spark.gpr -U \
	    --level=1 -j$(PROVE_J) 2>&1 | tail -25

# Re-render docs/proof-coverage.md from the latest gnatprove
# output. Run after `make prove`.
prove-coverage:
	@python3 scripts/render-proof-coverage.py

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
# all extensions — driven by CLI flags.  Per docs/conventions.md §10a.
tls-interop-build: tls-build tls-interop-go-helpers
	@$(ALR_ENV) alr -C crates/tls_interop build
	@# `examples` pins vendor/aws (v0.1 gRPC fork); on a CI image
	@# where that submodule isn't present, skip its build — the
	@# interop matrix doesn't depend on the example binaries.
	@if [ -d vendor/aws ]; then \
	    $(ALR_ENV) alr -C crates/examples build; \
	else \
	    echo "tls-interop-build: skipping examples-build (vendor/aws absent)"; \
	fi

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

TLS_INTEROP := ./crates/tls_interop/bin/tls_interop

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
# TLS stack integration demos (§10d)
# ============================================================

EC_DIR := crates/tls_core/tests/fixtures/interop/ec

mqtt-tls-demo:
	@$(ALR_ENV) TRANSPORT=tls alr -C crates/examples exec -- \
	  gprbuild -P examples.gpr -j8 mqtt_tls_demo.adb -p -q
	@echo "--- start mosquitto with TLS on :8883 first ---"
	@echo "docker run --rm -d -p 8883:8883 \\"
	@echo "  -v \$$PWD/$(EC_DIR):/certs:ro --name mqtt-tls \\"
	@echo "  eclipse-mosquitto sh -c 'printf \"listener 8883\\n\\"
	@echo "  cafile /certs/root.pem\\ncertfile /certs/leaf.pem\\n\\"
	@echo "  keyfile /certs/leaf.key\\nallow_anonymous true\\n\" \\"
	@echo "  > /mosquitto/config/mosquitto.conf && \\"
	@echo "  mosquitto -c /mosquitto/config/mosquitto.conf'"
	@echo "--- then: ./crates/examples/bin/mqtt_tls_demo ---"

grpc-tls-demo:
	@$(ALR_ENV) TRANSPORT=tls alr -C crates/examples exec -- \
	  gprbuild -P examples.gpr -j8 grpc_tls_demo.adb -p -q
	@echo "--- start nghttpd on :4443 first ---"
	@echo "nghttpd 4443 $(EC_DIR)/leaf.key $(EC_DIR)/leaf.pem -d /tmp &"
	@echo "--- then: ./crates/examples/bin/grpc_tls_demo ---"

# ============================================================
# Backward-compat aliases (legacy target names)
# ============================================================

bench: grpc-bench
bench-build: grpc-bench-build
bench-quick: grpc-bench-quick
codegen: grpc-codegen
plugin: grpc-plugin
test: tls-test

# ============================================================
# Docker CI image — see docker/Dockerfile for the cache strategy.
# Builds compiled Ada test binaries + every dep needed to run the
# testbench (gnatprove, openssl, gnutls-cli, Go, mosquitto).
# Subsequent builds are fast: a source-only edit recompiles
# only the changed crates' objects, not the dep tree.
# ============================================================

DOCKER_IMAGE      ?= transports-spark:ci
DOCKER_BUILDER    ?= docker buildx
DOCKER_PLATFORM   ?=

# `docker buildx build --load` uses the local BuildKit cache, so
# the cache mounts in docker/Dockerfile persist between runs.
DOCKER_BUILD_ARGS := --load -f docker/Dockerfile -t $(DOCKER_IMAGE) \
                    $(if $(DOCKER_PLATFORM),--platform=$(DOCKER_PLATFORM),) \
                    .

# Run helper.  `--init` for clean PID-1, `--rm` so the container
# disappears on exit.  `-v $(CURDIR):/work` is intentionally NOT
# the default — the image already contains the source + binaries.
# Override DOCKER_RUN_EXTRA to bind-mount for dev iteration.
DOCKER_RUN := docker run --rm --init $(DOCKER_RUN_EXTRA) $(DOCKER_IMAGE)

docker-image:
	@DOCKER_BUILDKIT=1 $(DOCKER_BUILDER) build $(DOCKER_BUILD_ARGS)

docker-test: docker-image
	@$(DOCKER_RUN) make tls-test

docker-prove: docker-image
	@$(DOCKER_RUN) make prove-quick

docker-interop: docker-image
	@$(DOCKER_RUN) make tls-interop

docker-ci: docker-image
	@$(DOCKER_RUN) sh -c 'make tls-test && make tls-interop && make prove-quick'

docker-shell: docker-image
	@docker run --rm -it --init -v $(CURDIR):/work $(DOCKER_IMAGE) bash
