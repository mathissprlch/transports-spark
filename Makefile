# Top-level convenience for grpc-ada.
#
# On macOS the GNAT toolchain shipped via Alire needs SDKROOT pointed at the
# Command Line Tools SDK so the linker can find -lSystem. Set it once here.

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  SDK := $(shell xcrun --show-sdk-path)
  # SDKROOT alone isn't enough on recent macOS — Apple ld needs LIBRARY_PATH
  # to include <sdk>/usr/lib so it can find -lSystem.
  ALR_ENV := SDKROOT=$(SDK) LIBRARY_PATH=$(SDK)/usr/lib
else
  ALR_ENV :=
endif

CRATES := protobuf_ada grpc_ada protoc_gen_grpc_ada protobuf_ada_tests examples
PLUGIN := crates/protoc_gen_grpc_ada/bin/protoc_gen_grpc_ada
GEN_DIR := crates/protobuf_ada_tests/generated
EXAMPLES_GEN := crates/examples/generated

.PHONY: all build test clean codegen plugin bench bench-build bench-quick

all: build

plugin:
	@( cd crates/protoc_gen_grpc_ada && $(ALR_ENV) alr build )

# Regenerate Ada code from .proto fixtures.
codegen: plugin
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

build:
	@for c in $(CRATES); do \
	  echo "==> build $$c"; \
	  ( cd crates/$$c && $(ALR_ENV) alr build ) || exit 1; \
	done

test: build
	@cd crates/protobuf_ada_tests && $(ALR_ENV) ./bin/test_main

clean:
	@for c in $(CRATES); do \
	  rm -rf crates/$$c/obj crates/$$c/lib crates/$$c/bin; \
	done
	@rm -rf $(GEN_DIR)

# ============================================================
# Performance bench (Ada vs Go grpc).
#
#   make bench-build  — builds Go server + bench client
#   make bench        — full ~30 min run
#   make bench-quick  — 30 s/workload, ~10 min run
# ============================================================

bench-build:
	@./bench/build.sh

bench: bench-build
	@cd crates/examples && BUILD_MODE=release $(ALR_ENV) alr build
	@./bench/run_bench.sh

bench-quick: bench-build
	@cd crates/examples && BUILD_MODE=release $(ALR_ENV) alr build
	@DUR_SRV=30s DUR_CLI=30 ./bench/run_bench.sh
