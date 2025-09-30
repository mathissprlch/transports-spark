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

CRATES := protobuf_ada protobuf_ada_tests

.PHONY: all build test clean

all: build

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
