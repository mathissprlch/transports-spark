# grpc-ada

A from-scratch implementation of [gRPC](https://grpc.io) in Ada.
Architecturally complete; awaiting AWS HTTP/2 link for real wire traffic.

## What works today

```
$ make codegen build test
... 9 tests, all passed
$ ./crates/examples/bin/greeter_client
Request:  World
Reply:    (reply pending HTTP/2 transport)
```

- **Protobuf wire format** in pure Ada — varint, ZigZag, fixed32/64,
  tag/wire-type, length-delim, Skip_Field for forward-compat.
- **Descriptor decoder** — parses real `protoc --descriptor_set_out` output
  for files, packages, messages, fields, enums, services.
- **`protoc-gen-grpc-ada`** — the `protoc` plugin, in Ada. Reads
  `CodeGeneratorRequest` from stdin and emits one Ada package per message,
  enum, and service:
  ```
  $ protoc --plugin=protoc-gen-grpc-ada=path/to/plugin \
           --grpc-ada_out=out -I proto proto/helloworld.proto
  ```
- **gRPC runtime types** — Status (16 codes), Metadata (ASCII + binary,
  case-insensitive lookup), Framing (5-byte length prefix), Deadline
  (`grpc-timeout` parser/formatter), Call, Server (handler dispatch),
  Channel.
- **Patched AWS** — `vendor/aws-patches/{0001,0002}-*.patch` add
  `AWS.Response.Set.Add_Trailer` and the HTTP/2 stream path that emits a
  trailer HEADERS frame after DATA. Applies cleanly to upstream master at
  the pinned commit.

## What's deferred

- **`GRPC.Transport.HTTP2` body** — spec is in place, body raises a clear
  `Program_Error` pending the AWS link. The AWS Alire crate v25.2.0
  produces a truncated `aws-os_lib.ads` on macOS Apple Silicon (verified
  reproducible without our patches); see [`docs/aws-integration.md`](docs/aws-integration.md)
  for the three remediation paths.
- Client stub codegen, end-to-end `helloworld` over the wire,
  cross-language `grpcurl` check, server streaming.

## Layout

```
crates/
  protobuf_ada/         protobuf wire format + descriptor decoder
  grpc_ada/             gRPC runtime
  protoc_gen_grpc_ada/  the protoc plugin (build-time tool)
  protobuf_ada_tests/   AUnit-flavoured tests + fixtures
  examples/             helloworld server + client
vendor/
  aws-patches/          unified diffs against AWS upstream
  bootstrap.sh          clones + applies the patches
docs/
  design.md             architecture sketch
  notes-grpc-wire.md    notes from PROTOCOL-HTTP2.md
  notes-protobuf.md     notes from protobuf encoding spec
  aws-integration.md    integration status + remediation paths
```

## Build

Tested on macOS arm64 with `alr 2.1.0` + `gnat_native 15.1.2` + `gprbuild
25.0.1`.

```sh
make codegen   # plugin → regenerate Ada from .proto fixtures
make build     # compile all crates
make test      # run the test binary
make clean
```

The Makefile injects `SDKROOT` and `LIBRARY_PATH` so the macOS linker can
find `-lSystem`. Linux should work with `ALR_ENV=` (the inner workings are
already conditional on `uname -s`).

## License

MIT — see [LICENSE](LICENSE).
