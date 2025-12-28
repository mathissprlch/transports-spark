# grpc-ada

A from-scratch implementation of [gRPC](https://grpc.io) in Ada. Single
runtime dependency: a vendored fork of [AWS](https://github.com/AdaCore/aws)
with two small patches that teach its HTTP/2 server to emit trailers.

## Hello world

```sh
$ make codegen build
$ ./crates/examples/bin/greeter_server &
Greeter listening on 0.0.0.0:50051

$ ./crates/examples/bin/greeter_client
Request:  World
Reply:    Hello, World!

# Same thing from raw HTTP/2 — proves wire-level conformance:
$ printf '\x00\x00\x00\x00\x07\x0a\x05World' \
  | curl -s -i --http2-prior-knowledge \
         -H 'content-type: application/grpc+proto' -H 'TE: trailers' \
         --data-binary @- \
         http://localhost:50051/helloworld.Greeter/SayHello \
  | xxd | tail -3
00000090: 0d0a 0000 0000 0f0a 0d48 656c 6c6f 2c20  .........Hello,
000000a0: 576f 726c 6421 6772 7063 2d73 7461 7475  World!grpc-statu
000000b0: 733a 2030 0d0a                           s: 0..
```

`grpc-status: 0` in the trailing HEADERS frame confirms the AWS patches
are working.

## What's in v0.1

- **Pure-Ada protobuf wire format** — varint, ZigZag, fixed32/64,
  tag/wire-type, length-delim, `Skip_Field` for forward-compat.
- **Descriptor decoder** for `FileDescriptorSet` and the subset of
  `descriptor.proto` the plugin needs.
- **`protoc-gen-grpc-ada`** — the `protoc` plugin, in Ada. Emits per
  message, enum, and service: record types with `Encode`/`Decode`,
  abstract service base, **server dispatch glue**, **client stubs**.
- **gRPC runtime** — `Status` (16 codes), `Metadata` (ASCII + binary,
  case-insensitive), `Framing` (5-byte length prefix), `Deadline`
  (`grpc-timeout`), `Call`, `Server`, `Channel`.
- **`GRPC.Transport.HTTP2`** — bridges AWS's `Server.Callback` to the
  dispatcher and the `AWS.Client.Post` to the stub. Trailer HEADERS
  frame carries `grpc-status` after the body.
- **Patched AWS** at pinned commit `483739e49a4`. Two unified diffs
  under `vendor/aws-patches/`. Bootstrap script clones, applies,
  installs helper GPRs and the platform `os_lib.ads`.
- **Helloworld example** — server, client, and an Ada `Greeter_Impl`
  service, each ~20 lines.

## Out of scope for v0.1

- Server / client / bidi streaming. The transport abstraction is
  designed for it; a `GRPC.Server_Writer (T)` generic is the next phase.
- TLS. Plaintext h2c only; the plumbing is there in AWS to add later.
- Bare metal. The API is biased toward bounded buffers and named
  access types so a Phase 2 lwIP transport can plug in below the
  framing layer; nothing today targets `light-tasking`.
- Connect-RPC and gRPC-Web.

## Layout

```
crates/
  protobuf_ada/         protobuf wire format + descriptor decoder
  grpc_ada/             gRPC runtime + HTTP/2 transport
  protoc_gen_grpc_ada/  the protoc plugin (build-time tool)
  protobuf_ada_tests/   AUnit-flavoured tests + fixtures
  examples/             helloworld server + client
vendor/
  aws-patches/          unified diffs against AWS upstream
  aws-overlays/         platform constants (os_lib.ads) + helper GPRs
  bootstrap.sh          clones AWS at pin, applies patches, installs overlays
docs/
  design.md             architecture sketch
  aws-integration.md    AWS bootstrap details
  notes-grpc-wire.md    notes from PROTOCOL-HTTP2.md
  notes-protobuf.md     notes from the protobuf encoding spec
```

## Build

Tested on macOS arm64 with `alr 2.1.0` + `gnat_native 15.1.2` + `gprbuild
25.0.1`. Linux x86_64 / aarch64 should work the same way once a fresh
`os_lib.ads` overlay is generated for the host (run
`vendor/aws-overlays/gen_os_lib.c`; output is committed per platform).

```sh
./vendor/bootstrap.sh   # one-time: clone AWS at pin, apply patches
make codegen            # build plugin and regenerate Ada from .proto
make build              # all crates
make test               # protobuf wire + framing + status suites
```

The macOS SDK headers and lib path are injected via Alire's
`[environment.'case(os)'.macos]` blocks in each crate's `alire.toml` —
no external `SDKROOT` needed.

## Defining a service

```proto
syntax = "proto3";
package helloworld;

service Greeter {
  rpc SayHello (HelloRequest) returns (HelloReply);
}

message HelloRequest { string name = 1; }
message HelloReply   { string message = 1; }
```

`protoc-gen-grpc-ada` emits:

```
helloworld.ads                          -- empty parent
helloworld-hello_request.ads/adb        -- T + Encode/Decode
helloworld-hello_reply.ads/adb          -- T + Encode/Decode
helloworld-greeter.ads                  -- abstract Service + Path_*
helloworld-greeter-dispatch.ads/adb     -- Bind (Server, Service_Access)
helloworld-greeter-client.ads/adb       -- per-method stubs
```

Implement the abstract base (`override Say_Hello`), pass an aliased
instance to `Helloworld.Greeter.Dispatch.Bind`, run
`GRPC.Transport.HTTP2.Run`. The client calls
`Helloworld.Greeter.Client.Say_Hello (Channel, Request, Reply)`.

## License

MIT — see [LICENSE](LICENSE).
