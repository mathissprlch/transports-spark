# transports-spark

Verified embedded transport stack in SPARK Ada. Two transports —
**MQTT 3.1.1** and **gRPC** — over two backends — Ada Web Server on
hosted Linux/macOS, and bare-metal MCU (STM32, Zynq). Verification
via AdaCore's [RecordFlux](https://github.com/AdaCore/RecordFlux) +
community GNATprove. No proprietary tooling.

The roadmap target is a formally verified MQTT 3.1.1 client in SPARK.
[SPARK CoAP](https://github.com/AdaCore/coap-spark) exists; an
open-source SPARK MQTT does not — that's the gap this fills. gRPC
follows as a second transport on the same verified `protobuf_core`.

## Status

**v0.1.0** (tagged) — pure-Ada gRPC over HTTP/2, end-to-end:

- Unary + server-streaming RPC. Helloworld + RouteGuide examples.
- Hand-written protobuf wire codec, descriptor decoder,
  `protoc-gen-grpc-ada` plugin, framing, status, metadata, channel,
  server, stubs.
- Single runtime dependency: a vendored AWS fork with two patches
  that teach its HTTP/2 server to emit trailers.

**v0.2** (in progress) — SPARK rework:

- `protobuf_core` — hand-written SPARK wire codec.
- `mqtt_core` — RecordFlux-driven SPARK MQTT 3.1.1 client (headline).
- `http2_core`, `grpc_core` — RecordFlux frame layer + SPARK framing;
  v0.1 gRPC refactored onto verified foundations.
- Bare-metal PoCs on STM32 + Zynq. Benchmarks: gRPC vs MQTT on
  identical hardware and payloads.

## Architecture

```
+--------------------------------------------------------+
|  Hosted (AWS)             Bare-metal MCU               |
+--------------------------------------------------------+
|  grpc_aws  mqtt_hosted    grpc_embed  mqtt_embed       |  transport bindings
+--------------------------------------------------------+
|  grpc_core | http2_core | mqtt_core | protobuf_core    |  SPARK cores
+--------------------------------------------------------+
```

`*_core` crates are transport-agnostic and SPARK-verified. Backend
crates wire the I/O. Bare-metal gRPC is a deliberate subset — single
bidi stream, static HPACK, bounded buffers, no heap — wire-compatible
with standard gRPC peers.

## V&V tiers

1. **SPARK Silver** across all code: absence of runtime errors.
2. **SPARK Gold** on load-bearing invariants: parser bounds, stream
   FSM, flow-control non-negative, MQTT QoS 1/2 delivery guarantees.
3. **Not** chasing full functional correctness vs HTTP/2 spec.

Where community GNATprove can't close a goal, it's documented as a
known gap rather than papered over.

## Quick start (v0.1, hosted)

```sh
$ make codegen build
$ ./crates/examples/bin/greeter_server &
Greeter listening on 0.0.0.0:50051

$ ./crates/examples/bin/greeter_client
Request:  World
Reply:    Hello, World!

# Wire conformance via raw HTTP/2:
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

`grpc-status: 0` in the trailing HEADERS frame confirms the AWS
trailer patches work.

## Layout

```
crates/
  protobuf_core/        SPARK protobuf wire codec (v0.2, hand-written)
  http2_core/           SPARK HTTP/2 frames + stream FSM (v0.2, RecordFlux + glue)
  mqtt_core/            SPARK MQTT 3.1.1 (v0.2, RecordFlux + glue)
  grpc_core/            SPARK gRPC framing on http2_core + protobuf_core (v0.2)
  protobuf_ada/         legacy: v0.1 protobuf codec (retires when protobuf_core lands)
  grpc_ada/             legacy: v0.1 gRPC runtime (retires when grpc_core + grpc_aws land)
  protoc_gen_grpc_ada/  protoc plugin (build-time; retargeted to protobuf_core)
  protobuf_ada_tests/   AUnit tests + fixtures
  examples/             helloworld + RouteGuide
targets/
  stm32f4/              STM32 Cortex-M (planned)
  zynq7000/             Xilinx Zynq-7000 (planned)
vendor/
  aws-patches/          unified diffs against AWS upstream (HTTP/2 trailer support)
  aws-overlays/         platform constants + helper GPRs
  bootstrap.sh          clones AWS at pin, applies patches
docs/
  design.md             architecture sketch
  aws-integration.md    AWS bootstrap details
  notes-grpc-wire.md    notes from PROTOCOL-HTTP2.md
  notes-protobuf.md     notes from the protobuf encoding spec
```

## Build

Tested on macOS arm64 with `alr 2.1.0` + `gnat_native 15.1.2` +
`gprbuild 25.0.1`. Linux x86_64 / aarch64 should work the same way
once a fresh `os_lib.ads` overlay is generated for the host (run
`vendor/aws-overlays/gen_os_lib.c`; output committed per platform).

```sh
./vendor/bootstrap.sh   # one-time: clone AWS at pin, apply patches
make codegen            # build plugin and regenerate Ada from .proto
make build              # all crates
make test               # protobuf wire + framing + status suites
```

The macOS SDK headers and lib path are injected via Alire's
`[environment.'case(os)'.macos]` blocks in each crate's `alire.toml`
— no external `SDKROOT` needed.

## Defining a service (v0.1 codegen)

```proto
syntax = "proto3";
package helloworld;

service Greeter {
  rpc SayHello (HelloRequest) returns (HelloReply);
}

message HelloRequest { string name = 1; }
message HelloReply   { string message = 1; }
```

`protoc-gen-grpc-ada` emits per service:

```
helloworld.ads                       empty parent
helloworld-hello_request.ads/adb     T + Encode/Decode
helloworld-hello_reply.ads/adb       T + Encode/Decode
helloworld-greeter.ads               abstract Service + Path_*
helloworld-greeter-dispatch.ads/adb  Bind (Server, Service_Access)
helloworld-greeter-client.ads/adb    per-method stubs
```

Implement the abstract base, pass an aliased instance to
`Helloworld.Greeter.Dispatch.Bind`, run `GRPC.Transport.HTTP2.Run`.
The client calls `Helloworld.Greeter.Client.Say_Hello (Channel,
Request, Reply)`. Codegen retargets to `protobuf_core` in v0.2.

## License

MIT — see [LICENSE](LICENSE).
