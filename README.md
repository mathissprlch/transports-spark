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

**v0.2** — SPARK rework, AWS replaced:

- `protobuf_core` — hand-written SPARK wire codec.
- `mqtt_core` — RecordFlux-driven SPARK MQTT 3.1.1 client + minimal
  broker (multi-client, topic routing, UNSUBSCRIBE).
- `http2_core` — RecordFlux frame layer (Frame, Settings, Goaway,
  WindowUpdate, RstStream, Headers, Ping) + Stream::Open / Half_Open
  state machines + handwritten HPACK (RFC 7541). Drops AWS entirely.
- `grpc_core` — gRPC framing (5-byte length prefix) + Status +
  Metadata over `http2_core`.
- Bare-metal track: memory-loopback `Transport` for in-image
  round-trips on Cortex-M / Zynq without GNAT.Sockets.

**v0.3** — full server functionality:

- `mqtt_core.broker` — full QoS 1/2 routing with per-client
  inflight tables (Awaiting_Puback / Awaiting_Pubrec /
  Awaiting_Pubcomp), 4-way handshake on both directions, multi-filter
  SUBSCRIBE with per-filter SUBACK return codes.
- `http2_core.server` — server-streaming, client-streaming, and bidi
  variants in addition to unary. Bidi runs pure-interleave via
  `Transport.Has_Pending` non-blocking poll.
- `http2_core.mux_server` — multi-stream HTTP/2: one TCP connection
  serves up to 16 concurrent streams demuxed by stream-id into
  per-stream `Stream::Open` FSMs. All four gRPC RPC types
  (unary, server-stream, client-stream, bidi) work concurrently
  on one connection with per-slot iterator state. RFC 9113 §5.1.2
  RST_STREAM (REFUSED_STREAM) when the pool is full.
- `http1_core` — minimal HTTP/1.1 server (RFC 9112 §3-4 subset:
  Content-Length body, Connection: close, no obs-fold, hand-written
  parser; RFLX-modeling deferred).

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

## Quick start

```sh
$ cd crates/examples && alr build
```

### gRPC (v0.2 single-stream + v0.3 multi-stream)

```sh
# Single-stream server: pick a mode (unary | server-stream |
# client-stream | bidi). Multi-mode demo for all four RPC types.
$ ./bin/greeter_streaming_server bidi 50051 &
$ echo '{"name":"alpha"}
{"name":"beta"}' | grpcurl -plaintext -d @ \
    -import-path proto -proto helloworld.proto \
    127.0.0.1:50051 helloworld.Greeter/BidiHello
{"message": "Hi, alpha!"}
{"message": "Hi, beta!"}

# Multi-stream server: up to 16 concurrent RPCs over one connection
# demuxed by stream-id. Mode picks RPC type:
#   unary | server-stream | client-stream | bidi
$ ./bin/greeter_mux_server bidi 50051 &
# 4 Python grpcio threads each running a BidiHello → ~10 ms total.
```

### MQTT broker (v0.3)

```sh
$ ./bin/mqtt_broker_demo 1883 &
$ ./bin/mqtt_demo 1883     # exercises QoS 0/1/2 + multi-topic SUBSCRIBE
mqtt_demo: subscribed to ada/test (QoS 2) + ada/aux (QoS 0)
mqtt_demo: QoS 1 publish (FSM-driven, awaits PUBACK)  -> publish acked
mqtt_demo: QoS 2 publish (FSM-driven, PUBREC + PUBCOMP)  -> completed
```

### HTTP/1.1 (v0.3)

```sh
$ ./bin/http1_demo 8080 &
$ curl -s http://localhost:8080/
Hello from Ada HTTP/1.1!
$ curl -s -X POST -d 'mixed Case' http://localhost:8080/upper
MIXED CASE
```

## Layout

```
crates/
  protobuf_core/        SPARK protobuf wire codec (v0.2, hand-written)
  http2_core/           SPARK HTTP/2 frames + stream FSMs + servers (v0.2-v0.3)
  http1_core/           Minimal HTTP/1.1 server (v0.3, hand-written wire)
  mqtt_core/            SPARK MQTT 3.1.1 client + broker (v0.2-v0.3)
  grpc_core/            SPARK gRPC framing on http2_core + protobuf_core (v0.2)
  rflx_runtime/         Shared RecordFlux runtime support
  protobuf_ada/         legacy: v0.1 protobuf codec (retires when protobuf_core lands)
  grpc_ada/             legacy: v0.1 gRPC runtime (retires when grpc_core lands)
  protoc_gen_grpc_ada/  protoc plugin (build-time)
  examples/             helloworld + RouteGuide + mqtt + http1 demos
  *_tests/              AUnit + scripted fuzz harnesses
targets/
  stm32f4/              STM32 Cortex-M (planned)
  zynq7000/             Xilinx Zynq-7000 (planned)
docs/
  design.md             architecture sketch (v0.1 baseline)
  notes-grpc-wire.md    notes from PROTOCOL-HTTP2.md
  notes-protobuf.md     notes from the protobuf encoding spec
```

## Build

Tested on macOS arm64 with `alr 2.1.0` + `gnat_native 15.1.2` +
`gprbuild 25.0.1`. Linux x86_64 / aarch64 should work the same way.
The v0.2+ stack drops the AWS dependency, so there's no submodule
or patch step — `alr build` in any crate suffices.

```sh
cd crates/examples && alr build      # builds all v0.1+v0.2+v0.3 demos
cd crates/<crate>_tests && alr run    # AUnit suites where they exist
```

The v0.1 `make codegen` flow is preserved for the legacy
`grpc_ada` / `protobuf_ada` crates; the v0.2+ stack does not need it.

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
