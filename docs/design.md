# Design notes

What v0.1 actually looks like. Earlier iterations of this file lived
under `git log -- docs/design.md`.

## What we built

A gRPC implementation in Ada whose runtime depends only on a vendored
fork of AWS. Single-runtime-dep is the architectural constraint that
shaped most of the choices below. Plus a `protoc` plugin that emits
Ada from `.proto` files.

## Layering

Bottom-up, mirroring grpc-core:

```
+----------------------------------------------------------+
|  Surface API     Channel · Stub · Server · Service       |   generated
+----------------------------------------------------------+   per-service
|  Dispatch glue   Generated Bind / Method handlers         |   by codegen
+----------------------------------------------------------+
|  Call layer      Call · Status · Metadata · Deadline      |
+----------------------------------------------------------+
|  Framing         5-byte compression-flag + big-endian len |
+----------------------------------------------------------+
|  Transport       GRPC.Transport.Stream  (abstract)        |
|                  GRPC.Transport.HTTP2   (over AWS)        |
+----------------------------------------------------------+
|  Codec runtime   Protobuf.Wire · Protobuf.IO              |
+----------------------------------------------------------+
```

Each generated package depends only on its layer and below. The
runtime never depends on generated code.

## The trailer patches

gRPC sends `grpc-status` in HTTP/2 trailers, but AWS's stream state
machine closes the stream on END_STREAM with no path to emit a
following HEADERS frame. Patch 1 (`vendor/aws-patches/0001-*`) adds
`AWS.Response.Set.Add_Trailer` plus accessors. Patch 2 (`0002-*`)
teaches the HTTP/2 message writer to suppress END_STREAM on the last
DATA frame when trailers are pending and append a trailer HEADERS
frame after the body.

The trailers-only path (errors before any body) reuses the same code:
`Has_Body` is false, so `More_Frames` returns true while trailers are
pending, and the trailer HEADERS frame carries END_STREAM directly.

Both patches are pure additions to AWS's existing types — no removed
or reshaped APIs — so they apply cleanly to upstream master and stay
mergeable upstream.

## Transport interface

`GRPC.Transport.Stream` is an abstract interface with six primitives:
`Send_Initial_Headers`, `Send_Message`, `Send_Trailers`,
`Receive_Initial_Headers`, `Receive_Message`, `Receive_Trailers`.
Concrete implementations live below it. v0.1 has one:
`GRPC.Transport.HTTP2.Server_Stream`, which buffers the AWS callback's
input and output then hands them back to the AWS layer. Server stream
is filled per request; the buffered Send_Message bytes become
`AWS.Response.Build`'s payload, the Send_Trailers map becomes
`Add_Trailer` calls, and the response goes back to AWS to serialize.

Streaming RPCs and a future bare-metal lwIP transport will plug in
here without touching anything above the framing layer.

## Codegen bootstrap

The plugin reads a `CodeGeneratorRequest` (itself a protobuf message)
from stdin. To parse that we need a protobuf decoder, but we're
writing the decoder. Bootstrap: hand-write a subset of
descriptor.proto's types in Ada and decode them with our own
wire-format module. Subset is exactly what the codegen consumes —
file names, packages, messages, fields, enums, services, methods.

The plugin emits, per service, three files:

- **Base spec** (`pkg-svc.ads`): abstract `Service` tagged type, one
  abstract subprogram per RPC, named `Service_Access` type, path
  string constants.
- **Dispatch** (`pkg-svc-dispatch.ads/adb`): one library-level
  Method_Handler per RPC that decodes the request, dispatches to
  `Bound.Method (Request, Response)`, encodes the response, and writes
  it back. `Bind (Server, Service_Access)` stashes the user's service
  ref and registers each handler with `GRPC.Server.Register_Method`.
- **Client** (`pkg-svc-client.ads/adb`): one library-level procedure
  per RPC that frames the request, calls `AWS.Client.Post` with
  `HTTPv2`, unwraps the response.

The pattern is mechanical and small — about 150 lines of generated
Ada per typical service.

## Why a named Service_Access type

Anonymous access parameters (`not null access Service'Class`) carry
their accessibility level dynamically, and assigning one into
library-level state trips a runtime check. The generated base exposes
`Service_Access` as a named type at library accessibility so Dispatch
can stash the user's service pointer cleanly. Callers use
`'Unchecked_Access` for procedure-local Service variables when the
lifetime is provably correct — the example takes this path because the
service is declared in `procedure Greeter_Server` and outlives
`GRPC.Transport.HTTP2.Run`.

## Concurrency model

AWS owns the listen socket and spawns a task per HTTP/2 connection;
within each connection it multiplexes streams. Our
`Service_Cb` runs on whichever task AWS hands us, which means handler
work happens directly on AWS's request thread. v0.1 is unary-only so
this is fine — handlers complete synchronously. Streaming will need a
per-stream queue that doesn't block AWS's reader; the architecture
supports it, the v0.1 implementation doesn't yet exercise it.

## Bare-metal door

The API is biased to keep a Phase 2 lwIP transport feasible without
breaking changes:

- Public framing and transport API takes
  `Ada.Streams.Stream_Element_Array`, never `String` or
  `Unbounded_String`.
- Generics that need a capacity (max streams, max headers) take it as
  a formal parameter, not via dynamic growth.
- `GRPC.Status` is a value type — never thrown across tasks, always
  returned. Bare-metal runtimes restrict cross-task exception
  propagation.
- `Metadata` accessors return slices/views where possible so a future
  bounded-storage backend can fit the same surface.

What stays out of v0.1 for bare-metal:
`Ada.Strings.Unbounded` is used internally; `Ada.Containers.Vectors`
is used in the server's method table; the example apps use `Text_IO`.
A Phase 2 port replaces these in the transport layer and below; the
upper layers stay.

## Out of scope

- Connect-RPC, gRPC-Web (different wire protocols).
- Client-streaming and bidi-streaming.
- Compression — `compression-flag = 0` everywhere.
- Reflection, health-check, channelz.
- TLS — plumbing is in AWS to add later.

## Open questions tracked for v0.2

- **AWS client-side trailer surface.** Server side is patched and
  proven. The Ada client today is happy because we don't depend on
  receiving trailers (response status is in `:status`). If a future
  flow needs `grpc-status` as a real signal on the client, AWS may
  need a third patch.
- **Generic instantiation footprint.** Each typed stub method emits a
  procedure body, not a generic instantiation, so this is currently
  fine. If we add streaming generics, watch object-file size.
- **Flow control for server-streaming.** Will need explicit
  `WINDOW_UPDATE` handling at the transport boundary.
