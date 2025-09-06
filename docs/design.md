# Design notes

Rough thinking before any code goes down. Nothing here is final.

## What we're building

A gRPC implementation in Ada that looks and feels like grpc++ from the user
side, but stays small enough to read in an afternoon. Plus a `protoc` plugin
that emits Ada from `.proto` files.

## Layering

Bottom-up, mirroring grpc-core:

```
+------------------------------------------------------+
|  Surface API     Channel · Stub · Server · Service   |
+------------------------------------------------------+
|  Call layer      Call · Status · Metadata · Deadline |
+------------------------------------------------------+
|  Framing         5-byte length-prefix encoder        |
+------------------------------------------------------+
|  Transport       HTTP/2 over patched AWS             |
+------------------------------------------------------+
|  Codec runtime   Protobuf.Wire · Protobuf.IO         |
+------------------------------------------------------+
```

Generated code (from the `protoc` plugin) lives outside this stack and depends
on Surface API + Codec runtime.

## The trailer problem

gRPC sends `grpc-status` in HTTP/2 trailers. AWS's HTTP/2 server has no path
to emit a HEADERS frame after DATA frames — its stream state machine closes on
END_STREAM. So we'll fork AWS, add `Set_Trailers` on `AWS.Response.Data`, and
extend the stream writer to flush a trailer HEADERS frame just before
END_STREAM. Patch lives on a `grpc-ada` branch of our AWS fork; vendored as a
git submodule under `vendor/aws`.

Trailers-only responses (errors, no body) need the same patch's flush path
called from the headers stage instead.

## Codegen bootstrap

The plugin reads a `CodeGeneratorRequest` (which is itself a protobuf message)
from stdin. To parse that, we need a protobuf decoder. To get a decoder, we
need... a working protobuf decoder. The bootstrap: hand-write a subset of
descriptor.proto's types in Ada and decode them with our wire-format module.
Subset = whatever the codegen actually consumes (file names, packages,
messages, fields, enums, services, methods).

## Concurrency

One Ada task per active stream. The transport reader feeds a protected queue
per stream; handler tasks pull from it. AWS already multiplexes streams over a
connection so we just have to not block its reader.

## What's deliberately out of scope

- Connect-RPC, gRPC-Web (different wire protocols, deferred).
- Client- and bidi-streaming (architecture supports them, not built first).
- Compression. Send `compression-flag = 0` for now.
- Reflection, health-check.

## Questions to resolve as we go

- AWS HTTP/2 client-side: does it surface trailers to a callback? If not,
  Patch 3 will add it.
- Flow control: server-streaming may need explicit WINDOW_UPDATE handling.
- Generic instantiation footprint: each typed Stub method is a generic. How
  bad does object-file size get for a moderately big proto?
