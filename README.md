# grpc-ada

A from-scratch implementation of [gRPC](https://grpc.io) in Ada.

Status: early exploration. Nothing works yet.

## Goals

- gRPC over HTTP/2, oriented on the C/C++ reference implementation.
- Single runtime dependency: [AWS](https://github.com/AdaCore/aws) (Ada Web Server),
  with a small patch to add HTTP/2 trailer support.
- A `protoc` plugin written in Ada that emits idiomatic Ada client stubs and
  server bases from `.proto` files.

## Non-goals (for now)

- Connect-RPC, gRPC-Web.
- Compression, reflection, health-check.
- Windows.

## Layout (planned)

```
crates/
  protobuf_ada/        — protobuf wire format + descriptor decoder
  grpc_ada/            — gRPC runtime
  protoc_gen_grpc_ada/ — code generator (protoc plugin)
  examples/
vendor/aws/            — pinned AWS fork
```

## License

MIT — see [LICENSE](LICENSE).
