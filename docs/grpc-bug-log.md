# gRPC + protobuf codegen bug log

Bugs in `protoc-gen-grpc-ada` codegen (`Codegen.Emit_*`) and the
`Grpc_Core` runtime layers. Classified per docs/conventions.md §9 taxonomy.

| Date | Found by | Component | Reference | Tag(s) | One-line summary | Commit |
|---|---|---|---|---|---|---|
| 2026-05-15 | Generated server: protobuf decode of large names | `Codegen.Emit_Server_V2.Emit` handler body | n/a (codegen) | (c)+(d) | The generated `Handle` used `Request_Body'Last` (buffer end, e.g. 64 KB) instead of `Request_Body_Last` (actual data end, e.g. 1 KB) when constructing the protobuf input slice. Trailing zero bytes decoded as empty fields for small payloads, but >4 KB names produced bogus length-delim varints. Fixed by slicing to `RFLX.RFLX_Types.Index (Request_Body_Last)`. (d): a Post on the protobuf decoder saying `Input'Length <= Spec_Encoded_Length (Spec_Output)` would have prevented this class of caller error. | (v0.5.1) |
