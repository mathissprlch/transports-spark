--  SPARK gRPC framing layer.
--
--  Five-byte length-prefixed messages over ``Http2_Core`` streams,
--  payloads via ``Protobuf_Core``. Status, metadata, deadline,
--  trailers. Transport-agnostic: separate ``grpc_aws`` and
--  ``grpc_embed`` crates wire the underlying I/O.
package Grpc_Core is

end Grpc_Core;
