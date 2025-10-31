--  GRPC — gRPC for Ada.
--
--  Children:
--    GRPC.Status     — status codes and error mapping
--    GRPC.Metadata   — request/response/trailing headers
--    GRPC.Framing    — 5-byte length-prefix frame encoder/decoder
--    GRPC.Deadline   — grpc-timeout header parsing/emission
--    GRPC.Call       — per-RPC state
--    GRPC.Server     — server / Server_Builder
--    GRPC.Channel    — client connection
--    GRPC.Service    — generic helpers for generated service bases
--    GRPC.Stub       — generic helpers for generated client stubs
--    GRPC.Transport  — abstract transport interface
--    GRPC.Transport.HTTP2 — concrete transport over patched AWS

package GRPC is
   pragma Pure;
end GRPC;
