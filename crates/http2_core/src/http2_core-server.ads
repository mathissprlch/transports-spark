--  Http2_Core.Server — single-stream HTTP/2 server.
--
--  v0.2 scope per ../specs/SCOPE.md, server side: one client at a
--  time, one stream per client. Suitable for unary gRPC RPCs against
--  a tooling client (grpcurl, python grpc) — the server-streaming
--  case can be added by extending the response loop. Multi-client +
--  multi-stream is v0.5 work.
--
--  Lifecycle:
--    1. Listen — bind + listen on host:port.
--    2. Accept_One — block until a client connects.
--    3. Serve_Once — receive HTTP/2 preface, exchange SETTINGS,
--       read HEADERS+optional DATA, dispatch via the caller-supplied
--       request handler, send HEADERS+DATA+trailing HEADERS.
--    4. Stop — close listening socket.

with RFLX.RFLX_Types;
with RFLX.RFLX_Builtin_Types;

with Http2_Core.Transport;
with Http2_Core.Hpack;

package Http2_Core.Server is

   type Listener is limited private;

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural);

   --  Buffers attached to the per-connection state for the next
   --  Accept_And_Serve. Like the client side, library never `new`s.
   procedure Attach_Buffers
     (L            : in out Listener;
      Buf          : in out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : in out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : in out RFLX.RFLX_Types.Bytes_Ptr);

   procedure Detach_Buffers
     (L            : in out Listener;
      Buf          : out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : out RFLX.RFLX_Types.Bytes_Ptr);

   --  Accept one client and serve a single RPC, then close. The
   --  generic formal Handle_Request is invoked once per accepted
   --  client between request consumption and response emission:
   --    * Request_Headers — :method, :path, :authority, content-type
   --      etc. (all the HEADERS the client sent)
   --    * Request_Body — the concatenated DATA frame payloads
   --      (gRPC-framed; caller strips the 5-byte prefix).
   --    * Response_Headers — fill with :status, content-type, plus
   --      whatever the application needs.
   --    * Response_Body — the response message bytes (caller is
   --      responsible for the gRPC 5-byte prefix).
   --    * Trailers — gRPC-trailing HEADERS (e.g. grpc-status, grpc-
   --      message). Sent after Response_Body with END_STREAM.
   generic
      with procedure Handle_Request
        (Request_Headers       : Hpack.Header_Block;
         Request_Headers_Last  : Natural;
         Request_Body          : RFLX.RFLX_Types.Bytes;
         Request_Body_Last     : Natural;
         Response_Headers      : in out Hpack.Header_Block;
         Response_Headers_Last : out Natural;
         Response_Body         : in out RFLX.RFLX_Types.Bytes;
         Response_Body_Last    : out Natural;
         Trailers              : in out Hpack.Header_Block;
         Trailers_Last         : out Natural);
   procedure Accept_And_Serve (L : in out Listener);

   --  Server-streaming: handler is invoked once with the request,
   --  then yields N response messages via Next_Reply. Each reply
   --  is gRPC-framed and sent as one DATA frame. Caller is
   --  responsible for putting the 5-byte gRPC framing prefix +
   --  protobuf body into Out_Buf.
   generic
      with procedure Setup_Response
        (Request_Headers       : Hpack.Header_Block;
         Request_Headers_Last  : Natural;
         Request_Body          : RFLX.RFLX_Types.Bytes;
         Request_Body_Last     : Natural;
         Response_Headers      : in out Hpack.Header_Block;
         Response_Headers_Last : out Natural;
         Trailers              : in out Hpack.Header_Block;
         Trailers_Last         : out Natural);
      with function Next_Reply
        (Out_Buf  : in out RFLX.RFLX_Types.Bytes;
         Out_Last : out RFLX.RFLX_Types.Index)
         return Boolean;
   procedure Accept_And_Serve_Server_Stream (L : in out Listener);

   --  Client-streaming: each inbound DATA frame's gRPC message
   --  (stripped 5-byte prefix) is delivered to On_Request_Message;
   --  after END_STREAM, Build_Response is invoked to fill the single
   --  reply (gRPC-framed in Response_Body by the caller).
   generic
      with procedure On_Request_Message
        (Message : RFLX.RFLX_Types.Bytes);
      with procedure Build_Response
        (Request_Headers       : Hpack.Header_Block;
         Request_Headers_Last  : Natural;
         Response_Headers      : in out Hpack.Header_Block;
         Response_Headers_Last : out Natural;
         Response_Body         : in out RFLX.RFLX_Types.Bytes;
         Response_Body_Last    : out Natural;
         Trailers              : in out Hpack.Header_Block;
         Trailers_Last         : out Natural);
   procedure Accept_And_Serve_Client_Stream (L : in out Listener);

   --  Bidi-streaming: response HEADERS sent up front (after request
   --  HEADERS arrived). Then both directions stream interleaved.
   --  Driver uses non-blocking select-style polling on the socket so
   --  the server can push replies independently of inbound frame
   --  timing — reply latency is bounded by the 1 ms idle backoff,
   --  not by the next client message. Loop ends when Next_Reply
   --  returns False AND client has END_STREAM'd. Trailers sent after.
   generic
      with procedure Setup_Response
        (Request_Headers       : Hpack.Header_Block;
         Request_Headers_Last  : Natural;
         Response_Headers      : in out Hpack.Header_Block;
         Response_Headers_Last : out Natural;
         Trailers              : in out Hpack.Header_Block;
         Trailers_Last         : out Natural);
      with procedure On_Request_Message
        (Message : RFLX.RFLX_Types.Bytes);
      with function Next_Reply
        (Out_Buf  : in out RFLX.RFLX_Types.Bytes;
         Out_Last : out RFLX.RFLX_Types.Index)
         return Boolean;
   procedure Accept_And_Serve_Bidi_Stream (L : in out Listener);

   procedure Stop (L : in out Listener);

   Server_Error : exception;

private

   type Listener is limited record
      Trans         : Transport.Listener;
      Buf           : RFLX.RFLX_Types.Bytes_Ptr := null;
      Inbound_Buf   : RFLX.RFLX_Types.Bytes_Ptr := null;
      Outgoing_Buf  : RFLX.RFLX_Types.Bytes_Ptr := null;
      --  Decoder dynamic table — survives across all RPCs served
      --  on this listener (one connection at a time).
      Hpack_Decoder : Hpack.Dynamic_Table.Table;
   end record;

end Http2_Core.Server;
