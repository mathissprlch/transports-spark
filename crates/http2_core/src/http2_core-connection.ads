--  Http2_Core.Connection — synchronous, single-stream HTTP/2 client.
--
--  v0.2 scope per ../specs/SCOPE.md: one stream open at a time, no
--  multiplexing, no priorities, no server push. Suitable for unary
--  gRPC RPCs (one HEADERS request → one HEADERS+DATA response →
--  trailing HEADERS) and the simpler streaming variants.
--
--  Lifecycle:
--    1. Open — TCP connect; emit §3.4 connection preface; emit our
--       SETTINGS; ACK peer SETTINGS; await our SETTINGS ACK.
--    2. Round_Trip — emit a HEADERS frame (with optional DATA tail)
--       on a freshly-issued stream id, then read inbound frames
--       until we see HEADERS+END_STREAM (or RST_STREAM) for that id.
--       Connection-management frames (PING, SETTINGS, WINDOW_UPDATE,
--       GOAWAY) are handled inline.
--    3. Close — emit GOAWAY(NO_ERROR), close socket.
--
--  Memory model: one fixed-size buffer per Connection (no per-RPC
--  heap), reused across operations. Inbound HEADERS fragments are
--  decoded into a caller-sized Hpack.Header_Block.
--
--  Out of scope (v0.2):
--    * Bidi-streaming with overlapped sends/receives — the API is
--      synchronous request/response.
--    * Trailers handling beyond mapping the trailing HEADERS frame
--      back to the caller (gRPC layer above does the grpc-status
--      interpretation).
--    * Reconnect / retry on flow-control stall. Single connection,
--      single attempt.

with RFLX.RFLX_Types;
with RFLX.RFLX_Builtin_Types;

with Http2_Core.Transport;
with Http2_Core.Hpack;

package Http2_Core.Connection is

   type Connection is limited private;

   --  Caller-supplied buffers. The Connection takes ownership on
   --  Attach (move semantics — the caller's pointers are nilled).
   --  Detach returns them. The library NEVER calls `new`; on bare-
   --  metal the application can back these with static `aliased
   --  Bytes` arrays via a custom storage pool.
   --
   --  Three buffers, mirroring Mqtt_Core.Client:
   --    * Buf          — driver working buffer (HPACK fragments,
   --                     outbound frames, hand-written ACKs)
   --    * Inbound_Buf  — external buffer attached to the
   --                     Stream::Half_Open FSM's B_Inbound slot
   --    * Outgoing_Buf — external buffer attached to the
   --                     Stream::Half_Open FSM's B_Outgoing slot
   procedure Attach_Buffers
     (C            : in out Connection;
      Buf          : in out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : in out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : in out RFLX.RFLX_Types.Bytes_Ptr);

   procedure Detach_Buffers
     (C            : in out Connection;
      Buf          : out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : out RFLX.RFLX_Types.Bytes_Ptr);

   --  Open a connection to host:port and complete the §3.4 preface +
   --  §6.5.3 SETTINGS handshake. Raises Connect_Error on socket
   --  failure or if the peer sends a malformed initial SETTINGS.
   --  Requires Attach_Buffers to have been called first.
   procedure Open
     (C    : in out Connection;
      Host : String;
      Port : Natural := 80);

   --  Perform a unary HTTP/2 round trip: send `Request_Headers` (with
   --  optional Request_Body in a single DATA frame) on a freshly-
   --  issued client stream id, then read until END_STREAM closes the
   --  reply.
   --
   --  On success:
   --    * Response_Headers contains the response header block (gRPC
   --      sees :status, content-type, plus any trailers in the
   --      trailing HEADERS frame).
   --    * Response_Body is filled with the concatenated DATA bytes.
   --    * Response_Body_Last is the index of the last filled byte.
   --
   --  Raises:
   --    * RPC_Error on RST_STREAM, GOAWAY mid-flight, decode
   --      failures, or buffer overflows.
   procedure Round_Trip
     (C                   : in out Connection;
      Request_Headers     : Hpack.Header_Block;
      Request_Body        : RFLX.RFLX_Types.Bytes;
      Response_Headers    : in out Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Response_Body       : in out RFLX.RFLX_Types.Bytes;
      Response_Body_Last  : out Natural);

   procedure Close (C : in out Connection);

   --  ===================================================================
   --  Streaming RPCs.
   --
   --  All four gRPC stream types share the same connection model:
   --  one HTTP/2 stream per RPC, request HEADERS + DATA + trailing
   --  HEADERS, with the difference being whether DATA messages
   --  flow one-shot or as a stream in either direction.
   --
   --    Round_Trip       — unary (1 req → 1 resp)
   --    Server_Stream    — 1 req → N resp     (Stream::Half_Open FSM)
   --    Client_Stream    — N req → 1 resp     (Stream::Client_Stream FSM)
   --    Bidi_Stream      — N req ↔ N resp     (Stream::Bidi_Stream FSM)
   --
   --  Callbacks use access-to-subprogram. The FSM remains SPARK-
   --  proven; this glue layer is hand-written.
   --  ===================================================================

   --  Generic procedures with formal subprogram parameters — lets
   --  callers pass nested procs / functions without Ada's library-
   --  level-only access-to-subprogram restriction.

   generic
      with procedure On_Message (Message : RFLX.RFLX_Types.Bytes);
   procedure Server_Stream
     (C                     : in out Connection;
      Request_Headers       : Hpack.Header_Block;
      Request_Body          : RFLX.RFLX_Types.Bytes;
      Response_Headers      : in out Hpack.Header_Block;
      Response_Headers_Last : out Natural);

   generic
      with function Next_Message
        (Out_Buf  : in out RFLX.RFLX_Types.Bytes;
         Out_Last : out RFLX.RFLX_Types.Index)
         return Boolean;
   procedure Client_Stream
     (C                     : in out Connection;
      Request_Headers       : Hpack.Header_Block;
      Response_Headers      : in out Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Response_Body         : in out RFLX.RFLX_Types.Bytes;
      Response_Body_Last    : out Natural);

   generic
      with function Next_Outbound
        (Out_Buf  : in out RFLX.RFLX_Types.Bytes;
         Out_Last : out RFLX.RFLX_Types.Index)
         return Boolean;
      with procedure On_Inbound (Message : RFLX.RFLX_Types.Bytes);
   procedure Bidi_Stream
     (C                     : in out Connection;
      Request_Headers       : Hpack.Header_Block;
      Response_Headers      : in out Hpack.Header_Block;
      Response_Headers_Last : out Natural);

   Connect_Error : exception;
   RPC_Error     : exception;

private

   --  Sized for unary gRPC: HEADERS fragment is rarely > 200B,
   --  request bodies < 1KB, responses likewise — but bound at
   --  16KB to match SETTINGS_MAX_FRAME_SIZE default per §6.5.2.
   Buffer_Capacity : constant := 16 * 1024 + 64;  -- 16KB + frame overhead

   type Connection is limited record
      Trans          : Transport.Channel;
      Buf            : RFLX.RFLX_Types.Bytes_Ptr := null;
      Inbound_Buf    : RFLX.RFLX_Types.Bytes_Ptr := null;
      Outgoing_Buf   : RFLX.RFLX_Types.Bytes_Ptr := null;
      --  Client stream ids start at 1 and increment by 2 (§5.1.1).
      Next_Stream_Id : RFLX.RFLX_Builtin_Types.Bit_Length := 1;
      --  RFC 9113 §6.9 flow-control accounting for the inbound
      --  side (server → client DATA). When ≥ Refill_At bytes have
      --  arrived since the last WINDOW_UPDATE, emit one to refresh
      --  by exactly that amount on stream 0 + the current stream.
      --  Without this, persistent connections hang once the peer's
      --  default 65 535-byte outbound window is exhausted.
      Conn_Bytes_Owed : RFLX.RFLX_Builtin_Types.Bit_Length := 0;
      --  HPACK decoder dynamic table; survives across all
      --  Round_Trip / streaming RPCs on this Connection.
      Hpack_Decoder  : Hpack.Dynamic_Table.Table;
   end record;

end Http2_Core.Connection;
