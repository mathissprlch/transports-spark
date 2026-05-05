--  Http2_Core.Mux_Server — multi-stream HTTP/2 server.
--
--  v0.3 scope: one TCP connection at a time, multiple concurrent
--  streams on that connection, single-threaded request dispatch.
--  All four gRPC RPC types (unary + server-stream + client-stream
--  + bidi) are served by per-RPC-type variants of
--  Accept_And_Serve_Multi_* below.
--
--  Connection-level frames (PING / SETTINGS / WINDOW_UPDATE on
--  stream 0 / GOAWAY) are handled by the connection driver; per-
--  stream HEADERS / DATA are demuxed into the matching slot's
--  Stream::Open FSM context. New streams above the cap trigger
--  RST_STREAM(REFUSED_STREAM) per RFC 9113 §5.1.2.
--
--  The four public variants share one connection driver
--  (Http2_Core.Mux_Server.Driver). They differ only in how each
--  slot's request body and response are handled — see the
--  per-variant comments below.

with RFLX.RFLX_Types;
with RFLX.RFLX_Builtin_Types;
private with RFLX.Stream.Open.FSM;

with Http2_Core.Transport;
with Http2_Core.Hpack;

package Http2_Core.Mux_Server is

   type Listener is limited private;

   --  Maximum concurrent streams per connection.
   Max_Streams : constant := 16;

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural);

   --  Attaches one connection-scope I/O buffer for frame read /
   --  write. Per-stream FSM buffers are allocated internally at
   --  Listen time (one pair per slot, reused across stream
   --  lifetimes — no per-RPC malloc).
   procedure Attach_Buffer
     (L   : in out Listener;
      Buf : in out RFLX.RFLX_Types.Bytes_Ptr);

   procedure Detach_Buffer
     (L   : in out Listener;
      Buf : out RFLX.RFLX_Types.Bytes_Ptr);

   --  Unary: Handle_Request runs once per stream when END_STREAM
   --  arrives on the request side. Returns a full
   --  HEADERS+DATA+trailers response in one shot.
   generic
      with procedure Handle_Request
        (Slot                  : Positive;
         Request_Headers       : Hpack.Header_Block;
         Request_Headers_Last  : Natural;
         Request_Body          : RFLX.RFLX_Types.Bytes;
         Request_Body_Last     : Natural;
         Response_Headers      : in out Hpack.Header_Block;
         Response_Headers_Last : out Natural;
         Response_Body         : in out RFLX.RFLX_Types.Bytes;
         Response_Body_Last    : out Natural;
         Trailers              : in out Hpack.Header_Block;
         Trailers_Last         : out Natural);
   procedure Accept_And_Serve_Multi (L : in out Listener);

   --  Server-streaming: Setup_Response runs once per stream when
   --  END_STREAM arrives on the request side. The driver then
   --  pumps Next_Reply for that slot until it returns False;
   --  trailers go and the slot closes.
   generic
      with procedure Setup_Response
        (Slot                  : Positive;
         Request_Headers       : Hpack.Header_Block;
         Request_Headers_Last  : Natural;
         Request_Body          : RFLX.RFLX_Types.Bytes;
         Request_Body_Last     : Natural;
         Response_Headers      : in out Hpack.Header_Block;
         Response_Headers_Last : out Natural;
         Trailers              : in out Hpack.Header_Block;
         Trailers_Last         : out Natural);
      with function Next_Reply
        (Slot     : Positive;
         Out_Buf  : in out RFLX.RFLX_Types.Bytes;
         Out_Last : out RFLX.RFLX_Types.Index)
         return Boolean;
   procedure Accept_And_Serve_Multi_Server_Stream
     (L : in out Listener);

   --  Client-streaming: each inbound DATA frame's gRPC message is
   --  delivered via On_Request_Message (with the slot index so the
   --  app can accumulate per-stream). When END_STREAM arrives,
   --  Build_Response runs and emits the single reply.
   generic
      with procedure On_Request_Message
        (Slot    : Positive;
         Message : RFLX.RFLX_Types.Bytes);
      with procedure Build_Response
        (Slot                  : Positive;
         Request_Headers       : Hpack.Header_Block;
         Request_Headers_Last  : Natural;
         Response_Headers      : in out Hpack.Header_Block;
         Response_Headers_Last : out Natural;
         Response_Body         : in out RFLX.RFLX_Types.Bytes;
         Response_Body_Last    : out Natural;
         Trailers              : in out Hpack.Header_Block;
         Trailers_Last         : out Natural);
   procedure Accept_And_Serve_Multi_Client_Stream
     (L : in out Listener);

   --  Bidi: response HEADERS go out as soon as the request HEADERS
   --  arrive (Setup_Response runs at that point). Each inbound
   --  DATA delivers a message; the driver pumps Next_Reply for
   --  that slot independently of inbound timing. Slot closes when
   --  Next_Reply returns False AND the request has ended.
   generic
      with procedure Setup_Response
        (Slot                  : Positive;
         Request_Headers       : Hpack.Header_Block;
         Request_Headers_Last  : Natural;
         Response_Headers      : in out Hpack.Header_Block;
         Response_Headers_Last : out Natural;
         Trailers              : in out Hpack.Header_Block;
         Trailers_Last         : out Natural);
      with procedure On_Request_Message
        (Slot    : Positive;
         Message : RFLX.RFLX_Types.Bytes);
      with function Next_Reply
        (Slot     : Positive;
         Out_Buf  : in out RFLX.RFLX_Types.Bytes;
         Out_Last : out RFLX.RFLX_Types.Index)
         return Boolean;
   procedure Accept_And_Serve_Multi_Bidi_Stream
     (L : in out Listener);

   procedure Stop (L : in out Listener);

   Mux_Server_Error : exception;

private

   subtype Bit_Len is RFLX.RFLX_Builtin_Types.Bit_Length;

   --  Per-slot phase. Headers_Complete fires as soon as the
   --  request HEADERS frame is parsed (used by bidi to fire
   --  Setup_Response without waiting for body). Body_Complete
   --  fires on END_STREAM (used by unary / server-stream /
   --  client-stream to dispatch the handler). Streaming carries
   --  server-stream / bidi past the headers/body phase while the
   --  app emits replies.
   type Stream_Phase is
     (Free,
      Headers_Complete,
      Awaiting_Body,
      Body_Complete,
      Streaming,
      Closed);

   --  Per-slot lightweight state.
   type Slot_State is record
      Phase     : Stream_Phase := Free;
      Stream_Id : Bit_Len := 0;
      --  FSM I/O buffers — owned by the slot for its lifetime,
      --  borrowed by Stream::Open.FSM during Initialize and
      --  returned via Finalize on Closed.
      Inbound_Buf  : RFLX.RFLX_Types.Bytes_Ptr := null;
      Outgoing_Buf : RFLX.RFLX_Types.Bytes_Ptr := null;
      --  Request accumulators.
      Headers_Last         : Natural := 0;
      Body_Cursor          : Integer := 0;  --  last filled index
      --  Streaming/bidi only.
      Slot_Trailers_Last   : Natural := 0;
      End_Of_Request       : Boolean := False;
      --  RFC 9113 §6.9.2 per-stream outbound flow-control window.
      --  Initialized at slot allocation from
      --  Listener.Initial_Stream_Window (peer's
      --  SETTINGS_INITIAL_WINDOW_SIZE), bumped by inbound
      --  WINDOW_UPDATE on this stream id, decremented by the byte
      --  count of each DATA frame the driver sends. Streaming
      --  Pump_Reply hooks skip a tick when this would underflow.
      Stream_Send_Window : Bit_Len := 65_535;
   end record;

   --  Per-slot heavy buffers kept in parallel arrays so Slot_State
   --  itself stays small.
   type Ctx_Pool      is array (1 .. Max_Streams)
     of RFLX.Stream.Open.FSM.Context;
   type Hdr_Block_Pool is array (1 .. Max_Streams)
     of Hpack.Header_Block (1 .. 16);
   type Body_Bytes_Pool is array (1 .. Max_Streams)
     of RFLX.RFLX_Types.Bytes (1 .. 16384);
   type Trailers_Pool is array (1 .. Max_Streams)
     of Hpack.Header_Block (1 .. 8);

   type Slot_Pool is array (1 .. Max_Streams) of Slot_State;

   type Listener is limited record
      Trans         : Transport.Listener;
      Buf           : RFLX.RFLX_Types.Bytes_Ptr := null;
      Slots         : Slot_Pool;
      Ctxs          : Ctx_Pool;
      Headers       : Hdr_Block_Pool;
      Bodies        : Body_Bytes_Pool;
      Slot_Trailers : Trailers_Pool;
      --  RFC 9113 §6.9 outbound flow control. The peer's
      --  connection-level inbound window (= our send window)
      --  starts at 65 535 (the default) and is replenished by
      --  inbound WINDOW_UPDATE frames on stream 0. Decremented
      --  by the byte count of each DATA frame we send. Streaming
      --  Pump_Reply hooks skip a tick when this would underflow.
      Peer_Send_Window : Bit_Len := 65_535;

      --  RFC 9113 §6.5.2 SETTINGS_INITIAL_WINDOW_SIZE — the
      --  per-stream initial flow-control window the peer
      --  advertised. Default 65 535; updated by inbound SETTINGS
      --  parameter id=4. Used as the initial per-stream send
      --  window for newly-allocated slots. Also used to delta-
      --  adjust open slots when the peer changes the setting
      --  mid-connection.
      Initial_Stream_Window : Bit_Len := 65_535;
   end record;

end Http2_Core.Mux_Server;
