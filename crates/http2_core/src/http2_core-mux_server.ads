--  Http2_Core.Mux_Server — multi-stream HTTP/2 server.
--
--  v0.3 scope: one TCP connection at a time, multiple concurrent
--  streams on that connection, single-threaded request dispatch.
--  Mirrors Http2_Core.Server but with a per-stream table indexed by
--  stream-id. Connection-level frames (PING / SETTINGS /
--  WINDOW_UPDATE on stream 0 / GOAWAY) are handled by the
--  connection driver; per-stream HEADERS and DATA are demuxed into
--  the matching Stream::Open FSM context.
--
--  Each stream slot owns its own pair of FSM buffers, allocated up
--  front at Listen and reused across stream lifetimes (no per-RPC
--  malloc). Max_Streams caps the in-flight stream count; new
--  HEADERS arriving when the table is full triggers RST_STREAM
--  (REFUSED_STREAM) per RFC 9113 §5.1.2.
--
--  HPACK: we still send HEADER_TABLE_SIZE = 0 in our SETTINGS, so
--  the peer's outbound HPACK never references the dynamic table.
--  This sidesteps the otherwise-necessary "shared dynamic table
--  across streams" coordination — each HEADERS frame is decoded
--  statelessly. Real HEADER_TABLE_SIZE > 0 is v0.4 work.
--
--  Lifecycle:
--    1. Listen — bind + listen.
--    2. Attach_Buffers — caller hands in the connection-level I/O
--       buffer (the same Buf the single-stream server uses).
--    3. Accept_And_Serve_Multi — accept one client, run the
--       connection until GOAWAY or EOF.

with RFLX.RFLX_Types;
with RFLX.RFLX_Builtin_Types;

with Http2_Core.Transport;
with Http2_Core.Hpack;

package Http2_Core.Mux_Server is

   type Listener is limited private;

   --  Maximum concurrent streams per connection. RFC 9113 §6.5.2
   --  recommends advertising this in SETTINGS_MAX_CONCURRENT_STREAMS;
   --  we already send 1 today (single-stream), this implementation
   --  will send Max_Streams instead.
   Max_Streams : constant := 16;

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural);

   --  Attaches one connection-scope I/O buffer (used for frame
   --  read/write into the socket). Per-stream FSM buffers are
   --  allocated internally at Listen time.
   procedure Attach_Buffer
     (L   : in out Listener;
      Buf : in out RFLX.RFLX_Types.Bytes_Ptr);

   procedure Detach_Buffer
     (L   : in out Listener;
      Buf : out RFLX.RFLX_Types.Bytes_Ptr);

   --  Accept one client and run the multi-stream connection until
   --  the peer GOAWAYs / closes or we hit a fatal protocol error.
   --  Handle_Request is invoked once per stream as soon as that
   --  stream's request body is complete (END_STREAM seen).
   --
   --  Same handler signature as Http2_Core.Server.Accept_And_Serve.
   --  Multi-stream variants for streaming RPCs are v0.4 work.
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
   procedure Accept_And_Serve_Multi (L : in out Listener);

   procedure Stop (L : in out Listener);

   Mux_Server_Error : exception;

private

   subtype Bit_Len is RFLX.RFLX_Builtin_Types.Bit_Length;

   --  Stream slot: one HTTP/2 stream's per-connection state. The
   --  FSM context is the protocol-correctness-critical part; the
   --  surrounding fields are accumulators consumed by the handler.
   type Stream_Phase is
     (Free,                 --  slot unused
      Awaiting_Body,        --  HEADERS seen, expecting DATA / END_STREAM
      Body_Complete,        --  END_STREAM seen, handler not yet run
      Closed);              --  response sent, slot draining

   type Stream_Slot is record
      Phase     : Stream_Phase := Free;
      Stream_Id : Bit_Len := 0;
      --  FSM buffers stay attached for the lifetime of the
      --  Listener — borrowed by Stream::Open during Initialize and
      --  returned via Finalize on Closed.
      Inbound_Buf  : RFLX.RFLX_Types.Bytes_Ptr := null;
      Outgoing_Buf : RFLX.RFLX_Types.Bytes_Ptr := null;
   end record;

   type Stream_Pool is array (1 .. Max_Streams) of Stream_Slot;

   type Listener is limited record
      Trans : Transport.Listener;
      Buf   : RFLX.RFLX_Types.Bytes_Ptr := null;
      Pool  : Stream_Pool;
   end record;

end Http2_Core.Mux_Server;
