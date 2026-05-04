--  Http2_Core.Mux_Server.Driver — connection driver shared by all
--  four mux-server variants. The driver owns the connection
--  lifecycle (preface, settings, frame demux, FSM driving, GOAWAY,
--  socket close); each variant supplies four hooks that decide
--  what to do at the per-stream phase transitions.
--
--  Hooks (called with `L : in out Listener` and `Slot : Positive`):
--
--    On_Inbound_Message — fired for each inbound gRPC message
--      (a DATA frame's payload with the 5-byte length prefix
--      already stripped). Default behavior for unary and server-
--      streaming is "accumulate into Bodies(Slot)"; client- and
--      bidi-streaming override to deliver to the user's callback.
--
--    On_Headers_Complete — fired the iteration after the request
--      HEADERS frame fully parsed, while Phase = Headers_Complete.
--      Bidi uses this to call Setup_Response and emit response
--      HEADERS up front; the others ignore it.
--
--    On_Body_Complete — fired the iteration after END_STREAM on
--      the request side, while Phase = Body_Complete. Unary calls
--      Handle_Request, server-stream calls Setup_Response,
--      client-stream calls Build_Response. Bidi ignores this
--      (its End_Of_Request flag is what matters).
--
--    On_Streaming_Tick — fired every iteration while a slot is
--      in Phase = Streaming. Server-stream and bidi pull
--      Next_Reply here; the others never enter Streaming.
--      Returns Made_Progress so the driver can decide whether
--      to idle-sleep.

with Http2_Core.Transport;

private generic
   with procedure On_Inbound_Message
     (L       : in out Listener;
      Chan    : Transport.Channel;
      Slot    : Positive;
      Message : RFLX.RFLX_Types.Bytes);
   with procedure On_Headers_Complete
     (L    : in out Listener;
      Chan : Transport.Channel;
      Slot : Positive);
   with procedure On_Body_Complete
     (L    : in out Listener;
      Chan : Transport.Channel;
      Slot : Positive);
   with procedure On_Streaming_Tick
     (L             : in out Listener;
      Chan          : Transport.Channel;
      Slot          : Positive;
      Made_Progress : out Boolean);
procedure Http2_Core.Mux_Server.Driver
  (L : in out Listener);
