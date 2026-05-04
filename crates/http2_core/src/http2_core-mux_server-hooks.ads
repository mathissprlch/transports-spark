--  Http2_Core.Mux_Server.Hooks — default hook implementations
--  shared by the variant subunits. Each variant of
--  Accept_And_Serve_Multi_* picks up these no-ops / default
--  accumulators where it doesn't need its own behavior.

with Http2_Core.Transport;

private package Http2_Core.Mux_Server.Hooks is

   --  Append a gRPC message into the slot's Bodies array. Used by
   --  the unary and server-streaming variants where the request
   --  body is consumed in one shot at Body_Complete.
   procedure Append_To_Body
     (L       : in out Listener;
      Chan    : Transport.Channel;
      Slot    : Positive;
      Message : RFLX.RFLX_Types.Bytes);

   --  No-op hooks for variants that don't use a particular phase.
   procedure Noop_Headers_Complete
     (L : in out Listener; Chan : Transport.Channel; Slot : Positive);

   procedure Noop_Body_Complete
     (L : in out Listener; Chan : Transport.Channel; Slot : Positive);

   procedure Noop_Tick
     (L             : in out Listener;
      Chan          : Transport.Channel;
      Slot          : Positive;
      Made_Progress : out Boolean);

   --  Emit a HEADERS+DATA?+trailers response in one shot and
   --  transition the slot to Closed. Used by unary and
   --  client-streaming variants — both produce a full response
   --  once the request is complete.
   procedure Send_Full_Response_And_Close
     (L              : in out Listener;
      Chan           : Transport.Channel;
      Slot           : Positive;
      Resp_Hdrs      : Hpack.Header_Block;
      Resp_Hdrs_Last : Natural;
      Resp_Body      : RFLX.RFLX_Types.Bytes;
      Resp_Body_Last : Natural;
      Trailers       : Hpack.Header_Block;
      Trailers_Last  : Natural);

end Http2_Core.Mux_Server.Hooks;
