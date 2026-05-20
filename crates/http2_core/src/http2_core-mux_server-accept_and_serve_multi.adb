with Http2_Core.Mux_Server.Driver;
with Http2_Core.Mux_Server.Hooks;

separate (Http2_Core.Mux_Server)
procedure Accept_And_Serve_Multi (L : in out Listener) is

   --  Body_Complete hook: invoke the user's handler and emit the
   --  full response in one shot.
   procedure Run_Handler
     (L : in out Listener; Chan : Transport.Channel;
      Slot : Positive);

   procedure Run_Handler
     (L : in out Listener; Chan : Transport.Channel;
      Slot : Positive)
   is
      Resp_Hdrs       : Hpack.Header_Block (1 .. 16);
      Resp_Hdrs_Last  : Natural;
      Resp_Body       : RFLX.RFLX_Types.Bytes (1 .. 16384) :=
        (others => 0);
      Resp_Body_Last  : Natural;
      Trailers        : Hpack.Header_Block (1 .. 8);
      Trailers_Last   : Natural;
   begin
      Resp_Hdrs_Last := Resp_Hdrs'First - 1;
      Trailers_Last  := Trailers'First - 1;
      Resp_Body_Last := Integer (Resp_Body'First) - 1;

      Handle_Request
        (Slot                  => Slot,
         Request_Headers       => L.Headers (Slot),
         Request_Headers_Last  => L.Slots (Slot).Headers_Last,
         Request_Body          =>
           L.Bodies (Slot)
             (L.Bodies (Slot)'First ..
                RFLX.RFLX_Types.Index (L.Slots (Slot).Body_Cursor)),
         Request_Body_Last     => L.Slots (Slot).Body_Cursor,
         Response_Headers      => Resp_Hdrs,
         Response_Headers_Last => Resp_Hdrs_Last,
         Response_Body         => Resp_Body,
         Response_Body_Last    => Resp_Body_Last,
         Trailers              => Trailers,
         Trailers_Last         => Trailers_Last);

      Hooks.Send_Full_Response_And_Close
        (L, Chan, Slot,
         Resp_Hdrs, Resp_Hdrs_Last,
         Resp_Body, Resp_Body_Last,
         Trailers, Trailers_Last);
   end Run_Handler;

   procedure Run is new Driver
     (On_Inbound_Message  => Hooks.Append_To_Body,
      On_Headers_Complete => Hooks.Noop_Headers_Complete,
      On_Body_Complete    => Run_Handler,
      On_Streaming_Tick   => Hooks.Noop_Tick);

begin
   Run (L);
end Accept_And_Serve_Multi;
