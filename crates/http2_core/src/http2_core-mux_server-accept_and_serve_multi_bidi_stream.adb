with Http2_Core.Mux_Server.Driver;
with Http2_Core.Mux_Server.Frames;
with Http2_Core.Mux_Server.Hooks;

separate (Http2_Core.Mux_Server)
procedure Accept_And_Serve_Multi_Bidi_Stream
  (L : in out Listener) is

   procedure Deliver
     (L : in out Listener; Chan : Transport.Channel;
      Slot : Positive; Message : RFLX.RFLX_Types.Bytes);

   procedure Deliver
     (L : in out Listener; Chan : Transport.Channel;
      Slot : Positive; Message : RFLX.RFLX_Types.Bytes)
   is
      pragma Unreferenced (L, Chan);
   begin
      On_Request_Message (Slot, Message);
   end Deliver;

   --  Headers_Complete (not Body_Complete): bidi fires
   --  Setup_Response as soon as the request HEADERS arrive and
   --  emits response HEADERS so the client can start receiving.
   procedure Begin_Stream
     (L : in out Listener; Chan : Transport.Channel;
      Slot : Positive);

   procedure Begin_Stream
     (L : in out Listener; Chan : Transport.Channel;
      Slot : Positive)
   is
      Resp_Hdrs      : Hpack.Header_Block (1 .. 16);
      Resp_Hdrs_Last : Natural;
   begin
      Resp_Hdrs_Last := Resp_Hdrs'First - 1;
      L.Slots (Slot).Slot_Trailers_Last :=
        L.Slot_Trailers (Slot)'First - 1;
      Setup_Response
        (Slot                  => Slot,
         Request_Headers       => L.Headers (Slot),
         Request_Headers_Last  => L.Slots (Slot).Headers_Last,
         Response_Headers      => Resp_Hdrs,
         Response_Headers_Last => Resp_Hdrs_Last,
         Trailers              => L.Slot_Trailers (Slot),
         Trailers_Last         => L.Slots (Slot).Slot_Trailers_Last);
      Frames.Send_Headers_Frame
        (L, Chan, L.Slots (Slot).Stream_Id,
         Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
         End_Stream => False);
      L.Slots (Slot).Phase := Streaming;
   end Begin_Stream;

   --  Streaming tick: pull one Next_Reply. Trailers go only when
   --  Next_Reply returned False AND the request has ended (the
   --  server may want to keep generating replies even after the
   --  client stops, or vice versa, until both sides are done).
   procedure Pump_Reply
     (L             : in out Listener;
      Chan          : Transport.Channel;
      Slot          : Positive;
      Made_Progress : out Boolean);

   procedure Pump_Reply
     (L             : in out Listener;
      Chan          : Transport.Channel;
      Slot          : Positive;
      Made_Progress : out Boolean)
   is
      Msg_Buf  : RFLX.RFLX_Types.Bytes (1 .. 16384) := (others => 0);
      Msg_Last : RFLX.RFLX_Types.Index;
      Has_Msg  : Boolean;
   begin
      --  RFC 9113 §6.9: connection or per-stream window depleted
      --  — back off until an inbound WINDOW_UPDATE refreshes it.
      declare
         use type Bit_Len;
      begin
         if L.Peer_Send_Window = 0
           or else L.Slots (Slot).Stream_Send_Window = 0
         then
            Made_Progress := False;
            return;
         end if;
      end;
      Has_Msg := Next_Reply (Slot, Msg_Buf, Msg_Last);
      if Has_Msg then
         Frames.Send_Data_Frame
           (L, Chan, L.Slots (Slot).Stream_Id,
            Msg_Buf (Msg_Buf'First .. Msg_Last),
            End_Stream => False);
         Made_Progress := True;
         return;
      end if;
      if L.Slots (Slot).End_Of_Request then
         Frames.Send_Headers_Frame
           (L, Chan, L.Slots (Slot).Stream_Id,
            L.Slot_Trailers (Slot)
              (L.Slot_Trailers (Slot)'First
                 .. L.Slots (Slot).Slot_Trailers_Last),
            End_Stream => True);
         L.Slots (Slot).Phase := Closed;
      end if;
      Made_Progress := False;
   end Pump_Reply;

   procedure Run is new Driver
     (On_Inbound_Message  => Deliver,
      On_Headers_Complete => Begin_Stream,
      On_Body_Complete    => Hooks.Noop_Body_Complete,
      On_Streaming_Tick   => Pump_Reply);

begin
   Run (L);
end Accept_And_Serve_Multi_Bidi_Stream;
