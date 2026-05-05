with Http2_Core.Mux_Server.Driver;
with Http2_Core.Mux_Server.Frames;
with Http2_Core.Mux_Server.Hooks;

separate (Http2_Core.Mux_Server)
procedure Accept_And_Serve_Multi_Server_Stream
  (L : in out Listener) is

   use type RFLX.RFLX_Types.Index;

   --  Body_Complete: caller's Setup_Response runs once, response
   --  HEADERS go out, slot transitions to Streaming. From there the
   --  driver pumps Pump_Reply each iteration.
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
         Request_Body          =>
           L.Bodies (Slot)
             (L.Bodies (Slot)'First ..
                RFLX.RFLX_Types.Index (L.Slots (Slot).Body_Cursor)),
         Request_Body_Last     => L.Slots (Slot).Body_Cursor,
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

   --  Per-iteration tick: pull one Next_Reply. False → trailers go
   --  and the slot closes.
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
      --  RFC 9113 §6.9: the peer's advertised window is exhausted;
      --  defer pumping until an inbound WINDOW_UPDATE refreshes it.
      --  Don't even ask the application for a reply — that would
      --  require a queue to hold it; instead, idle this tick.
      declare
         use type Bit_Len;
      begin
         if L.Peer_Send_Window = 0 then
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
      else
         Frames.Send_Headers_Frame
           (L, Chan, L.Slots (Slot).Stream_Id,
            L.Slot_Trailers (Slot)
              (L.Slot_Trailers (Slot)'First
                 .. L.Slots (Slot).Slot_Trailers_Last),
            End_Stream => True);
         L.Slots (Slot).Phase := Closed;
         Made_Progress := False;
      end if;
   end Pump_Reply;

   procedure Run is new Driver
     (On_Inbound_Message  => Hooks.Append_To_Body,
      On_Headers_Complete => Hooks.Noop_Headers_Complete,
      On_Body_Complete    => Begin_Stream,
      On_Streaming_Tick   => Pump_Reply);

begin
   Run (L);
end Accept_And_Serve_Multi_Server_Stream;
