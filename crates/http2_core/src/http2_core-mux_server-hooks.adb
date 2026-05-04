with Http2_Core.Mux_Server.Frames;

package body Http2_Core.Mux_Server.Hooks is

   use type RFLX.RFLX_Types.Index;

   procedure Append_To_Body
     (L       : in out Listener;
      Chan    : Transport.Channel;
      Slot    : Positive;
      Message : RFLX.RFLX_Types.Bytes)
   is
      pragma Unreferenced (Chan);
   begin
      if L.Slots (Slot).Body_Cursor + Message'Length
        <= Integer (L.Bodies (Slot)'Last)
      then
         L.Bodies (Slot)
           (RFLX.RFLX_Types.Index (L.Slots (Slot).Body_Cursor + 1)
            .. RFLX.RFLX_Types.Index
                 (L.Slots (Slot).Body_Cursor + Message'Length))
           := Message;
         L.Slots (Slot).Body_Cursor :=
           L.Slots (Slot).Body_Cursor + Message'Length;
      end if;
   end Append_To_Body;

   procedure Noop_Headers_Complete
     (L : in out Listener; Chan : Transport.Channel; Slot : Positive)
   is
      pragma Unreferenced (L, Chan, Slot);
   begin
      null;
   end Noop_Headers_Complete;

   procedure Noop_Body_Complete
     (L : in out Listener; Chan : Transport.Channel; Slot : Positive)
   is
      pragma Unreferenced (L, Chan, Slot);
   begin
      null;
   end Noop_Body_Complete;

   procedure Noop_Tick
     (L             : in out Listener;
      Chan          : Transport.Channel;
      Slot          : Positive;
      Made_Progress : out Boolean)
   is
      pragma Unreferenced (L, Chan, Slot);
   begin
      Made_Progress := False;
   end Noop_Tick;

   procedure Send_Full_Response_And_Close
     (L              : in out Listener;
      Chan           : Transport.Channel;
      Slot           : Positive;
      Resp_Hdrs      : Hpack.Header_Block;
      Resp_Hdrs_Last : Natural;
      Resp_Body      : RFLX.RFLX_Types.Bytes;
      Resp_Body_Last : Natural;
      Trailers       : Hpack.Header_Block;
      Trailers_Last  : Natural)
   is
   begin
      Frames.Send_Headers_Frame
        (L, Chan, L.Slots (Slot).Stream_Id,
         Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
         End_Stream => False);
      if Resp_Body_Last >= Integer (Resp_Body'First) then
         Frames.Send_Data_Frame
           (L, Chan, L.Slots (Slot).Stream_Id,
            Resp_Body
              (Resp_Body'First ..
                 RFLX.RFLX_Types.Index (Resp_Body_Last)),
            End_Stream => False);
      end if;
      Frames.Send_Headers_Frame
        (L, Chan, L.Slots (Slot).Stream_Id,
         Trailers (Trailers'First .. Trailers_Last),
         End_Stream => True);
      L.Slots (Slot).Phase := Closed;
   end Send_Full_Response_And_Close;

end Http2_Core.Mux_Server.Hooks;
