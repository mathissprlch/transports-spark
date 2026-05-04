with RFLX.Http2_Parameters;
use type RFLX.Http2_Parameters.HTTP_2_Frame_Type_Enum;

with RFLX.Stream.Open.FSM;

with Http2_Core.Wire;
with Http2_Core.Hpack;
with Http2_Core.Mux_Server.Frames;
with Http2_Core.Mux_Server.Slots;

procedure Http2_Core.Mux_Server.Driver (L : in out Listener) is

   use type RFLX.RFLX_Types.Index;
   use type RFLX.RFLX_Types.Length;
   use type RFLX.RFLX_Types.Byte;
   use type RFLX.RFLX_Types.Bytes_Ptr;
   use type Bit_Len;

   package FSM renames RFLX.Stream.Open.FSM;

   subtype U8 is RFLX.RFLX_Types.Byte;

   Chan : Transport.Channel;

   Goaway_Pending : Boolean := False;
   Last_Stream_Id : Bit_Len := 0;

   ---------------------------------------------------------------------
   --  Drain_Stream_App — pull every queued App_Pending frame out of
   --  the FSM for one slot. HEADERS frames have their HPACK fragment
   --  decoded into L.Headers (Slot); DATA payloads have the gRPC
   --  length prefix stripped and are dispatched via the variant's
   --  On_Inbound_Message hook. END_STREAM on either fires
   --  On_Body_Complete; HEADERS itself fires On_Headers_Complete.
   ---------------------------------------------------------------------

   procedure Drain_Stream_App (Slot : Positive);

   procedure Drain_Stream_App (Slot : Positive) is
   begin
      loop
         FSM.Run (L.Ctxs (Slot));
         exit when not FSM.Has_Data (L.Ctxs (Slot), FSM.C_App_Pending);
         declare
            N : constant RFLX.RFLX_Types.Length :=
              FSM.Read_Buffer_Size (L.Ctxs (Slot), FSM.C_App_Pending);
            View : RFLX.RFLX_Types.Bytes
              (L.Buf'First ..
                 L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
            Hdr : Wire.Frame_Header;
            Hdr_Valid : Boolean;
         begin
            FSM.Read (L.Ctxs (Slot), FSM.C_App_Pending, View);
            Wire.Decode_Frame_Header
              (Buffer => View (View'First .. View'First + 8),
               Header => Hdr, Valid => Hdr_Valid);
            if not Hdr_Valid then
               return;
            end if;
            case Hdr.Frame_Type_Value is
               when RFLX.Http2_Parameters.HEADERS =>
                  declare
                     Frag_First : RFLX.RFLX_Types.Index :=
                       View'First + 9;
                     Frag_Last  : constant RFLX.RFLX_Types.Index :=
                       View'Last;
                     Decode_OK  : Boolean;
                  begin
                     if (Hdr.Flags and Wire.Flag_PRIORITY) /= 0 then
                        Frag_First := Frag_First + 5;
                     end if;
                     declare
                        Frag : Hpack.Octet_Array
                          (1 .. Natural (Frag_Last - Frag_First) + 1);
                     begin
                        for K in Frag'Range loop
                           Frag (K) :=
                             Hpack.Octet
                               (View
                                  (Frag_First
                                   + RFLX.RFLX_Types.Index (K) - 1));
                        end loop;
                        Hpack.Decode
                          (Input        => Frag,
                           Headers      => L.Headers (Slot),
                           Headers_Last => L.Slots (Slot).Headers_Last,
                           Output_OK    => Decode_OK);
                        if not Decode_OK then
                           raise Mux_Server_Error
                             with "HPACK decode failed";
                        end if;
                     end;
                  end;
                  On_Headers_Complete (L, Chan, Slot);
                  if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                     L.Slots (Slot).End_Of_Request := True;
                     On_Body_Complete (L, Chan, Slot);
                  end if;

               when RFLX.Http2_Parameters.DATA =>
                  if Hdr.Length > 0 then
                     declare
                        First : constant RFLX.RFLX_Types.Index :=
                          View'First + 9;
                        Lst   : constant RFLX.RFLX_Types.Index :=
                          First +
                          RFLX.RFLX_Types.Index (Hdr.Length) - 1;
                        Pay   : constant RFLX.RFLX_Types.Bytes :=
                          View (First .. Lst);
                        Msg   : constant RFLX.RFLX_Types.Bytes :=
                          Frames.Strip_Grpc_Frame (Pay);
                     begin
                        if Msg'Length > 0 then
                           On_Inbound_Message (L, Chan, Slot, Msg);
                        end if;
                     end;
                  end if;
                  if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                     L.Slots (Slot).End_Of_Request := True;
                     On_Body_Complete (L, Chan, Slot);
                  end if;

               when others =>
                  --  Connection-mgmt frames bubble up here too
                  --  (Stream::Open's transition table forwards
                  --  them); already handled at the connection
                  --  layer via the stream-id == 0 fast path.
                  null;
            end case;
         end;
      end loop;
   end Drain_Stream_App;

   ---------------------------------------------------------------------
   --  Handle_Frame — connection-level routing. Stream-id 0 frames
   --  are PING / SETTINGS / GOAWAY (handled inline). Per-stream
   --  frames are routed to a slot — allocating a fresh one on the
   --  first HEADERS.
   ---------------------------------------------------------------------

   procedure Handle_Frame
     (Hdr  : Wire.Frame_Header;
      Last : RFLX.RFLX_Types.Index);

   procedure Handle_Frame
     (Hdr  : Wire.Frame_Header;
      Last : RFLX.RFLX_Types.Index)
   is
   begin
      if Hdr.Stream_Identifier = 0 then
         case Hdr.Frame_Type_Value is
            when RFLX.Http2_Parameters.PING =>
               if (Hdr.Flags and Wire.Flag_ACK) = 0
                 and Hdr.Length = 8
               then
                  Frames.Send_Ping_Ack
                    (L, Chan,
                     L.Buf.all (L.Buf'First + 9 .. L.Buf'First + 16));
               end if;
            when RFLX.Http2_Parameters.SETTINGS =>
               if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                  Frames.Send_Settings_Ack (L, Chan);
               end if;
            when RFLX.Http2_Parameters.GOAWAY =>
               Goaway_Pending := True;
            when others => null;
         end case;
         return;
      end if;

      declare
         Slot : Natural := Slots.Find_Slot (L, Hdr.Stream_Identifier);
      begin
         if Slot = 0 then
            if Hdr.Frame_Type_Value =
              RFLX.Http2_Parameters.HEADERS
            then
               Slot := Slots.Allocate_Slot (L, Hdr.Stream_Identifier);
               if Slot = 0 then
                  --  RFC 9113 §5.1.2: pool full → REFUSED_STREAM.
                  Frames.Send_Rst_Stream
                    (L, Chan, Hdr.Stream_Identifier, 7);
                  return;
               end if;
            else
               --  Late frame for a closed stream.
               return;
            end if;
         end if;

         if FSM.Needs_Data (L.Ctxs (Slot), FSM.C_Network) then
            FSM.Write
              (L.Ctxs (Slot),
               FSM.C_Network,
               L.Buf.all (L.Buf'First .. Last));
         end if;
         Drain_Stream_App (Slot);
      end;
   end Handle_Frame;

   ---------------------------------------------------------------------
   --  After the connection loop exits we still need to ack any
   --  trailing PING the peer sent (Python grpcio expects it for a
   --  clean shutdown). Best-effort drain — five frames, then GOAWAY.
   ---------------------------------------------------------------------

   procedure Drain_And_Goodbye;
   procedure Drain_And_Goodbye is
   begin
      for K in 1 .. 5 loop
         declare
            Hdr2 : Wire.Frame_Header;
            Last2 : RFLX.RFLX_Types.Index;
            OK2 : Boolean;
         begin
            Slots.Read_Frame (L, Chan, Hdr2, Last2, OK2);
            exit when not OK2;
            if Hdr2.Frame_Type_Value = RFLX.Http2_Parameters.PING
              and (Hdr2.Flags and Wire.Flag_ACK) = 0
              and Hdr2.Length = 8
            then
               Frames.Send_Ping_Ack
                 (L, Chan,
                  L.Buf.all (L.Buf'First + 9 .. L.Buf'First + 16));
               exit;
            end if;
         exception
            when others => exit;
         end;
      end loop;
      Frames.Send_Goaway (L, Chan, Last_Stream_Id);
   end Drain_And_Goodbye;

   ---------------------------------------------------------------------

begin
   if L.Buf = null then
      raise Mux_Server_Error
        with "Http2_Core.Mux_Server.Attach_Buffer must be called first";
   end if;

   Transport.Accept_One (L.Trans, Chan);
   Slots.Receive_Preface (Chan);
   Frames.Send_Settings_Initial (L, Chan);

   Connection_Loop :
   loop
      exit Connection_Loop when Goaway_Pending;

      declare
         Made_Progress : Boolean := False;
         Tick_Progress : Boolean;
      begin
         if Transport.Has_Pending (Chan) then
            declare
               Frame_Hdr : Wire.Frame_Header;
               Frame_Last : RFLX.RFLX_Types.Index;
               OK : Boolean;
            begin
               Slots.Read_Frame (L, Chan, Frame_Hdr, Frame_Last, OK);
               exit Connection_Loop when not OK;
               Handle_Frame (Frame_Hdr, Frame_Last);
               Made_Progress := True;
            end;
         end if;

         for I in L.Slots'Range loop
            case L.Slots (I).Phase is
               when Streaming =>
                  On_Streaming_Tick (L, Chan, I, Tick_Progress);
                  if Tick_Progress then
                     Made_Progress := True;
                  end if;
               when Closed =>
                  Last_Stream_Id := L.Slots (I).Stream_Id;
                  Slots.Release_Slot (L, I);
                  Made_Progress := True;
               when others => null;
            end case;
         end loop;

         if not Made_Progress then
            delay 0.001;
         end if;
      end;
   end loop Connection_Loop;

   Drain_And_Goodbye;

   for I in L.Slots'Range loop
      if L.Slots (I).Phase /= Free then
         Slots.Release_Slot (L, I);
      end if;
   end loop;

   Transport.Close (Chan);
end Http2_Core.Mux_Server.Driver;
