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

   --  RFC 9113 §6.9 flow-control accounting. We're conservative:
   --  every inbound DATA frame's payload counts against the
   --  connection-level + per-stream windows. When ≥ Refill_At
   --  bytes have accumulated since the last WINDOW_UPDATE, we
   --  send one to refresh by exactly that amount. Per-stream
   --  windows refill at the same threshold but are scoped per slot.
   Refill_At         : constant := 32_768;     --  half the default
   Conn_Bytes_Owed   : Bit_Len := 0;
   Stream_Bytes_Owed : array (1 .. Max_Streams) of Bit_Len :=
     (others => 0);

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

                     --  RFC 9113 §6.9: count the DATA frame's
                     --  payload (the full Hdr.Length, including
                     --  any padding) against both the connection
                     --  and the per-stream window. Refill once
                     --  we cross the threshold.
                     Conn_Bytes_Owed := Conn_Bytes_Owed + Hdr.Length;
                     Stream_Bytes_Owed (Slot) :=
                       Stream_Bytes_Owed (Slot) + Hdr.Length;
                     if Conn_Bytes_Owed >= Refill_At then
                        Frames.Send_Window_Update
                          (L, Chan, 0, Conn_Bytes_Owed);
                        Conn_Bytes_Owed := 0;
                     end if;
                     if Stream_Bytes_Owed (Slot) >= Refill_At then
                        Frames.Send_Window_Update
                          (L, Chan, L.Slots (Slot).Stream_Id,
                           Stream_Bytes_Owed (Slot));
                        Stream_Bytes_Owed (Slot) := 0;
                     end if;
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
                  --  RFC 9113 §6.5.1: zero or more 6-byte
                  --  parameters (16-bit id + 32-bit value, both
                  --  big-endian). We pick out
                  --  SETTINGS_INITIAL_WINDOW_SIZE (id=4); other
                  --  ids (HEADER_TABLE_SIZE, MAX_FRAME_SIZE,
                  --  MAX_CONCURRENT_STREAMS, ENABLE_PUSH,
                  --  MAX_HEADER_LIST_SIZE) are accepted-but-
                  --  ignored for now — we'll act on them as the
                  --  matching feature lands (HPACK dyn table
                  --  pulls in HEADER_TABLE_SIZE).
                  declare
                     Off : RFLX.RFLX_Types.Index :=
                       L.Buf'First + 9;
                     End_At : constant RFLX.RFLX_Types.Index :=
                       L.Buf'First + 9
                       + RFLX.RFLX_Types.Index (Hdr.Length) - 1;
                  begin
                     while Off + 5 <= End_At loop
                        declare
                           Id : constant Bit_Len :=
                             Bit_Len (L.Buf.all (Off)) * 256
                             + Bit_Len (L.Buf.all (Off + 1));
                           Val : constant Bit_Len :=
                             Bit_Len (L.Buf.all (Off + 2)) * 16777216
                             + Bit_Len (L.Buf.all (Off + 3)) * 65536
                             + Bit_Len (L.Buf.all (Off + 4)) * 256
                             + Bit_Len (L.Buf.all (Off + 5));
                        begin
                           if Id = 4 then  --  INITIAL_WINDOW_SIZE
                              --  RFC §6.9.2: when the setting
                              --  changes mid-connection, the
                              --  receiver MUST adjust the size of
                              --  all open streams' send windows by
                              --  the delta. New streams allocated
                              --  after this point pick up the new
                              --  value via Allocate_Slot.
                              declare
                                 Old : constant Bit_Len :=
                                   L.Initial_Stream_Window;
                              begin
                                 if Val >= Old then
                                    declare
                                       Up : constant Bit_Len :=
                                         Val - Old;
                                    begin
                                       for SI in L.Slots'Range loop
                                          if L.Slots (SI).Phase /= Free
                                          then
                                             L.Slots (SI).Stream_Send_Window :=
                                               L.Slots (SI).Stream_Send_Window
                                               + Up;
                                          end if;
                                       end loop;
                                    end;
                                 else
                                    declare
                                       Down : constant Bit_Len :=
                                         Old - Val;
                                    begin
                                       for SI in L.Slots'Range loop
                                          if L.Slots (SI).Phase /= Free
                                          then
                                             if L.Slots (SI).Stream_Send_Window
                                               >= Down
                                             then
                                                L.Slots (SI).Stream_Send_Window :=
                                                  L.Slots (SI).Stream_Send_Window
                                                  - Down;
                                             else
                                                L.Slots (SI).Stream_Send_Window := 0;
                                             end if;
                                          end if;
                                       end loop;
                                    end;
                                 end if;
                                 L.Initial_Stream_Window := Val;
                              end;
                           end if;
                        end;
                        Off := Off + 6;
                     end loop;
                  end;
                  Frames.Send_Settings_Ack (L, Chan);
               end if;
            when RFLX.Http2_Parameters.GOAWAY =>
               Goaway_Pending := True;
            when RFLX.Http2_Parameters.WINDOW_UPDATE =>
               --  RFC 9113 §6.9.1: 4-byte big-endian increment in
               --  the payload (high bit reserved, ignored). On
               --  Stream_Identifier=0 this bumps the connection-
               --  level send window; per-stream variants
               --  (Stream_Identifier > 0) are routed below to the
               --  matching slot's Stream_Send_Window.
               if Hdr.Length = 4 then
                  declare
                     B0 : constant U8 :=
                       L.Buf.all (L.Buf'First + 9) and 16#7F#;
                     B1 : constant U8 :=
                       L.Buf.all (L.Buf'First + 10);
                     B2 : constant U8 :=
                       L.Buf.all (L.Buf'First + 11);
                     B3 : constant U8 :=
                       L.Buf.all (L.Buf'First + 12);
                     Inc : constant Bit_Len :=
                       Bit_Len (B0) * 16777216
                       + Bit_Len (B1) * 65536
                       + Bit_Len (B2) * 256
                       + Bit_Len (B3);
                  begin
                     L.Peer_Send_Window :=
                       L.Peer_Send_Window + Inc;
                  end;
               end if;
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

         --  RFC 9113 §6.9.1 stream-level WINDOW_UPDATE — bumps the
         --  matching slot's per-stream send window. Handled here
         --  rather than fed into the Stream::Open FSM since this
         --  is a transport-layer concern.
         if Hdr.Frame_Type_Value =
           RFLX.Http2_Parameters.WINDOW_UPDATE
           and then Hdr.Length = 4
         then
            declare
               B0 : constant U8 :=
                 L.Buf.all (L.Buf'First + 9) and 16#7F#;
               B1 : constant U8 :=
                 L.Buf.all (L.Buf'First + 10);
               B2 : constant U8 :=
                 L.Buf.all (L.Buf'First + 11);
               B3 : constant U8 :=
                 L.Buf.all (L.Buf'First + 12);
               Inc : constant Bit_Len :=
                 Bit_Len (B0) * 16777216
                 + Bit_Len (B1) * 65536
                 + Bit_Len (B2) * 256
                 + Bit_Len (B3);
            begin
               L.Slots (Slot).Stream_Send_Window :=
                 L.Slots (Slot).Stream_Send_Window + Inc;
            end;
            return;
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
         Has_Streaming : Boolean := False;
         Got_Data      : Boolean;
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
                  Has_Streaming := True;
                  On_Streaming_Tick (L, Chan, I, Tick_Progress);
                  if Tick_Progress then
                     Made_Progress := True;
                  end if;
               when Closed =>
                  Last_Stream_Id := L.Slots (I).Stream_Id;
                  --  Per-stream window dies with the stream; reset
                  --  so the slot's next tenant starts at zero.
                  Stream_Bytes_Owed (I) := 0;
                  Slots.Release_Slot (L, I);
                  Made_Progress := True;
               when others => null;
            end case;
         end loop;

         --  No-progress wait. When there are no Streaming slots
         --  the only thing that can wake us is inbound data, so
         --  block on the socket up to 100 ms — wakes immediately
         --  when a frame arrives, costs nothing while idle. With
         --  Streaming slots in flight we still need to busy-poll
         --  in case On_Streaming_Tick produces a reply on the
         --  next iteration; cap the polling at 100 µs so reply
         --  latency stays bounded.
         if not Made_Progress then
            if Has_Streaming then
               Transport.Wait_For_Data (Chan, 0.0001, Got_Data);
            else
               Transport.Wait_For_Data (Chan, 0.1, Got_Data);
            end if;
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
