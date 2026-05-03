with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.Http2_Parameters;
with RFLX.Stream.Open.FSM;

with Http2_Core.Wire;

package body Http2_Core.Server is

   use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;
   use type RFLX.RFLX_Builtin_Types.Bit_Length;
   use type RFLX.RFLX_Builtin_Types.Byte;
   use type RFLX.Http2_Parameters.HTTP_2_Frame_Type_Enum;
   use type RFLX.RFLX_Types.Length;

   subtype U8       is RFLX.RFLX_Types.Byte;
   subtype Bit_Len  is RFLX.RFLX_Builtin_Types.Bit_Length;

   ---------------------------------------------------------------------
   --  Listen / Stop / Buffer attachment
   ---------------------------------------------------------------------

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural)
   is
   begin
      Transport.Listen (L.Trans, Host, Port);
   end Listen;

   procedure Stop (L : in out Listener) is
   begin
      if Transport.Is_Listening (L.Trans) then
         Transport.Stop (L.Trans);
      end if;
   end Stop;

   procedure Attach_Buffers
     (L            : in out Listener;
      Buf          : in out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : in out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : in out RFLX.RFLX_Types.Bytes_Ptr)
   is
   begin
      L.Buf          := Buf;
      L.Inbound_Buf  := Inbound_Buf;
      L.Outgoing_Buf := Outgoing_Buf;
      Buf            := null;
      Inbound_Buf    := null;
      Outgoing_Buf   := null;
   end Attach_Buffers;

   procedure Detach_Buffers
     (L            : in out Listener;
      Buf          : out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : out RFLX.RFLX_Types.Bytes_Ptr)
   is
   begin
      Buf            := L.Buf;
      Inbound_Buf    := L.Inbound_Buf;
      Outgoing_Buf   := L.Outgoing_Buf;
      L.Buf          := null;
      L.Inbound_Buf  := null;
      L.Outgoing_Buf := null;
   end Detach_Buffers;

   ---------------------------------------------------------------------
   --  Read_Frame — same shape as the client's local helper, but
   --  reads from a passed-in Channel rather than a Connection.
   ---------------------------------------------------------------------

   procedure Read_Frame
     (Trans   : Transport.Channel;
      Buf     : RFLX.RFLX_Types.Bytes_Ptr;
      Header  :    out Wire.Frame_Header;
      Last    :    out RFLX.RFLX_Types.Index;
      Success :    out Boolean);

   procedure Read_Frame
     (Trans   : Transport.Channel;
      Buf     : RFLX.RFLX_Types.Bytes_Ptr;
      Header  :    out Wire.Frame_Header;
      Last    :    out RFLX.RFLX_Types.Index;
      Success :    out Boolean)
   is
      Hdr_Slice : RFLX.RFLX_Types.Bytes (Buf'First .. Buf'First + 8);
      Hdr_OK    : Boolean;
   begin
      Header  := (others => <>);
      Last    := Buf'First;
      Success := False;
      Transport.Receive_Full (Trans, Hdr_Slice, Hdr_OK);
      if not Hdr_OK then
         return;
      end if;
      Buf.all (Buf'First .. Buf'First + 8) := Hdr_Slice;
      Wire.Decode_Frame_Header
        (Buffer => Buf.all (Buf'First .. Buf'First + 8),
         Header => Header,
         Valid  => Hdr_OK);
      if not Hdr_OK then
         return;
      end if;
      if Header.Length = 0 then
         Last    := Buf'First + 8;
         Success := True;
         return;
      end if;
      if Bit_Len (Buf'Length) < Header.Length + 9 then
         return;
      end if;
      declare
         Body_Slice : RFLX.RFLX_Types.Bytes
           (Buf'First + 9 ..
              Buf'First + 8 + RFLX.RFLX_Types.Index (Header.Length));
         Body_OK : Boolean;
      begin
         Transport.Receive_Full (Trans, Body_Slice, Body_OK);
         if not Body_OK then
            return;
         end if;
         Buf.all (Body_Slice'Range) := Body_Slice;
         Last    := Body_Slice'Last;
         Success := True;
      end;
   end Read_Frame;

   ---------------------------------------------------------------------
   --  Accept_And_Serve — full server-side handshake + one RPC.
   ---------------------------------------------------------------------

   procedure Accept_And_Serve (L : in out Listener)
   is
      Chan      : Transport.Channel;
      Stream_Id : Bit_Len := 0;

      Got_Peer_Settings : Boolean := False;
      Got_Settings_Ack  : Boolean := False;
   begin
      if L.Buf = null
        or else L.Inbound_Buf = null
        or else L.Outgoing_Buf = null
      then
         raise Server_Error
           with "Http2_Core.Server.Attach_Buffers must be called first";
      end if;

      Transport.Accept_One (L.Trans, Chan);

      --  §3.4 — server reads 24-byte preface from client first.
      declare
         Pref_Bytes : RFLX.RFLX_Types.Bytes
           (RFLX.RFLX_Types.Index'First ..
              RFLX.RFLX_Types.Index'First +
              RFLX.RFLX_Types.Index (Wire.Preface'Length) - 1);
         Pref_OK : Boolean;
      begin
         Transport.Receive_Full (Chan, Pref_Bytes, Pref_OK);
         if not Pref_OK then
            Transport.Close (Chan);
            raise Server_Error with "EOF before preface";
         end if;
         for I in Pref_Bytes'Range loop
            if Pref_Bytes (I) /=
              U8 (Character'Pos
                    (Wire.Preface
                       (Wire.Preface'First +
                          Integer (I - Pref_Bytes'First))))
            then
               Transport.Close (Chan);
               raise Server_Error with "bad preface";
            end if;
         end loop;
      end;

      --  §6.5 — server emits its own SETTINGS as the first frame
      --  after the preface (mirror of client side).
      declare
         Last : RFLX.RFLX_Types.Index;
         Params : constant Wire.Settings_List (1 .. 3) :=
           ((Identifier => RFLX.Http2_Parameters.HEADER_TABLE_SIZE,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.ENABLE_PUSH,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.MAX_CONCURRENT_STREAMS,
             Value      => 1));
      begin
         Wire.Encode_Settings (L.Buf, Last, Params);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
      end;

      --  Note: we don't run a separate SETTINGS-handshake loop here.
      --  The FSM's Awaiting_Headers state already enumerates SETTINGS
      --  in its dispatch table (Forwarding_Connection_Frame), so we
      --  let the main FSM driver handle SETTINGS, PING, etc. inline
      --  with the HEADERS frame the client pipelines after them.
      --  Reading SETTINGS in a separate prologue would race with
      --  the HEADERS frame and silently drop it.
      pragma Unreferenced (Got_Peer_Settings);
      pragma Unreferenced (Got_Settings_Ack);

      --  Drive Stream::Open FSM through the request/response cycle.
      declare
         package FSM renames RFLX.Stream.Open.FSM;
         use type FSM.State;
         Ctx : FSM.Context;

         Request_Headers : Hpack.Header_Block (1 .. 16);
         Request_Headers_Last : Natural;
         Request_Body  : RFLX.RFLX_Types.Bytes (1 .. 16384) :=
           (others => 0);
         Request_Body_Cursor : Integer :=
           Integer (Request_Body'First) - 1;
         Got_End_Of_Request : Boolean := False;
      begin
         FSM.Initialize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
         Request_Headers_Last := Request_Headers'First - 1;

         --  Pre-feed: the FSM's first state (Awaiting_Headers) does
         --  Network'Read; if no data has been fed before the first
         --  Run, Verify_Message fails on empty buffer and the FSM
         --  goes straight to S_Final. Same trap as MQTT's Receive
         --  machine — see the MQTT driver for the same pattern.
         declare
            Frame_Last : RFLX.RFLX_Types.Index;
            Frame_Hdr  : Wire.Frame_Header;
            Read_OK    : Boolean;
         begin
            Read_Frame (Chan, L.Buf, Frame_Hdr, Frame_Last, Read_OK);
            if not Read_OK then
               FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
               Transport.Close (Chan);
               raise Server_Error with "EOF before first frame";
            end if;
            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               FSM.Write
                 (Ctx, FSM.C_Network,
                  L.Buf.all (L.Buf'First .. Frame_Last));
            end if;
         end;

         --  Phase 1: read request HEADERS + body. Drive FSM until
         --  it transitions out of the request side (Loading_Response
         --  next-state).
         Drive_Request :
         loop
            FSM.Run (Ctx);
            exit Drive_Request when not FSM.Active (Ctx);
            exit Drive_Request when
              FSM.Next_State (Ctx) = FSM.S_Loading_Response;

            if FSM.Has_Data (Ctx, FSM.C_Network) then
               --  Server-side FSM might have ACK frames to send.
               declare
                  N : constant RFLX.RFLX_Types.Length :=
                    FSM.Read_Buffer_Size (Ctx, FSM.C_Network);
                  View : RFLX.RFLX_Types.Bytes
                    (L.Buf'First ..
                       L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
               begin
                  FSM.Read (Ctx, FSM.C_Network, View);
                  Transport.Send (Chan, View);
               end;
            end if;

            if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
               declare
                  N : constant RFLX.RFLX_Types.Length :=
                    FSM.Read_Buffer_Size (Ctx, FSM.C_App_Pending);
                  View : RFLX.RFLX_Types.Bytes
                    (L.Buf'First ..
                       L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
                  Hdr        : Wire.Frame_Header;
                  Hdr_Valid  : Boolean;
               begin
                  FSM.Read (Ctx, FSM.C_App_Pending, View);
                  if View'Length < 9 then
                     FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     Transport.Close (Chan);
                     raise Server_Error with "short pending frame";
                  end if;
                  Wire.Decode_Frame_Header
                    (Buffer => View (View'First .. View'First + 8),
                     Header => Hdr,
                     Valid  => Hdr_Valid);
                  if not Hdr_Valid then
                     FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     Transport.Close (Chan);
                     raise Server_Error with "bad pending frame header";
                  end if;
                  case Hdr.Frame_Type_Value is
                     when RFLX.Http2_Parameters.HEADERS =>
                        Stream_Id := Hdr.Stream_Identifier;
                        --  Decode HPACK fragment.
                        if (Hdr.Flags and Wire.Flag_END_HEADERS) = 0 then
                           FSM.Finalize
                             (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                           Transport.Close (Chan);
                           raise Server_Error
                             with "CONTINUATION not supported";
                        end if;
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
                                (1 ..
                                   Natural (Frag_Last - Frag_First) + 1);
                           begin
                              for I in Frag'Range loop
                                 Frag (I) :=
                                   Hpack.Octet
                                     (View
                                        (Frag_First
                                         + RFLX.RFLX_Types.Index (I)
                                         - 1));
                              end loop;
                              Hpack.Decode
                                (Input        => Frag,
                                 Headers      => Request_Headers,
                                 Headers_Last => Request_Headers_Last,
                                 Output_OK    => Decode_OK);
                              if not Decode_OK then
                                 FSM.Finalize
                                   (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                                 Transport.Close (Chan);
                                 raise Server_Error
                                   with "HPACK decode failed";
                              end if;
                           end;
                        end;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                           Got_End_Of_Request := True;
                        end if;
                     when RFLX.Http2_Parameters.DATA =>
                        if Hdr.Length > 0 then
                           declare
                              Need : constant Integer :=
                                Request_Body_Cursor + 1
                                + Integer (Hdr.Length);
                           begin
                              if Need > Integer (Request_Body'Last) then
                                 FSM.Finalize
                                   (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                                 Transport.Close (Chan);
                                 raise Server_Error
                                   with "request body overflow";
                              end if;
                              for I in 1 .. Integer (Hdr.Length) loop
                                 Request_Body_Cursor :=
                                   Request_Body_Cursor + 1;
                                 Request_Body
                                   (RFLX.RFLX_Types.Index
                                      (Request_Body_Cursor)) :=
                                   View
                                     (View'First + 8
                                      + RFLX.RFLX_Types.Index (I));
                              end loop;
                           end;
                        end if;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                           Got_End_Of_Request := True;
                        end if;
                     when RFLX.Http2_Parameters.RST_STREAM =>
                        FSM.Finalize
                          (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                        Transport.Close (Chan);
                        raise Server_Error with "client RST_STREAM";
                     when RFLX.Http2_Parameters.PING =>
                        if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                           declare
                              Ack_Last : RFLX.RFLX_Types.Index;
                              Echo : constant RFLX.RFLX_Types.Bytes :=
                                View
                                  (View'First + 9 ..
                                     View'First + 16);
                           begin
                              Wire.Encode_Ping
                                (Buffer => L.Buf, Last => Ack_Last,
                                 Opaque_Data => Echo, Ack => True);
                              Transport.Send
                                (Chan,
                                 L.Buf.all (L.Buf'First .. Ack_Last));
                           end;
                        end if;
                     when RFLX.Http2_Parameters.SETTINGS =>
                        if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                           declare
                              Ack_Last : RFLX.RFLX_Types.Index;
                           begin
                              Wire.Encode_Settings_Ack
                                (L.Buf, Ack_Last);
                              Transport.Send
                                (Chan,
                                 L.Buf.all (L.Buf'First .. Ack_Last));
                           end;
                        end if;
                     when RFLX.Http2_Parameters.WINDOW_UPDATE =>
                        null;
                     when RFLX.Http2_Parameters.GOAWAY =>
                        FSM.Finalize
                          (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                        Transport.Close (Chan);
                        raise Server_Error with "client GOAWAY";
                     when others =>
                        null;
                  end case;
               end;
            end if;

            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               declare
                  Frame_Last : RFLX.RFLX_Types.Index;
                  Frame_Hdr  : Wire.Frame_Header;
                  Read_OK    : Boolean;
               begin
                  Read_Frame (Chan, L.Buf, Frame_Hdr, Frame_Last, Read_OK);
                  if not Read_OK then
                     FSM.Finalize
                       (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     Transport.Close (Chan);
                     raise Server_Error with "EOF in request";
                  end if;
                  if FSM.Needs_Data (Ctx, FSM.C_Network) then
                     FSM.Write
                       (Ctx, FSM.C_Network,
                        L.Buf.all (L.Buf'First .. Frame_Last));
                  end if;
               end;
            end if;
         end loop Drive_Request;

         --  Phase 2: invoke caller's handler.
         declare
            Resp_Hdrs : Hpack.Header_Block (1 .. 16);
            Resp_Hdrs_Last : Natural;
            Resp_Body : RFLX.RFLX_Types.Bytes (1 .. 16384) :=
              (others => 0);
            Resp_Body_Last : Natural;
            Trailers : Hpack.Header_Block (1 .. 8);
            Trailers_Last : Natural;
         begin
            declare
               Empty_Slice : constant RFLX.RFLX_Types.Bytes (1 .. 0) :=
                 (others => 0);
               Have_Body   : constant Boolean :=
                 Request_Body_Cursor >= Integer (Request_Body'First);
            begin
            Handle_Request
              (Request_Headers       => Request_Headers,
               Request_Headers_Last  => Request_Headers_Last,
               Request_Body          =>
                 (if Have_Body then
                    Request_Body
                      (Request_Body'First ..
                         RFLX.RFLX_Types.Index (Request_Body_Cursor))
                  else Empty_Slice),
               Request_Body_Last     => Request_Body_Cursor,
               Response_Headers      => Resp_Hdrs,
               Response_Headers_Last => Resp_Hdrs_Last,
               Response_Body         => Resp_Body,
               Response_Body_Last    => Resp_Body_Last,
               Trailers              => Trailers,
               Trailers_Last         => Trailers_Last);

            --  Phase 3: emit response. Compose the three frames
            --  (HEADERS, DATA, trailing-HEADERS) into L.Buf and
            --  hand to FSM via App_Outbox one at a time. Drive
            --  Loading_Response → Sending_Response loop.

            --  Send response HEADERS (no END_STREAM — we'll send
            --  body and trailers).
            declare
               Frag_Out  : Hpack.Octet_Array
                 (1 .. Hpack.Max_Header_Length * Hpack.Max_Headers);
               Frag_Last : Natural;
               Frag_OK   : Boolean;
               Frame_Last : RFLX.RFLX_Types.Index;
            begin
               Hpack.Encode
                 (Headers     =>
                    Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
                  Output      => Frag_Out,
                  Output_Last => Frag_Last,
                  Output_OK   => Frag_OK);
               if not Frag_OK then
                  FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                  Transport.Close (Chan);
                  raise Server_Error with "response HPACK encode failed";
               end if;
               declare
                  Frag_Bytes : RFLX.RFLX_Types.Bytes
                    (1 .. RFLX.RFLX_Types.Index (Frag_Last));
               begin
                  for I in 1 .. Frag_Last loop
                     Frag_Bytes (RFLX.RFLX_Types.Index (I)) :=
                       U8 (Frag_Out (I));
                  end loop;
                  Wire.Encode_Headers
                    (Buffer => L.Buf, Last => Frame_Last,
                     Stream_Id => Stream_Id, Fragment => Frag_Bytes,
                     End_Stream => False);
               end;
               Transport.Send (Chan, L.Buf.all (L.Buf'First .. Frame_Last));
            end;

            --  Send response DATA (gRPC-framed bytes from caller).
            if Resp_Body_Last >= Integer (Resp_Body'First) then
               declare
                  Data_Last : RFLX.RFLX_Types.Index;
                  Body_View : constant RFLX.RFLX_Types.Bytes :=
                    Resp_Body
                      (Resp_Body'First ..
                         RFLX.RFLX_Types.Index (Resp_Body_Last));
               begin
                  Wire.Encode_Data
                    (Buffer => L.Buf, Last => Data_Last,
                     Stream_Id => Stream_Id, Payload => Body_View,
                     End_Stream => False);
                  Transport.Send
                    (Chan, L.Buf.all (L.Buf'First .. Data_Last));
               end;
            end if;

            --  Send trailing HEADERS (END_STREAM closes the stream).
            declare
               Frag_Out  : Hpack.Octet_Array
                 (1 .. Hpack.Max_Header_Length * Hpack.Max_Headers);
               Frag_Last : Natural;
               Frag_OK   : Boolean;
               Frame_Last : RFLX.RFLX_Types.Index;
            begin
               Hpack.Encode
                 (Headers     =>
                    Trailers (Trailers'First .. Trailers_Last),
                  Output      => Frag_Out,
                  Output_Last => Frag_Last,
                  Output_OK   => Frag_OK);
               if not Frag_OK then
                  FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                  Transport.Close (Chan);
                  raise Server_Error
                    with "trailers HPACK encode failed";
               end if;
               declare
                  Frag_Bytes : RFLX.RFLX_Types.Bytes
                    (1 .. RFLX.RFLX_Types.Index (Frag_Last));
               begin
                  for I in 1 .. Frag_Last loop
                     Frag_Bytes (RFLX.RFLX_Types.Index (I)) :=
                       U8 (Frag_Out (I));
                  end loop;
                  Wire.Encode_Headers
                    (Buffer => L.Buf, Last => Frame_Last,
                     Stream_Id => Stream_Id, Fragment => Frag_Bytes,
                     End_Stream => True);
               end;
               Transport.Send
                 (Chan, L.Buf.all (L.Buf'First .. Frame_Last));
            end;
            end;  --  declare Have_Body / Empty_Slice
         end;

         FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
         pragma Unreferenced (Got_End_Of_Request);
      end;

      --  Drain post-response frames and answer PING with PING-ACK.
      --  Python grpcio sends a PING after the response and waits
      --  for the ACK before treating the RPC as cleanly complete;
      --  without it the client surfaces "Socket closed" on TCP-FIN.
      for K in 1 .. 5 loop
         declare
            Hdr2 : Wire.Frame_Header;
            Last2 : RFLX.RFLX_Types.Index;
            OK2 : Boolean;
         begin
            Read_Frame (Chan, L.Buf, Hdr2, Last2, OK2);
            exit when not OK2;
            if Hdr2.Frame_Type_Value = RFLX.Http2_Parameters.PING
              and (Hdr2.Flags and Wire.Flag_ACK) = 0
              and Hdr2.Length = 8
            then
               declare
                  Ack_Last : RFLX.RFLX_Types.Index;
                  Echo : constant RFLX.RFLX_Types.Bytes :=
                    L.Buf.all (L.Buf'First + 9 .. L.Buf'First + 16);
               begin
                  Wire.Encode_Ping
                    (Buffer => L.Buf, Last => Ack_Last,
                     Opaque_Data => Echo, Ack => True);
                  Transport.Send
                    (Chan, L.Buf.all (L.Buf'First .. Ack_Last));
               end;
               exit;  --  PING-ACK sent, we're done
            end if;
            --  WINDOW_UPDATE / GOAWAY / RST_STREAM — log + continue
         exception
            when others => exit;
         end;
      end loop;

      --  §6.8 — emit GOAWAY before closing so the client sees a
      --  clean shutdown instead of a "socket closed" error. Python
      --  grpcio reads frames eagerly and surfaces the bare TCP-FIN
      --  as transport.Status.UNAVAILABLE; GOAWAY tells it the
      --  shutdown is intentional.
      declare
         Goaway_Last : RFLX.RFLX_Types.Index;
         Empty : constant RFLX.RFLX_Types.Bytes (1 .. 0) :=
           (others => 0);
      begin
         Wire.Encode_Goaway
           (Buffer         => L.Buf,
            Last           => Goaway_Last,
            Last_Stream_Id => Stream_Id,
            Error_Code     => 0,  --  NO_ERROR
            Debug_Data     => Empty);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Goaway_Last));
      exception
         when others => null;  --  best effort; client may have already gone
      end;

      Transport.Close (Chan);
   end Accept_And_Serve;

   ---------------------------------------------------------------------
   --  Accept_And_Serve_Server_Stream — same request phase as
   --  Accept_And_Serve, but emits N DATA frames pulled from the
   --  caller's Next_Reply function before sending trailing HEADERS.
   --
   --  Request side is identical (modulo the handler interface) so the
   --  body is largely a copy of Accept_And_Serve up through Phase 2.
   --  Phase 3's response phase is the streaming difference.
   ---------------------------------------------------------------------

   procedure Accept_And_Serve_Server_Stream (L : in out Listener)
   is
      Chan      : Transport.Channel;
      Stream_Id : Bit_Len := 0;
      Got_Peer_Settings : Boolean := False;
      Got_Settings_Ack  : Boolean := False;
   begin
      if L.Buf = null
        or else L.Inbound_Buf = null
        or else L.Outgoing_Buf = null
      then
         raise Server_Error
           with "Http2_Core.Server.Attach_Buffers must be called first";
      end if;

      Transport.Accept_One (L.Trans, Chan);

      --  Preface (24 bytes).
      declare
         Pref_Bytes : RFLX.RFLX_Types.Bytes
           (RFLX.RFLX_Types.Index'First ..
              RFLX.RFLX_Types.Index'First +
              RFLX.RFLX_Types.Index (Wire.Preface'Length) - 1);
         Pref_OK : Boolean;
      begin
         Transport.Receive_Full (Chan, Pref_Bytes, Pref_OK);
         if not Pref_OK then
            Transport.Close (Chan);
            raise Server_Error with "EOF before preface";
         end if;
         for I in Pref_Bytes'Range loop
            if Pref_Bytes (I) /=
              U8 (Character'Pos
                    (Wire.Preface
                       (Wire.Preface'First +
                          Integer (I - Pref_Bytes'First))))
            then
               Transport.Close (Chan);
               raise Server_Error with "bad preface";
            end if;
         end loop;
      end;

      --  Send our SETTINGS.
      declare
         Last : RFLX.RFLX_Types.Index;
         Params : constant Wire.Settings_List (1 .. 3) :=
           ((Identifier => RFLX.Http2_Parameters.HEADER_TABLE_SIZE,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.ENABLE_PUSH,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.MAX_CONCURRENT_STREAMS,
             Value      => 1));
      begin
         Wire.Encode_Settings (L.Buf, Last, Params);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
      end;

      pragma Unreferenced (Got_Peer_Settings);
      pragma Unreferenced (Got_Settings_Ack);

      --  FSM-driven request phase (identical to unary).
      declare
         package FSM renames RFLX.Stream.Open.FSM;
         use type FSM.State;
         Ctx : FSM.Context;

         Request_Headers : Hpack.Header_Block (1 .. 16);
         Request_Headers_Last : Natural;
         Request_Body  : RFLX.RFLX_Types.Bytes (1 .. 16384) :=
           (others => 0);
         Request_Body_Cursor : Integer :=
           Integer (Request_Body'First) - 1;
         Got_End_Of_Request : Boolean := False;
      begin
         FSM.Initialize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
         Request_Headers_Last := Request_Headers'First - 1;

         --  Pre-feed first frame.
         declare
            Frame_Last : RFLX.RFLX_Types.Index;
            Frame_Hdr  : Wire.Frame_Header;
            Read_OK    : Boolean;
         begin
            Read_Frame (Chan, L.Buf, Frame_Hdr, Frame_Last, Read_OK);
            if not Read_OK then
               FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
               Transport.Close (Chan);
               raise Server_Error with "EOF before first frame";
            end if;
            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               FSM.Write
                 (Ctx, FSM.C_Network,
                  L.Buf.all (L.Buf'First .. Frame_Last));
            end if;
         end;

         Drive_Request :
         loop
            FSM.Run (Ctx);
            exit Drive_Request when not FSM.Active (Ctx);
            exit Drive_Request when
              FSM.Next_State (Ctx) = FSM.S_Loading_Response;

            if FSM.Has_Data (Ctx, FSM.C_Network) then
               declare
                  N : constant RFLX.RFLX_Types.Length :=
                    FSM.Read_Buffer_Size (Ctx, FSM.C_Network);
                  View : RFLX.RFLX_Types.Bytes
                    (L.Buf'First ..
                       L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
               begin
                  FSM.Read (Ctx, FSM.C_Network, View);
                  Transport.Send (Chan, View);
               end;
            end if;

            if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
               declare
                  N : constant RFLX.RFLX_Types.Length :=
                    FSM.Read_Buffer_Size (Ctx, FSM.C_App_Pending);
                  View : RFLX.RFLX_Types.Bytes
                    (L.Buf'First ..
                       L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
                  Hdr        : Wire.Frame_Header;
                  Hdr_Valid  : Boolean;
               begin
                  FSM.Read (Ctx, FSM.C_App_Pending, View);
                  if View'Length < 9 then
                     FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     Transport.Close (Chan);
                     raise Server_Error with "short pending frame";
                  end if;
                  Wire.Decode_Frame_Header
                    (Buffer => View (View'First .. View'First + 8),
                     Header => Hdr,
                     Valid  => Hdr_Valid);
                  if not Hdr_Valid then
                     FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     Transport.Close (Chan);
                     raise Server_Error with "bad pending frame header";
                  end if;
                  case Hdr.Frame_Type_Value is
                     when RFLX.Http2_Parameters.HEADERS =>
                        Stream_Id := Hdr.Stream_Identifier;
                        if (Hdr.Flags and Wire.Flag_END_HEADERS) = 0 then
                           FSM.Finalize
                             (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                           Transport.Close (Chan);
                           raise Server_Error
                             with "CONTINUATION not supported";
                        end if;
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
                                (1 ..
                                   Natural (Frag_Last - Frag_First) + 1);
                           begin
                              for I in Frag'Range loop
                                 Frag (I) :=
                                   Hpack.Octet
                                     (View
                                        (Frag_First
                                         + RFLX.RFLX_Types.Index (I)
                                         - 1));
                              end loop;
                              Hpack.Decode
                                (Input        => Frag,
                                 Headers      => Request_Headers,
                                 Headers_Last => Request_Headers_Last,
                                 Output_OK    => Decode_OK);
                              if not Decode_OK then
                                 FSM.Finalize
                                   (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                                 Transport.Close (Chan);
                                 raise Server_Error
                                   with "HPACK decode failed";
                              end if;
                           end;
                        end;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                           Got_End_Of_Request := True;
                        end if;
                     when RFLX.Http2_Parameters.DATA =>
                        if Hdr.Length > 0 then
                           declare
                              Need : constant Integer :=
                                Request_Body_Cursor + 1
                                + Integer (Hdr.Length);
                           begin
                              if Need > Integer (Request_Body'Last) then
                                 FSM.Finalize
                                   (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                                 Transport.Close (Chan);
                                 raise Server_Error
                                   with "request body overflow";
                              end if;
                              for I in 1 .. Integer (Hdr.Length) loop
                                 Request_Body_Cursor :=
                                   Request_Body_Cursor + 1;
                                 Request_Body
                                   (RFLX.RFLX_Types.Index
                                      (Request_Body_Cursor)) :=
                                   View
                                     (View'First + 8
                                      + RFLX.RFLX_Types.Index (I));
                              end loop;
                           end;
                        end if;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                           Got_End_Of_Request := True;
                        end if;
                     when RFLX.Http2_Parameters.RST_STREAM =>
                        FSM.Finalize
                          (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                        Transport.Close (Chan);
                        raise Server_Error with "client RST_STREAM";
                     when RFLX.Http2_Parameters.PING =>
                        if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                           declare
                              Ack_Last : RFLX.RFLX_Types.Index;
                              Echo : constant RFLX.RFLX_Types.Bytes :=
                                View
                                  (View'First + 9 ..
                                     View'First + 16);
                           begin
                              Wire.Encode_Ping
                                (Buffer => L.Buf, Last => Ack_Last,
                                 Opaque_Data => Echo, Ack => True);
                              Transport.Send
                                (Chan,
                                 L.Buf.all (L.Buf'First .. Ack_Last));
                           end;
                        end if;
                     when RFLX.Http2_Parameters.SETTINGS =>
                        if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                           declare
                              Ack_Last : RFLX.RFLX_Types.Index;
                           begin
                              Wire.Encode_Settings_Ack
                                (L.Buf, Ack_Last);
                              Transport.Send
                                (Chan,
                                 L.Buf.all (L.Buf'First .. Ack_Last));
                           end;
                        end if;
                     when RFLX.Http2_Parameters.WINDOW_UPDATE =>
                        null;
                     when RFLX.Http2_Parameters.GOAWAY =>
                        FSM.Finalize
                          (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                        Transport.Close (Chan);
                        raise Server_Error with "client GOAWAY";
                     when others =>
                        null;
                  end case;
               end;
            end if;

            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               declare
                  Frame_Last : RFLX.RFLX_Types.Index;
                  Frame_Hdr  : Wire.Frame_Header;
                  Read_OK    : Boolean;
               begin
                  Read_Frame (Chan, L.Buf, Frame_Hdr, Frame_Last, Read_OK);
                  if not Read_OK then
                     FSM.Finalize
                       (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     Transport.Close (Chan);
                     raise Server_Error with "EOF in request";
                  end if;
                  if FSM.Needs_Data (Ctx, FSM.C_Network) then
                     FSM.Write
                       (Ctx, FSM.C_Network,
                        L.Buf.all (L.Buf'First .. Frame_Last));
                  end if;
               end;
            end if;
         end loop Drive_Request;

         pragma Unreferenced (Got_End_Of_Request);

         --  STREAMING RESPONSE PHASE.
         declare
            Resp_Hdrs : Hpack.Header_Block (1 .. 16);
            Resp_Hdrs_Last : Natural;
            Trailers : Hpack.Header_Block (1 .. 8);
            Trailers_Last : Natural;
            Empty_Slice : constant RFLX.RFLX_Types.Bytes (1 .. 0) :=
              (others => 0);
            Have_Body   : constant Boolean :=
              Request_Body_Cursor >= Integer (Request_Body'First);
         begin
            Setup_Response
              (Request_Headers       => Request_Headers,
               Request_Headers_Last  => Request_Headers_Last,
               Request_Body          =>
                 (if Have_Body then
                    Request_Body
                      (Request_Body'First ..
                         RFLX.RFLX_Types.Index (Request_Body_Cursor))
                  else Empty_Slice),
               Request_Body_Last     => Request_Body_Cursor,
               Response_Headers      => Resp_Hdrs,
               Response_Headers_Last => Resp_Hdrs_Last,
               Trailers              => Trailers,
               Trailers_Last         => Trailers_Last);

            --  Send response HEADERS (no END_STREAM).
            declare
               Frag_Out  : Hpack.Octet_Array
                 (1 .. Hpack.Max_Header_Length * Hpack.Max_Headers);
               Frag_Last : Natural;
               Frag_OK   : Boolean;
               Frame_Last : RFLX.RFLX_Types.Index;
            begin
               Hpack.Encode
                 (Headers     =>
                    Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
                  Output      => Frag_Out,
                  Output_Last => Frag_Last,
                  Output_OK   => Frag_OK);
               if not Frag_OK then
                  FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                  Transport.Close (Chan);
                  raise Server_Error with "response HPACK encode failed";
               end if;
               declare
                  Frag_Bytes : RFLX.RFLX_Types.Bytes
                    (1 .. RFLX.RFLX_Types.Index (Frag_Last));
               begin
                  for I in 1 .. Frag_Last loop
                     Frag_Bytes (RFLX.RFLX_Types.Index (I)) :=
                       U8 (Frag_Out (I));
                  end loop;
                  Wire.Encode_Headers
                    (Buffer => L.Buf, Last => Frame_Last,
                     Stream_Id => Stream_Id, Fragment => Frag_Bytes,
                     End_Stream => False);
               end;
               Transport.Send
                 (Chan, L.Buf.all (L.Buf'First .. Frame_Last));
            end;

            --  Streaming loop: pull each reply via Next_Reply, send
            --  as one DATA frame. Caller is responsible for the
            --  5-byte gRPC framing prefix on each message.
            Stream_Loop :
            loop
               declare
                  Msg_Buf  : RFLX.RFLX_Types.Bytes (1 .. 16384) :=
                    (others => 0);
                  Msg_Last : RFLX.RFLX_Types.Index;
                  Has_Msg  : Boolean;
                  Data_Last : RFLX.RFLX_Types.Index;
               begin
                  Has_Msg := Next_Reply (Msg_Buf, Msg_Last);
                  exit Stream_Loop when not Has_Msg;
                  Wire.Encode_Data
                    (Buffer => L.Buf, Last => Data_Last,
                     Stream_Id => Stream_Id,
                     Payload =>
                       Msg_Buf (Msg_Buf'First .. Msg_Last),
                     End_Stream => False);
                  Transport.Send
                    (Chan, L.Buf.all (L.Buf'First .. Data_Last));
               end;
            end loop Stream_Loop;

            --  Send trailing HEADERS with END_STREAM.
            declare
               Frag_Out  : Hpack.Octet_Array
                 (1 .. Hpack.Max_Header_Length * Hpack.Max_Headers);
               Frag_Last : Natural;
               Frag_OK   : Boolean;
               Frame_Last : RFLX.RFLX_Types.Index;
            begin
               Hpack.Encode
                 (Headers     =>
                    Trailers (Trailers'First .. Trailers_Last),
                  Output      => Frag_Out,
                  Output_Last => Frag_Last,
                  Output_OK   => Frag_OK);
               if not Frag_OK then
                  FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                  Transport.Close (Chan);
                  raise Server_Error
                    with "trailers HPACK encode failed";
               end if;
               declare
                  Frag_Bytes : RFLX.RFLX_Types.Bytes
                    (1 .. RFLX.RFLX_Types.Index (Frag_Last));
               begin
                  for I in 1 .. Frag_Last loop
                     Frag_Bytes (RFLX.RFLX_Types.Index (I)) :=
                       U8 (Frag_Out (I));
                  end loop;
                  Wire.Encode_Headers
                    (Buffer => L.Buf, Last => Frame_Last,
                     Stream_Id => Stream_Id, Fragment => Frag_Bytes,
                     End_Stream => True);
               end;
               Transport.Send
                 (Chan, L.Buf.all (L.Buf'First .. Frame_Last));
            end;
         end;

         FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
      end;

      --  Post-response PING-ACK + GOAWAY (same as unary).
      for K in 1 .. 5 loop
         declare
            Hdr2 : Wire.Frame_Header;
            Last2 : RFLX.RFLX_Types.Index;
            OK2 : Boolean;
         begin
            Read_Frame (Chan, L.Buf, Hdr2, Last2, OK2);
            exit when not OK2;
            if Hdr2.Frame_Type_Value = RFLX.Http2_Parameters.PING
              and (Hdr2.Flags and Wire.Flag_ACK) = 0
              and Hdr2.Length = 8
            then
               declare
                  Ack_Last : RFLX.RFLX_Types.Index;
                  Echo : constant RFLX.RFLX_Types.Bytes :=
                    L.Buf.all (L.Buf'First + 9 .. L.Buf'First + 16);
               begin
                  Wire.Encode_Ping
                    (Buffer => L.Buf, Last => Ack_Last,
                     Opaque_Data => Echo, Ack => True);
                  Transport.Send
                    (Chan, L.Buf.all (L.Buf'First .. Ack_Last));
               end;
               exit;
            end if;
         exception
            when others => exit;
         end;
      end loop;

      declare
         Goaway_Last : RFLX.RFLX_Types.Index;
         Empty : constant RFLX.RFLX_Types.Bytes (1 .. 0) :=
           (others => 0);
      begin
         Wire.Encode_Goaway
           (Buffer => L.Buf, Last => Goaway_Last,
            Last_Stream_Id => Stream_Id,
            Error_Code => 0,
            Debug_Data => Empty);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Goaway_Last));
      exception
         when others => null;
      end;

      Transport.Close (Chan);
   end Accept_And_Serve_Server_Stream;

end Http2_Core.Server;
