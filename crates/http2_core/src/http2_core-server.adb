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
   --  Common helpers shared by all four Accept_And_Serve_* variants.
   --  Each extracts a phase that was previously inlined four times
   --  (~80–100 lines per variant).
   ---------------------------------------------------------------------

   --  §3.4 — read 24-byte connection preface, validate. Closes Chan
   --  + raises Server_Error on EOF or mismatch.
   procedure Receive_Preface
     (Chan : Transport.Channel);

   procedure Receive_Preface
     (Chan : Transport.Channel)
   is
      Pref_Bytes : RFLX.RFLX_Types.Bytes
        (RFLX.RFLX_Types.Index'First ..
           RFLX.RFLX_Types.Index'First +
           RFLX.RFLX_Types.Index (Wire.Preface'Length) - 1);
      Pref_OK : Boolean;
   begin
      Transport.Receive_Full (Chan, Pref_Bytes, Pref_OK);
      if not Pref_OK then
         raise Server_Error with "EOF before preface";
      end if;
      for I in Pref_Bytes'Range loop
         if Pref_Bytes (I) /=
           U8 (Character'Pos
                 (Wire.Preface
                    (Wire.Preface'First +
                       Integer (I - Pref_Bytes'First))))
         then
            raise Server_Error with "bad preface";
         end if;
      end loop;
   end Receive_Preface;

   --  §6.5 — emit our initial SETTINGS frame (HEADER_TABLE_SIZE=0,
   --  ENABLE_PUSH=0, MAX_CONCURRENT_STREAMS=1).
   procedure Send_Initial_Settings
     (L    : in out Listener;
      Chan : Transport.Channel);

   procedure Send_Initial_Settings
     (L    : in out Listener;
      Chan : Transport.Channel)
   is
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
   end Send_Initial_Settings;

   --  HPACK-encode `Headers` and emit as one HEADERS frame.
   procedure Encode_And_Send_Headers
     (L          : in out Listener;
      Chan       : Transport.Channel;
      Stream_Id  : Bit_Len;
      Headers    : Hpack.Header_Block;
      End_Stream : Boolean);

   procedure Encode_And_Send_Headers
     (L          : in out Listener;
      Chan       : Transport.Channel;
      Stream_Id  : Bit_Len;
      Headers    : Hpack.Header_Block;
      End_Stream : Boolean)
   is
      Frag_Out  : Hpack.Octet_Array
        (1 .. Hpack.Max_Header_Length * Hpack.Max_Headers);
      Frag_Last : Natural;
      Frag_OK   : Boolean;
      Frame_Last : RFLX.RFLX_Types.Index;
   begin
      Hpack.Encode
        (Headers     => Headers,
         Output      => Frag_Out,
         Output_Last => Frag_Last,
         Output_OK   => Frag_OK);
      if not Frag_OK then
         raise Server_Error with "HPACK encode failed";
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
            End_Stream => End_Stream);
      end;
      Transport.Send (Chan, L.Buf.all (L.Buf'First .. Frame_Last));
   end Encode_And_Send_Headers;

   --  Wrap caller's gRPC-framed payload in a DATA frame and emit.
   procedure Send_Data_Frame
     (L          : in out Listener;
      Chan       : Transport.Channel;
      Stream_Id  : Bit_Len;
      Payload    : RFLX.RFLX_Types.Bytes;
      End_Stream : Boolean);

   procedure Send_Data_Frame
     (L          : in out Listener;
      Chan       : Transport.Channel;
      Stream_Id  : Bit_Len;
      Payload    : RFLX.RFLX_Types.Bytes;
      End_Stream : Boolean)
   is
      Data_Last : RFLX.RFLX_Types.Index;
   begin
      Wire.Encode_Data
        (Buffer => L.Buf, Last => Data_Last,
         Stream_Id => Stream_Id, Payload => Payload,
         End_Stream => End_Stream);
      Transport.Send (Chan, L.Buf.all (L.Buf'First .. Data_Last));
   end Send_Data_Frame;

   --  Post-response cleanup. Reads up to 5 client frames; if a
   --  PING arrives, ACK it (so Python grpcio doesn't surface
   --  TCP-FIN as Socket_Closed). Then emit GOAWAY(NO_ERROR) and
   --  close the socket.
   procedure Drain_And_Goodbye
     (L         : in out Listener;
      Chan      : in out Transport.Channel;
      Stream_Id : Bit_Len);

   procedure Drain_And_Goodbye
     (L         : in out Listener;
      Chan      : in out Transport.Channel;
      Stream_Id : Bit_Len)
   is
   begin
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
   end Drain_And_Goodbye;

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

      Receive_Preface (Chan);
      Send_Initial_Settings (L, Chan);

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
                                (Input         => Frag,
                                 Headers       => Request_Headers,
                                 Headers_Last  => Request_Headers_Last,
                                 Output_OK     => Decode_OK,
                                 Decoder_State => L.Hpack_Decoder);
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

            Encode_And_Send_Headers
              (L, Chan, Stream_Id,
               Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
               End_Stream => False);

            if Resp_Body_Last >= Integer (Resp_Body'First) then
               Send_Data_Frame
                 (L, Chan, Stream_Id,
                  Resp_Body
                    (Resp_Body'First ..
                       RFLX.RFLX_Types.Index (Resp_Body_Last)),
                  End_Stream => False);
            end if;

            Encode_And_Send_Headers
              (L, Chan, Stream_Id,
               Trailers (Trailers'First .. Trailers_Last),
               End_Stream => True);
            end;  --  declare Have_Body / Empty_Slice
         end;

         FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
         pragma Unreferenced (Got_End_Of_Request);
      end;

      Drain_And_Goodbye (L, Chan, Stream_Id);
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

      Receive_Preface (Chan);
      Send_Initial_Settings (L, Chan);

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
                                (Input         => Frag,
                                 Headers       => Request_Headers,
                                 Headers_Last  => Request_Headers_Last,
                                 Output_OK     => Decode_OK,
                                 Decoder_State => L.Hpack_Decoder);
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

            Encode_And_Send_Headers
              (L, Chan, Stream_Id,
               Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
               End_Stream => False);

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
               begin
                  Has_Msg := Next_Reply (Msg_Buf, Msg_Last);
                  exit Stream_Loop when not Has_Msg;
                  Send_Data_Frame
                    (L, Chan, Stream_Id,
                     Msg_Buf (Msg_Buf'First .. Msg_Last),
                     End_Stream => False);
               end;
            end loop Stream_Loop;

            Encode_And_Send_Headers
              (L, Chan, Stream_Id,
               Trailers (Trailers'First .. Trailers_Last),
               End_Stream => True);
         end;

         FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
      end;

      Drain_And_Goodbye (L, Chan, Stream_Id);
   end Accept_And_Serve_Server_Stream;

   ---------------------------------------------------------------------
   --  Strip the 5-byte gRPC framing prefix from a DATA-frame
   --  payload. Empty-or-too-short inputs return an empty slice.
   ---------------------------------------------------------------------

   function Strip_Grpc_Frame
     (View : RFLX.RFLX_Types.Bytes) return RFLX.RFLX_Types.Bytes;

   function Strip_Grpc_Frame
     (View : RFLX.RFLX_Types.Bytes) return RFLX.RFLX_Types.Bytes is
   begin
      if View'Length < 5 then
         return View (View'First .. View'First - 1);
      end if;
      declare
         Msg_Len_64 : constant Long_Long_Integer :=
           Long_Long_Integer (View (View'First + 1)) * 16777216
           + Long_Long_Integer (View (View'First + 2)) * 65536
           + Long_Long_Integer (View (View'First + 3)) * 256
           + Long_Long_Integer (View (View'First + 4));
      begin
         if Msg_Len_64 <= 0
           or else Msg_Len_64 > Long_Long_Integer (View'Length) - 5
         then
            return View (View'First .. View'First - 1);
         end if;
         declare
            Msg_Len : constant Natural := Natural (Msg_Len_64);
         begin
            return View
                     (View'First + 5 ..
                        View'First + 4
                        + RFLX.RFLX_Types.Index (Msg_Len));
         end;
      end;
   end Strip_Grpc_Frame;

   ---------------------------------------------------------------------
   --  Accept_And_Serve_Client_Stream — N requests → 1 response.
   ---------------------------------------------------------------------

   procedure Accept_And_Serve_Client_Stream (L : in out Listener)
   is
      Chan      : Transport.Channel;
      Stream_Id : Bit_Len := 0;
   begin
      if L.Buf = null
        or else L.Inbound_Buf = null
        or else L.Outgoing_Buf = null
      then
         raise Server_Error
           with "Http2_Core.Server.Attach_Buffers must be called first";
      end if;

      Transport.Accept_One (L.Trans, Chan);

      Receive_Preface (Chan);
      Send_Initial_Settings (L, Chan);

      --  FSM-driven request phase, but each DATA frame's gRPC message
      --  is delivered to On_Request_Message immediately (no body
      --  accumulation).
      declare
         package FSM renames RFLX.Stream.Open.FSM;
         use type FSM.State;
         Ctx : FSM.Context;

         Request_Headers : Hpack.Header_Block (1 .. 16);
         Request_Headers_Last : Natural;
         Got_End_Of_Request : Boolean := False;
      begin
         FSM.Initialize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
         Request_Headers_Last := Request_Headers'First - 1;

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

            if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
               declare
                  N : constant RFLX.RFLX_Types.Length :=
                    FSM.Read_Buffer_Size (Ctx, FSM.C_App_Pending);
                  View : RFLX.RFLX_Types.Bytes
                    (L.Buf'First ..
                       L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
                  Hdr : Wire.Frame_Header;
                  Hdr_Valid : Boolean;
               begin
                  FSM.Read (Ctx, FSM.C_App_Pending, View);
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
                           Frag_Last : constant RFLX.RFLX_Types.Index :=
                             View'Last;
                           Decode_OK : Boolean;
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
                                (Input         => Frag,
                                 Headers       => Request_Headers,
                                 Headers_Last  => Request_Headers_Last,
                                 Output_OK     => Decode_OK,
                                 Decoder_State => L.Hpack_Decoder);
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
                        --  Differs from unary: each DATA frame's
                        --  gRPC message is surfaced immediately
                        --  rather than accumulated.
                        if Hdr.Length > 0 then
                           declare
                              Payload : constant RFLX.RFLX_Types.Bytes :=
                                View
                                  (View'First + 9
                                   .. View'First + 8
                                      + RFLX.RFLX_Types.Index (Hdr.Length));
                              Msg : constant RFLX.RFLX_Types.Bytes :=
                                Strip_Grpc_Frame (Payload);
                           begin
                              if Msg'Length > 0 then
                                 On_Request_Message (Msg);
                              end if;
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
                                View (View'First + 9 ..
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

         --  RESPONSE PHASE — single response (like unary).
         declare
            Resp_Hdrs : Hpack.Header_Block (1 .. 16);
            Resp_Hdrs_Last : Natural;
            Resp_Body : RFLX.RFLX_Types.Bytes (1 .. 16384) :=
              (others => 0);
            Resp_Body_Last : Natural;
            Trailers : Hpack.Header_Block (1 .. 8);
            Trailers_Last : Natural;
         begin
            Build_Response
              (Request_Headers       => Request_Headers,
               Request_Headers_Last  => Request_Headers_Last,
               Response_Headers      => Resp_Hdrs,
               Response_Headers_Last => Resp_Hdrs_Last,
               Response_Body         => Resp_Body,
               Response_Body_Last    => Resp_Body_Last,
               Trailers              => Trailers,
               Trailers_Last         => Trailers_Last);

            Encode_And_Send_Headers
              (L, Chan, Stream_Id,
               Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
               End_Stream => False);

            if Resp_Body_Last >= Integer (Resp_Body'First) then
               Send_Data_Frame
                 (L, Chan, Stream_Id,
                  Resp_Body
                    (Resp_Body'First ..
                       RFLX.RFLX_Types.Index (Resp_Body_Last)),
                  End_Stream => False);
            end if;

            Encode_And_Send_Headers
              (L, Chan, Stream_Id,
               Trailers (Trailers'First .. Trailers_Last),
               End_Stream => True);
         end;

         FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
      end;

      Drain_And_Goodbye (L, Chan, Stream_Id);
   end Accept_And_Serve_Client_Stream;

   ---------------------------------------------------------------------
   --  Accept_And_Serve_Bidi_Stream — full duplex.
   --
   --  After receiving client HEADERS, server emits its response
   --  HEADERS immediately (so the client can start expecting
   --  replies), then enters an interleave loop. Each iteration:
   --    1. Drain any FSM-pending inbound (DATA → On_Request_Message).
   --    2. If client hasn't END_STREAM'd, try a non-blocking-ish read
   --       on Network and feed FSM.
   --    3. If we still have replies (Next_Reply returns True),
   --       emit one DATA frame.
   --  Loop ends when both Next_Reply returned False AND client
   --  END_STREAM'd. Trailers are sent after.
   ---------------------------------------------------------------------

   procedure Accept_And_Serve_Bidi_Stream (L : in out Listener)
   is
      Chan      : Transport.Channel;
      Stream_Id : Bit_Len := 0;
   begin
      if L.Buf = null
        or else L.Inbound_Buf = null
        or else L.Outgoing_Buf = null
      then
         raise Server_Error
           with "Http2_Core.Server.Attach_Buffers must be called first";
      end if;

      Transport.Accept_One (L.Trans, Chan);

      Receive_Preface (Chan);
      Send_Initial_Settings (L, Chan);

      --  Drive request side until HEADERS arrives + emit response
      --  HEADERS so client can start receiving replies. Then
      --  interleave inbound DATA / outbound DATA.
      declare
         package FSM renames RFLX.Stream.Open.FSM;
         use type FSM.State;
         Ctx : FSM.Context;

         Request_Headers : Hpack.Header_Block (1 .. 16);
         Request_Headers_Last : Natural;
         Got_Request_Headers : Boolean := False;
         Got_End_Of_Request : Boolean := False;
         No_More_Replies : Boolean := False;
         Resp_Hdrs : Hpack.Header_Block (1 .. 16);
         Resp_Hdrs_Last : Natural;
         Trailers : Hpack.Header_Block (1 .. 8);
         Trailers_Last : Natural;
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

         --  Inner helper: process one App_Pending frame.
         --  HEADERS → fold into Request_Headers (set Got_Request_Headers).
         --  DATA → strip gRPC framing, deliver to On_Request_Message.
         --  Connection-mgmt → ack inline.

         --  Drive the FSM until we've seen the HEADERS frame. Then
         --  emit our response HEADERS and enter interleave mode.
         Drive_Until_Headers :
         loop
            FSM.Run (Ctx);
            exit Drive_Until_Headers when not FSM.Active (Ctx);

            if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
               declare
                  N : constant RFLX.RFLX_Types.Length :=
                    FSM.Read_Buffer_Size (Ctx, FSM.C_App_Pending);
                  View : RFLX.RFLX_Types.Bytes
                    (L.Buf'First ..
                       L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
                  Hdr : Wire.Frame_Header;
                  Hdr_Valid : Boolean;
               begin
                  FSM.Read (Ctx, FSM.C_App_Pending, View);
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
                        declare
                           Frag_First : RFLX.RFLX_Types.Index :=
                             View'First + 9;
                           Frag_Last : constant RFLX.RFLX_Types.Index :=
                             View'Last;
                           Decode_OK : Boolean;
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
                                (Input         => Frag,
                                 Headers       => Request_Headers,
                                 Headers_Last  => Request_Headers_Last,
                                 Output_OK     => Decode_OK,
                                 Decoder_State => L.Hpack_Decoder);
                              if not Decode_OK then
                                 FSM.Finalize
                                   (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                                 Transport.Close (Chan);
                                 raise Server_Error
                                   with "HPACK decode failed";
                              end if;
                           end;
                        end;
                        Got_Request_Headers := True;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                           Got_End_Of_Request := True;
                        end if;
                        exit Drive_Until_Headers;
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
                  Read_Frame
                    (Chan, L.Buf, Frame_Hdr, Frame_Last, Read_OK);
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
         end loop Drive_Until_Headers;

         if not Got_Request_Headers then
            FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
            Transport.Close (Chan);
            raise Server_Error with "no HEADERS";
         end if;

         --  Caller sets up response headers + trailers up front.
         Setup_Response
           (Request_Headers       => Request_Headers,
            Request_Headers_Last  => Request_Headers_Last,
            Response_Headers      => Resp_Hdrs,
            Response_Headers_Last => Resp_Hdrs_Last,
            Trailers              => Trailers,
            Trailers_Last         => Trailers_Last);

         Encode_And_Send_Headers
           (L, Chan, Stream_Id,
            Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
            End_Stream => False);

         --  Pure-interleave bidi loop. Each iteration:
         --    1. If a client frame is queued (Has_Pending poll), read
         --       it, feed FSM. We don't try to drain socket bytes in
         --       this step — one frame per iteration keeps inbound
         --       and outbound balanced.
         --    2. Drive FSM. Drain *all* queued App_Pending frames:
         --       multiple frames may have been demuxed from a single
         --       Network write, and re-checking once isn't enough.
         --       For each DATA frame, deliver payload to
         --       On_Request_Message; track END_STREAM flag.
         --    3. Pull one reply from Next_Reply; if available, send
         --       as a DATA frame.
         --    4. If nothing happened this iteration, sleep 1 ms so
         --       we don't busy-spin while waiting on the client.
         --  Loop ends when the client has END_STREAM'd AND
         --  Next_Reply returned False (no more replies queued).
         pragma Unreferenced (No_More_Replies);
         Bidi_Loop :
         loop
            declare
               Made_Progress : Boolean := False;
               Reply_Pending : Boolean := False;
            begin
               --  (1) Inbound: only read if the channel has bytes
               --  ready, else we'd block while the app has replies
               --  to send.
               if not Got_End_Of_Request
                 and then Transport.Has_Pending (Chan)
               then
                  declare
                     Frame_Last : RFLX.RFLX_Types.Index;
                     Frame_Hdr  : Wire.Frame_Header;
                     Read_OK    : Boolean;
                  begin
                     Read_Frame
                       (Chan, L.Buf, Frame_Hdr, Frame_Last, Read_OK);
                     if not Read_OK then
                        Got_End_Of_Request := True;
                     else
                        Made_Progress := True;
                        if FSM.Needs_Data (Ctx, FSM.C_Network) then
                           FSM.Write
                             (Ctx, FSM.C_Network,
                              L.Buf.all (L.Buf'First .. Frame_Last));
                        end if;
                     end if;
                  end;
               end if;

               --  (2) Drive FSM and drain every queued App_Pending
               --  frame. The single-Read_Frame above can deliver a
               --  buffered burst that produces N App_Pending events
               --  in a row.
               FSM.Run (Ctx);
               Drain_App :
               loop
                  exit Drain_App when
                    not FSM.Has_Data (Ctx, FSM.C_App_Pending);
                  declare
                     N : constant RFLX.RFLX_Types.Length :=
                       FSM.Read_Buffer_Size (Ctx, FSM.C_App_Pending);
                     View : RFLX.RFLX_Types.Bytes
                       (L.Buf'First ..
                          L.Buf'First +
                            RFLX.RFLX_Types.Index (N) - 1);
                     Hdr : Wire.Frame_Header;
                     Hdr_Valid : Boolean;
                  begin
                     FSM.Read (Ctx, FSM.C_App_Pending, View);
                     Wire.Decode_Frame_Header
                       (Buffer => View (View'First .. View'First + 8),
                        Header => Hdr,
                        Valid  => Hdr_Valid);
                     if Hdr_Valid
                       and then Hdr.Frame_Type_Value =
                                  RFLX.Http2_Parameters.DATA
                     then
                        if Hdr.Length > 0 then
                           declare
                              Payload : constant
                                RFLX.RFLX_Types.Bytes :=
                                  View
                                    (View'First + 9
                                     .. View'First + 8
                                        + RFLX.RFLX_Types.Index
                                            (Hdr.Length));
                              Msg : constant RFLX.RFLX_Types.Bytes :=
                                Strip_Grpc_Frame (Payload);
                           begin
                              if Msg'Length > 0 then
                                 On_Request_Message (Msg);
                                 Made_Progress := True;
                              end if;
                           end;
                        end if;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0
                        then
                           Got_End_Of_Request := True;
                        end if;
                     end if;
                  end;
                  --  After delivering a request message, give the
                  --  application a chance to enqueue its reply for
                  --  the next outbound step. Re-Run so further
                  --  buffered network bytes can produce more
                  --  App_Pending entries.
                  FSM.Run (Ctx);
               end loop Drain_App;

               --  (3) Outbound: pull one reply per iteration. We
               --  don't drain to exhaustion here — that would let
               --  a chatty server starve inbound polling.
               declare
                  Msg_Buf  : RFLX.RFLX_Types.Bytes (1 .. 16384) :=
                    (others => 0);
                  Msg_Last : RFLX.RFLX_Types.Index;
                  Has_Msg  : Boolean;
               begin
                  Has_Msg := Next_Reply (Msg_Buf, Msg_Last);
                  if Has_Msg then
                     Send_Data_Frame
                       (L, Chan, Stream_Id,
                        Msg_Buf (Msg_Buf'First .. Msg_Last),
                        End_Stream => False);
                     Made_Progress := True;
                     Reply_Pending := True;
                  end if;
               end;

               exit Bidi_Loop when
                 Got_End_Of_Request and not Reply_Pending;

               if not Made_Progress then
                  delay 0.001;
               end if;
            end;
         end loop Bidi_Loop;

         Encode_And_Send_Headers
           (L, Chan, Stream_Id,
            Trailers (Trailers'First .. Trailers_Last),
            End_Stream => True);

         FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
      end;

      Drain_And_Goodbye (L, Chan, Stream_Id);
   end Accept_And_Serve_Bidi_Stream;

end Http2_Core.Server;
