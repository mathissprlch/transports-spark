with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.Http2_Parameters;
with RFLX.Stream.Half_Open.FSM;

with Http2_Core.Wire;

package body Http2_Core.Connection is

   use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;
   use type RFLX.RFLX_Builtin_Types.Bit_Length;
   use type RFLX.RFLX_Builtin_Types.Byte;
   use type RFLX.Http2_Parameters.HTTP_2_Frame_Type_Enum;
   use type RFLX.RFLX_Types.Length;

   subtype U8       is RFLX.RFLX_Types.Byte;
   subtype Bit_Len  is RFLX.RFLX_Builtin_Types.Bit_Length;

   --  Read the next full HTTP/2 frame off the wire into C.Buf
   --  starting at C.Buf'First. Sets Last to the index of the last
   --  byte of the frame and Header to the parsed fixed-header.
   procedure Read_Frame
     (C       : in out Connection;
      Header  :    out Wire.Frame_Header;
      Last    :    out RFLX.RFLX_Types.Index;
      Success :    out Boolean);

   procedure Read_Frame
     (C       : in out Connection;
      Header  :    out Wire.Frame_Header;
      Last    :    out RFLX.RFLX_Types.Index;
      Success :    out Boolean)
   is
      Hdr_Slice : RFLX.RFLX_Types.Bytes (C.Buf'First .. C.Buf'First + 8);
      Hdr_OK    : Boolean;
   begin
      Header  := (others => <>);
      Last    := C.Buf'First;
      Success := False;

      Transport.Receive_Full (C.Trans, Hdr_Slice, Hdr_OK);
      if not Hdr_OK then
         return;
      end if;
      C.Buf.all (C.Buf'First .. C.Buf'First + 8) := Hdr_Slice;

      Wire.Decode_Frame_Header
        (Buffer => C.Buf.all (C.Buf'First .. C.Buf'First + 8),
         Header => Header,
         Valid  => Hdr_OK);
      if not Hdr_OK then
         return;
      end if;

      if Header.Length = 0 then
         Last    := C.Buf'First + 8;
         Success := True;
         return;
      end if;

      if Bit_Len (C.Buf'Length) < Header.Length + 9 then
         --  Frame larger than our buffer. v0.2 bound is
         --  SETTINGS_MAX_FRAME_SIZE (16384) — we advertise that, so
         --  a peer sending more is a protocol violation.
         return;
      end if;

      declare
         Body_Slice : RFLX.RFLX_Types.Bytes
           (C.Buf'First + 9 ..
              C.Buf'First + 8 + RFLX.RFLX_Types.Index (Header.Length));
         Body_OK    : Boolean;
      begin
         Transport.Receive_Full (C.Trans, Body_Slice, Body_OK);
         if not Body_OK then
            return;
         end if;
         C.Buf.all (Body_Slice'Range) := Body_Slice;
         Last    := Body_Slice'Last;
         Success := True;
      end;
   end Read_Frame;

   ---------------------------------------------------------------------
   --  Open
   ---------------------------------------------------------------------

   procedure Open
     (C    : in out Connection;
      Host : String;
      Port : Natural := 80)
   is
      Last      : RFLX.RFLX_Types.Index;
      Header    : Wire.Frame_Header;
      Read_OK   : Boolean;
      Got_Peer_Settings : Boolean := False;
      Got_Settings_Ack  : Boolean := False;
   begin
      --  Buffers are caller-supplied via Attach_Buffers. Library never
      --  calls `new`. All three slots must be attached before Open.
      if C.Buf = null
        or else C.Inbound_Buf = null
        or else C.Outgoing_Buf = null
      then
         raise Connect_Error
           with "Http2_Core.Connection.Attach_Buffers must be called before Open";
      end if;

      Transport.Connect (C.Trans, Host, Port);

      --  §3.4 connection preface — fixed 24 bytes.
      declare
         Pref_Bytes : RFLX.RFLX_Types.Bytes
           (RFLX.RFLX_Types.Index'First ..
              RFLX.RFLX_Types.Index'First +
              RFLX.RFLX_Types.Index (Wire.Preface'Length) - 1);
         J : Integer := Wire.Preface'First;
      begin
         for I in Pref_Bytes'Range loop
            Pref_Bytes (I) := U8 (Character'Pos (Wire.Preface (J)));
            J := J + 1;
         end loop;
         Transport.Send (C.Trans, Pref_Bytes);
      end;

      --  §6.5 — emit our SETTINGS. v0.2 bounded subset per SCOPE.md.
      declare
         Params : constant Wire.Settings_List (1 .. 3) :=
           ((Identifier => RFLX.Http2_Parameters.HEADER_TABLE_SIZE,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.ENABLE_PUSH,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.MAX_CONCURRENT_STREAMS,
             Value      => 1));
      begin
         Wire.Encode_Settings (C.Buf, Last, Params);
         Transport.Send (C.Trans, C.Buf.all (C.Buf'First .. Last));
      end;

      --  §6.5.3 — read until both sides' SETTINGS are exchanged + ACKed.
      while not (Got_Peer_Settings and Got_Settings_Ack) loop
         Read_Frame (C, Header, Last, Read_OK);
         if not Read_OK then
            Transport.Close (C.Trans);
            raise Connect_Error
              with "preface/SETTINGS handshake failed";
         end if;

         if Header.Frame_Type_Value = RFLX.Http2_Parameters.SETTINGS then
            if (Header.Flags and Wire.Flag_ACK) /= 0 then
               if Header.Length /= 0 then
                  Transport.Close (C.Trans);
                  raise Connect_Error
                    with "non-empty SETTINGS-ACK from peer";
               end if;
               Got_Settings_Ack := True;
            else
               Got_Peer_Settings := True;
               declare
                  Ack_Last : RFLX.RFLX_Types.Index;
               begin
                  Wire.Encode_Settings_Ack (C.Buf, Ack_Last);
                  Transport.Send
                    (C.Trans,
                     C.Buf.all (C.Buf'First .. Ack_Last));
               end;
            end if;
         else
            if Header.Frame_Type_Value /=
              RFLX.Http2_Parameters.WINDOW_UPDATE
            then
               Transport.Close (C.Trans);
               raise Connect_Error
                 with "unexpected frame during handshake";
            end if;
         end if;
      end loop;
   end Open;

   ---------------------------------------------------------------------
   --  Round_Trip — synchronous unary RPC, FSM-driven.
   --
   --  The Stream::Half_Open machine in specs/stream.rflx models the
   --  client-side single-stream lifecycle from "we sent HEADERS" to
   --  "stream closed". Driver responsibilities:
   --
   --    * Compose request HEADERS in C.Buf, hand to FSM via App_Outbox.
   --    * Drain FSM's Network channel into the TCP socket.
   --    * Send any request DATA frame directly (the v0.2 FSM does not
   --      model request-side DATA — only the response side).
   --    * Pull each inbound frame from the socket, hand to the FSM
   --      via Network. The FSM's Awaiting_Reply state has the
   --      verification-dividend dispatch table — frame types not in
   --      its legal set drive the FSM to S_Final (protocol violation).
   --    * Drain App_Pending: the FSM has already classified the frame
   --      (HEADERS/DATA/connection-mgmt/RST_STREAM); driver decodes
   --      payload and folds into the caller's response slots.
   --    * Exit when END_STREAM seen on HEADERS or DATA, or when FSM
   --      transitions out of Active (S_Final on RST_STREAM /
   --      protocol violation).
   ---------------------------------------------------------------------

   procedure Round_Trip
     (C                     : in out Connection;
      Request_Headers       : Hpack.Header_Block;
      Request_Body          : RFLX.RFLX_Types.Bytes;
      Response_Headers      : in out Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Response_Body         : in out RFLX.RFLX_Types.Bytes;
      Response_Body_Last    : out Natural)
   is
      package FSM renames RFLX.Stream.Half_Open.FSM;
      Ctx : FSM.Context;

      Stream_Id : constant Bit_Len := C.Next_Stream_Id;
      Hdrs_Last : RFLX.RFLX_Types.Index;
      End_Stream_Out : constant Boolean := Request_Body'Length = 0;

      Body_Cursor   : Integer := Integer (Response_Body'First) - 1;
      Got_Headers   : Boolean := False;
      Stream_Closed : Boolean := False;
      Headers_Sent  : Boolean := False;
   begin
      Response_Headers_Last := Response_Headers'First - 1;
      Response_Body_Last    := Integer (Response_Body'First) - 1;
      C.Next_Stream_Id      := C.Next_Stream_Id + 2;

      --  Encode request HEADERS frame into C.Buf.
      declare
         Frag_Out  : Hpack.Octet_Array
           (1 .. Hpack.Max_Header_Length * Hpack.Max_Headers);
         Frag_Last : Natural;
         Frag_OK   : Boolean;
      begin
         Hpack.Encode
           (Headers     => Request_Headers,
            Output      => Frag_Out,
            Output_Last => Frag_Last,
            Output_OK   => Frag_OK);
         if not Frag_OK then
            raise RPC_Error with "HPACK encode failed";
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
              (Buffer     => C.Buf,
               Last       => Hdrs_Last,
               Stream_Id  => Stream_Id,
               Fragment   => Frag_Bytes,
               End_Stream => End_Stream_Out);
         end;
      end;

      --  Initialize Stream::Half_Open with caller-supplied buffers.
      FSM.Initialize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);

      --  Hand HEADERS bytes to the FSM via App_Outbox. The FSM's
      --  Loading state reads them, transitions to Sending_Headers.
      if FSM.Needs_Data (Ctx, FSM.C_App_Outbox) then
         FSM.Write
           (Ctx, FSM.C_App_Outbox,
            C.Buf.all (C.Buf'First .. Hdrs_Last));
      end if;

      Drive_Loop :
      loop
         FSM.Run (Ctx);
         exit Drive_Loop when not FSM.Active (Ctx);
         exit Drive_Loop when Stream_Closed;

         --  FSM has bytes to emit on Network — drain to socket.
         if FSM.Has_Data (Ctx, FSM.C_Network) then
            declare
               N : constant RFLX.RFLX_Types.Length :=
                 FSM.Read_Buffer_Size (Ctx, FSM.C_Network);
               View : RFLX.RFLX_Types.Bytes
                 (C.Buf'First ..
                    C.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
            begin
               FSM.Read (Ctx, FSM.C_Network, View);
               Transport.Send (C.Trans, View);
            end;

            --  Just drained HEADERS bytes. If there's a request body,
            --  send DATA directly: the v0.2 FSM only models response-
            --  side traffic, so request DATA is hand-written.
            if not Headers_Sent then
               Headers_Sent := True;
               if not End_Stream_Out then
                  declare
                     Data_Last : RFLX.RFLX_Types.Index;
                  begin
                     Wire.Encode_Data
                       (Buffer     => C.Buf,
                        Last       => Data_Last,
                        Stream_Id  => Stream_Id,
                        Payload    => Request_Body,
                        End_Stream => True);
                     Transport.Send
                       (C.Trans,
                        C.Buf.all (C.Buf'First .. Data_Last));
                  end;
               end if;
            end if;
         end if;

         --  FSM has classified an inbound frame; act on it.
         if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
            declare
               N : constant RFLX.RFLX_Types.Length :=
                 FSM.Read_Buffer_Size (Ctx, FSM.C_App_Pending);
               View : RFLX.RFLX_Types.Bytes
                 (C.Buf'First ..
                    C.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
               Hdr        : Wire.Frame_Header;
               Hdr_Valid  : Boolean;
            begin
               FSM.Read (Ctx, FSM.C_App_Pending, View);

               if View'Length < 9 then
                  FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
                  Transport.Close (C.Trans);
                  raise RPC_Error with "App_Pending frame < 9 bytes";
               end if;

               Wire.Decode_Frame_Header
                 (Buffer => View (View'First .. View'First + 8),
                  Header => Hdr,
                  Valid  => Hdr_Valid);
               if not Hdr_Valid then
                  FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
                  Transport.Close (C.Trans);
                  raise RPC_Error with "App_Pending frame header decode failed";
               end if;

               case Hdr.Frame_Type_Value is
                  when RFLX.Http2_Parameters.HEADERS =>
                     if (Hdr.Flags and Wire.Flag_END_HEADERS) = 0 then
                        FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
                        Transport.Close (C.Trans);
                        raise RPC_Error
                          with "CONTINUATION not supported in v0.2";
                     end if;
                     if (Hdr.Flags and Wire.Flag_PADDED) /= 0 then
                        FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
                        Transport.Close (C.Trans);
                        raise RPC_Error
                          with "PADDED HEADERS not supported in v0.2";
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
                                     (Frag_First +
                                        RFLX.RFLX_Types.Index (I) - 1));
                           end loop;
                           Hpack.Decode
                             (Input        => Frag,
                              Headers      => Response_Headers,
                              Headers_Last => Response_Headers_Last,
                              Output_OK    => Decode_OK);
                           if not Decode_OK then
                              FSM.Finalize
                                (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
                              Transport.Close (C.Trans);
                              raise RPC_Error with "HPACK decode failed";
                           end if;
                        end;
                     end;
                     Got_Headers := True;
                     if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                        Stream_Closed := True;
                     end if;

                  when RFLX.Http2_Parameters.DATA =>
                     if Hdr.Length > 0 then
                        declare
                           Need : constant Integer :=
                             Body_Cursor + 1 + Integer (Hdr.Length);
                        begin
                           if Need > Integer (Response_Body'Last) then
                              FSM.Finalize
                                (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
                              Transport.Close (C.Trans);
                              raise RPC_Error
                                with "response body overflow";
                           end if;
                           --  Loop from 1 — Index'First = 1, see
                           --  iteration-01 fix.
                           for I in 1 .. Integer (Hdr.Length) loop
                              Body_Cursor := Body_Cursor + 1;
                              Response_Body
                                (RFLX.RFLX_Types.Index (Body_Cursor)) :=
                                View
                                  (View'First + 8
                                   + RFLX.RFLX_Types.Index (I));
                           end loop;
                        end;
                     end if;
                     if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                        Stream_Closed := True;
                     end if;

                  when RFLX.Http2_Parameters.RST_STREAM =>
                     FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
                     Transport.Close (C.Trans);
                     raise RPC_Error with "peer reset stream";

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
                             (Buffer => C.Buf, Last => Ack_Last,
                              Opaque_Data => Echo, Ack => True);
                           Transport.Send
                             (C.Trans,
                              C.Buf.all (C.Buf'First .. Ack_Last));
                        end;
                     end if;

                  when RFLX.Http2_Parameters.SETTINGS =>
                     if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                        declare
                           Ack_Last : RFLX.RFLX_Types.Index;
                        begin
                           Wire.Encode_Settings_Ack
                             (C.Buf, Ack_Last);
                           Transport.Send
                             (C.Trans,
                              C.Buf.all (C.Buf'First .. Ack_Last));
                        end;
                     end if;

                  when RFLX.Http2_Parameters.WINDOW_UPDATE =>
                     null;  --  v0.2 doesn't proactively manage flow control

                  when RFLX.Http2_Parameters.GOAWAY =>
                     FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
                     Transport.Close (C.Trans);
                     raise RPC_Error with "peer sent GOAWAY";

                  when others =>
                     --  FSM's Awaiting_Reply transition table already
                     --  rejected anything else as protocol violation;
                     --  reaching here would mean the FSM forwarded an
                     --  out-of-band frame type. Treat as bug.
                     null;
               end case;
            end;
         end if;

         --  FSM is starved on Network — pull a frame from the socket
         --  and feed it.
         if FSM.Needs_Data (Ctx, FSM.C_Network) then
            declare
               Frame_Last : RFLX.RFLX_Types.Index;
               Frame_Hdr  : Wire.Frame_Header;
               Read_OK    : Boolean;
            begin
               Read_Frame (C, Frame_Hdr, Frame_Last, Read_OK);
               if not Read_OK then
                  FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
                  Transport.Close (C.Trans);
                  raise RPC_Error with "EOF or socket error";
               end if;
               if FSM.Needs_Data (Ctx, FSM.C_Network) then
                  FSM.Write
                    (Ctx, FSM.C_Network,
                     C.Buf.all (C.Buf'First .. Frame_Last));
               end if;
            end;
         end if;
      end loop Drive_Loop;

      FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);

      if not Got_Headers then
         raise RPC_Error with "stream closed before HEADERS arrived";
      end if;
      Response_Body_Last := Body_Cursor;
   end Round_Trip;

   ---------------------------------------------------------------------
   --  Close — emit GOAWAY(NO_ERROR) and close socket.
   ---------------------------------------------------------------------

   procedure Close (C : in out Connection) is
      Last  : RFLX.RFLX_Types.Index;
      Empty : constant RFLX.RFLX_Types.Bytes (1 .. 0) := (others => 0);
   begin
      if C.Buf /= null and Transport.Is_Open (C.Trans) then
         begin
            Wire.Encode_Goaway
              (Buffer         => C.Buf,
               Last           => Last,
               Last_Stream_Id => C.Next_Stream_Id - 2,
               Error_Code     => 0,  --  NO_ERROR
               Debug_Data     => Empty);
            Transport.Send (C.Trans, C.Buf.all (C.Buf'First .. Last));
         exception
            when others => null;
         end;
      end if;
      if Transport.Is_Open (C.Trans) then
         Transport.Close (C.Trans);
      end if;
      --  Buffer ownership stays with the application; Close does
      --  NOT free. Use Detach_Buffers to recover.
   end Close;

   procedure Attach_Buffers
     (C            : in out Connection;
      Buf          : in out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : in out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : in out RFLX.RFLX_Types.Bytes_Ptr)
   is
   begin
      C.Buf          := Buf;
      C.Inbound_Buf  := Inbound_Buf;
      C.Outgoing_Buf := Outgoing_Buf;
      Buf            := null;
      Inbound_Buf    := null;
      Outgoing_Buf   := null;
   end Attach_Buffers;

   procedure Detach_Buffers
     (C            : in out Connection;
      Buf          : out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : out RFLX.RFLX_Types.Bytes_Ptr)
   is
   begin
      Buf            := C.Buf;
      Inbound_Buf    := C.Inbound_Buf;
      Outgoing_Buf   := C.Outgoing_Buf;
      C.Buf          := null;
      C.Inbound_Buf  := null;
      C.Outgoing_Buf := null;
   end Detach_Buffers;

end Http2_Core.Connection;
