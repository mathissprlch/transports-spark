with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.Http2_Parameters;
with RFLX.Stream.Half_Open.FSM;
with RFLX.Stream.Client_Stream.FSM;
with RFLX.Stream.Bidi_Stream.FSM;

with Http2_Core.Wire;

package body Http2_Core.Connection is

   use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;
   use type RFLX.RFLX_Builtin_Types.Bit_Length;
   use type RFLX.RFLX_Builtin_Types.Byte;
   use type RFLX.Http2_Parameters.HTTP_2_Frame_Type_Enum;
   use type RFLX.RFLX_Types.Length;

   subtype U8       is RFLX.RFLX_Types.Byte;
   subtype Bit_Len  is RFLX.RFLX_Builtin_Types.Bit_Length;

   --  RFC 9113 §6.9: count an inbound DATA frame's payload against
   --  the connection-level window and emit a WINDOW_UPDATE on
   --  stream 0 once we owe ≥ 32 KB. Without this, persistent
   --  connections stall when 64 KB of cumulative server→client
   --  DATA has arrived. Round_Trip + the three streaming variants
   --  all need this; the body lives in one place.
   Refill_At : constant Bit_Len := 2 * 1024 * 1024;
   --  Half the 4 MB initial window we advertise. Fires a WU when
   --  we've consumed 2 MB of inbound DATA. Responses up to 4 MB
   --  work; beyond that, multiple WU cycles keep the window open.
   --  Note: outbound flow control (respecting the *server's* window
   --  for our request DATA) is NOT implemented — request bodies are
   --  limited to the server's initial window (~63 KB default).

   procedure Account_Inbound_Data
     (C : in out Connection; Length : Bit_Len;
      Stream_Id : Bit_Len := 0);

   procedure Account_Inbound_Data
     (C : in out Connection; Length : Bit_Len;
      Stream_Id : Bit_Len := 0) is
   begin
      C.Conn_Bytes_Owed := C.Conn_Bytes_Owed + Length;
      if C.Conn_Bytes_Owed >= Refill_At then
         declare
            Wu_Ptr : RFLX.RFLX_Types.Bytes_Ptr :=
              new RFLX.RFLX_Types.Bytes'(1 .. 26 => 0);
            Wu_Last : RFLX.RFLX_Types.Index;
            Owed : constant Bit_Len := C.Conn_Bytes_Owed;
         begin
            Wire.Encode_Window_Update
              (Buffer    => Wu_Ptr,
               Last      => Wu_Last,
               Stream_Id => 0,
               Increment => Owed);
            Transport.Send
              (C.Trans, Wu_Ptr.all (Wu_Ptr'First .. Wu_Last));
            if Stream_Id > 0 then
               Wire.Encode_Window_Update
                 (Buffer    => Wu_Ptr,
                  Last      => Wu_Last,
                  Stream_Id => Stream_Id,
                  Increment => Owed);
               Transport.Send
                 (C.Trans, Wu_Ptr.all (Wu_Ptr'First .. Wu_Last));
            end if;
            C.Conn_Bytes_Owed := 0;
            pragma Unreferenced (Wu_Ptr);
         end;
      end if;
   end Account_Inbound_Data;

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

   procedure Configure_Tls_Client
     (C         : in out Connection;
      Trust_Der : RFLX.RFLX_Types.Bytes) is
   begin
      Transport.Set_Trust_Anchor (C.Trans, Trust_Der);
   end Configure_Tls_Client;

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
         Params : constant Wire.Settings_List (1 .. 4) :=
           ((Identifier => RFLX.Http2_Parameters.HEADER_TABLE_SIZE,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.ENABLE_PUSH,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.MAX_CONCURRENT_STREAMS,
             Value      => 1),
            (Identifier => RFLX.Http2_Parameters.INITIAL_WINDOW_SIZE,
             Value      => 4 * 1024 * 1024));
      begin
         Wire.Encode_Settings (C.Buf, Last, Params);
         Transport.Send (C.Trans, C.Buf.all (C.Buf'First .. Last));
      end;

      --  Bump the connection-level window from the default 65535 to 4MB.
      --  INITIAL_WINDOW_SIZE only affects streams (§6.9.2); the
      --  connection window is separate (§6.9.1) and can only grow via
      --  WINDOW_UPDATE on stream 0.
      declare
         Wu_Ptr : RFLX.RFLX_Types.Bytes_Ptr :=
           new RFLX.RFLX_Types.Bytes'(1 .. 26 => 0);
         Wu_Last : RFLX.RFLX_Types.Index;
      begin
         Wire.Encode_Window_Update
           (Buffer    => Wu_Ptr,
            Last      => Wu_Last,
            Stream_Id => 0,
            Increment => 4 * 1024 * 1024 - 65_535);
         Transport.Send
           (C.Trans, Wu_Ptr.all (Wu_Ptr'First .. Wu_Last));
         pragma Unreferenced (Wu_Ptr);
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
                     Max_Payload : constant := 16_384;
                     --  Length (0-based) instead of Index (1-based)
                     --  so the final subtraction to 0 doesn't fail
                     --  the range check.
                     Remaining   : RFLX.RFLX_Types.Length :=
                       RFLX.RFLX_Types.Length (Request_Body'Length);
                     Offset      : RFLX.RFLX_Types.Index :=
                       Request_Body'First;
                  begin
                     while Remaining > 0 loop
                        declare
                           Chunk : constant RFLX.RFLX_Types.Length :=
                             RFLX.RFLX_Types.Length'Min
                               (Remaining, Max_Payload);
                           Is_Last : constant Boolean :=
                             Chunk = Remaining;
                           Data_Last : RFLX.RFLX_Types.Index;
                        begin
                           Wire.Encode_Data
                             (Buffer     => C.Buf,
                              Last       => Data_Last,
                              Stream_Id  => Stream_Id,
                              Payload    =>
                                Request_Body
                                  (Offset ..
                                     Offset
                                     + RFLX.RFLX_Types.Index (Chunk)
                                     - 1),
                              End_Stream => Is_Last);
                           Transport.Send
                             (C.Trans,
                              C.Buf.all (C.Buf'First .. Data_Last));
                           Offset    := Offset
                             + RFLX.RFLX_Types.Index (Chunk);
                           Remaining := Remaining - Chunk;
                        end;
                     end loop;
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
                             (Input         => Frag,
                              Headers       => Response_Headers,
                              Headers_Last  => Response_Headers_Last,
                              Output_OK     => Decode_OK,
                              Decoder_State => C.Hpack_Decoder);
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

                        Account_Inbound_Data (C, Hdr.Length, Stream_Id);
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
   --  Common helpers shared by Round_Trip and the three streaming
   --  RPCs. Encode HEADERS into a Bytes view inside the connection
   --  scratch buffer; dispatch a connection-management frame (PING
   --  ACK / SETTINGS ACK / WINDOW_UPDATE / GOAWAY).
   ---------------------------------------------------------------------

   procedure Encode_Request_Headers
     (C          : in out Connection;
      Headers    : Hpack.Header_Block;
      Stream_Id  : Bit_Len;
      End_Stream : Boolean;
      Last       : out RFLX.RFLX_Types.Index);

   procedure Encode_Request_Headers
     (C          : in out Connection;
      Headers    : Hpack.Header_Block;
      Stream_Id  : Bit_Len;
      End_Stream : Boolean;
      Last       : out RFLX.RFLX_Types.Index)
   is
      Frag_Out  : Hpack.Octet_Array
        (1 .. Hpack.Max_Header_Length * Hpack.Max_Headers);
      Frag_Last : Natural;
      Frag_OK   : Boolean;
   begin
      Hpack.Encode (Headers, Frag_Out, Frag_Last, Frag_OK);
      if not Frag_OK then
         raise RPC_Error with "HPACK encode failed";
      end if;
      declare
         Frag_Bytes : RFLX.RFLX_Types.Bytes
           (1 .. RFLX.RFLX_Types.Index (Frag_Last));
      begin
         for I in 1 .. Frag_Last loop
            Frag_Bytes (RFLX.RFLX_Types.Index (I)) := U8 (Frag_Out (I));
         end loop;
         Wire.Encode_Headers
           (Buffer => C.Buf, Last => Last, Stream_Id => Stream_Id,
            Fragment => Frag_Bytes, End_Stream => End_Stream);
      end;
   end Encode_Request_Headers;

   --  Handle a connection-management frame (PING / SETTINGS / WINDOW
   --  / GOAWAY). Used by the streaming drivers; identical to the
   --  inline logic in Round_Trip.
   procedure Handle_Connection_Frame
     (C    : in out Connection;
      Hdr  : Wire.Frame_Header;
      View : RFLX.RFLX_Types.Bytes);

   procedure Handle_Connection_Frame
     (C    : in out Connection;
      Hdr  : Wire.Frame_Header;
      View : RFLX.RFLX_Types.Bytes)
   is
   begin
      case Hdr.Frame_Type_Value is
         when RFLX.Http2_Parameters.PING =>
            if (Hdr.Flags and Wire.Flag_ACK) = 0 then
               declare
                  Ack_Last : RFLX.RFLX_Types.Index;
                  Echo : constant RFLX.RFLX_Types.Bytes :=
                    View (View'First + 9 .. View'First + 16);
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
                  Wire.Encode_Settings_Ack (C.Buf, Ack_Last);
                  Transport.Send
                    (C.Trans, C.Buf.all (C.Buf'First .. Ack_Last));
               end;
            end if;
         when RFLX.Http2_Parameters.WINDOW_UPDATE =>
            null;
         when RFLX.Http2_Parameters.GOAWAY =>
            raise RPC_Error with "peer sent GOAWAY";
         when others =>
            null;
      end case;
   end Handle_Connection_Frame;

   --  Decode the 5-byte gRPC framing prefix at View'First. Returns
   --  the slice of bytes the caller should pass to a Message handler
   --  (raw protobuf payload, no prefix). View'Length < 5 or invalid
   --  length → returns an empty slice (caller checks 'Length).
   --  v0.2 assumes one gRPC message per HTTP/2 DATA frame.
   function Strip_Grpc_Frame
     (View : RFLX.RFLX_Types.Bytes) return RFLX.RFLX_Types.Bytes;

   function Strip_Grpc_Frame
     (View : RFLX.RFLX_Types.Bytes) return RFLX.RFLX_Types.Bytes
   is
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
            return View (View'First + 5 ..
                           View'First + 4
                           + RFLX.RFLX_Types.Index (Msg_Len));
         end;
      end;
   end Strip_Grpc_Frame;

   --  Decode an HPACK header block from a HEADERS frame, fold into
   --  Response_Headers (in out, accumulated last-write-wins on
   --  trailing-HEADERS overwrite per v0.2 semantics).
   procedure Decode_Header_Frame
     (C                     : in out Connection;
      Hdr                   : Wire.Frame_Header;
      View                  : RFLX.RFLX_Types.Bytes;
      Response_Headers      : in out Hpack.Header_Block;
      Response_Headers_Last : in out Natural);

   procedure Decode_Header_Frame
     (C                     : in out Connection;
      Hdr                   : Wire.Frame_Header;
      View                  : RFLX.RFLX_Types.Bytes;
      Response_Headers      : in out Hpack.Header_Block;
      Response_Headers_Last : in out Natural)
   is
      pragma Unreferenced (C);
      Frag_First : RFLX.RFLX_Types.Index := View'First + 9;
      Frag_Last  : constant RFLX.RFLX_Types.Index := View'Last;
      Decode_OK  : Boolean;
   begin
      if (Hdr.Flags and Wire.Flag_END_HEADERS) = 0 then
         raise RPC_Error with "CONTINUATION not supported in v0.2";
      end if;
      if (Hdr.Flags and Wire.Flag_PADDED) /= 0 then
         raise RPC_Error with "PADDED HEADERS not supported in v0.2";
      end if;
      if (Hdr.Flags and Wire.Flag_PRIORITY) /= 0 then
         Frag_First := Frag_First + 5;
      end if;
      declare
         Frag : Hpack.Octet_Array
           (1 .. Natural (Frag_Last - Frag_First) + 1);
      begin
         for I in Frag'Range loop
            Frag (I) :=
              Hpack.Octet
                (View (Frag_First + RFLX.RFLX_Types.Index (I) - 1));
         end loop;
         Hpack.Decode
           (Input         => Frag,
            Headers       => Response_Headers,
            Headers_Last  => Response_Headers_Last,
            Output_OK     => Decode_OK,
            Decoder_State => C.Hpack_Decoder);
         if not Decode_OK then
            raise RPC_Error with "HPACK decode failed";
         end if;
      end;
   end Decode_Header_Frame;

   ---------------------------------------------------------------------
   --  Server_Stream — 1 request → N responses.
   --  Reuses Stream::Half_Open FSM (Awaiting_Reply already loops
   --  for unary; for server-streaming we just keep going until
   --  the trailing HEADERS frame's END_STREAM bit fires).
   ---------------------------------------------------------------------

   procedure Server_Stream
     (C                     : in out Connection;
      Request_Headers       : Hpack.Header_Block;
      Request_Body          : RFLX.RFLX_Types.Bytes;
      Response_Headers      : in out Hpack.Header_Block;
      Response_Headers_Last : out Natural)
   is
      package FSM renames RFLX.Stream.Half_Open.FSM;
      Ctx : FSM.Context;

      Stream_Id : constant Bit_Len := C.Next_Stream_Id;
      Hdrs_Last : RFLX.RFLX_Types.Index;
      End_Stream_Out : constant Boolean := Request_Body'Length = 0;

      Got_Headers   : Boolean := False;
      Stream_Closed : Boolean := False;
      Headers_Sent  : Boolean := False;
   begin
      Response_Headers_Last := Response_Headers'First - 1;
      C.Next_Stream_Id      := C.Next_Stream_Id + 2;

      Encode_Request_Headers
        (C, Request_Headers, Stream_Id, End_Stream_Out, Hdrs_Last);

      FSM.Initialize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
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

            if not Headers_Sent then
               Headers_Sent := True;
               if not End_Stream_Out then
                  declare
                     Data_Last : RFLX.RFLX_Types.Index;
                  begin
                     Wire.Encode_Data
                       (Buffer => C.Buf, Last => Data_Last,
                        Stream_Id => Stream_Id,
                        Payload => Request_Body, End_Stream => True);
                     Transport.Send
                       (C.Trans,
                        C.Buf.all (C.Buf'First .. Data_Last));
                  end;
               end if;
            end if;
         end if;

         if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
            declare
               N    : constant RFLX.RFLX_Types.Length :=
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
                  raise RPC_Error
                    with "App_Pending frame header decode failed";
               end if;

               case Hdr.Frame_Type_Value is
                  when RFLX.Http2_Parameters.HEADERS =>
                     Decode_Header_Frame
                       (C, Hdr, View,
                        Response_Headers, Response_Headers_Last);
                     Got_Headers := True;
                     if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                        Stream_Closed := True;
                     end if;
                  when RFLX.Http2_Parameters.DATA =>
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
                              On_Message (Msg);
                           end if;
                        end;
                        Account_Inbound_Data (C, Hdr.Length, Stream_Id);
                     end if;
                     if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                        Stream_Closed := True;
                     end if;
                  when RFLX.Http2_Parameters.RST_STREAM =>
                     FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
                     Transport.Close (C.Trans);
                     raise RPC_Error with "peer reset stream";
                  when others =>
                     Handle_Connection_Frame (C, Hdr, View);
               end case;
            end;
         end if;

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
   end Server_Stream;

   ---------------------------------------------------------------------
   --  Client_Stream — N requests → 1 response.
   --  Uses Stream::Client_Stream FSM (Loading_Data / Sending_Data
   --  loop until END_STREAM, then Awaiting_Reply).
   ---------------------------------------------------------------------

   procedure Client_Stream
     (C                     : in out Connection;
      Request_Headers       : Hpack.Header_Block;
      Response_Headers      : in out Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Response_Body         : in out RFLX.RFLX_Types.Bytes;
      Response_Body_Last    : out Natural)
   is
      package FSM renames RFLX.Stream.Client_Stream.FSM;
      Ctx : FSM.Context;

      Stream_Id : constant Bit_Len := C.Next_Stream_Id;
      Hdrs_Last : RFLX.RFLX_Types.Index;

      Body_Cursor   : Integer := Integer (Response_Body'First) - 1;
      Got_Headers   : Boolean := False;
      Stream_Closed : Boolean := False;

      --  Outbound DATA-frame staging.
      Msg_Buf  : RFLX.RFLX_Types.Bytes (1 .. 8192) := (others => 0);
      Msg_Last : RFLX.RFLX_Types.Index;

      End_Of_Outbound : Boolean := False;
   begin
      Response_Headers_Last := Response_Headers'First - 1;
      Response_Body_Last    := Integer (Response_Body'First) - 1;
      C.Next_Stream_Id      := C.Next_Stream_Id + 2;

      Encode_Request_Headers
        (C, Request_Headers, Stream_Id, False, Hdrs_Last);

      FSM.Initialize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
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

         --  FSM wants outbound data: pull next request msg from
         --  caller, gRPC-frame it, wrap as HTTP/2 DATA, hand to FSM.
         if FSM.Needs_Data (Ctx, FSM.C_App_Outbox)
           and then not End_Of_Outbound
         then
            declare
               Has_Msg : constant Boolean :=
                 Next_Message (Msg_Buf, Msg_Last);
            begin
               if not Has_Msg then
                  End_Of_Outbound := True;
               end if;
            end;

            declare
               Data_Last  : RFLX.RFLX_Types.Index;
               Frame_View : RFLX.RFLX_Types.Bytes
                 (C.Buf'First .. C.Buf'First + 8 + 5 + 8192);
               --  Use a slice of C.Buf to compose: [9-byte H2 hdr
               --  | 5-byte gRPC prefix | protobuf body | END_STREAM
               --  flag-encoded]
               Inner : RFLX.RFLX_Types.Bytes
                 (1 .. 5 +
                    (if End_Of_Outbound then 0 else
                       RFLX.RFLX_Types.Index (Msg_Last) - 0));
            begin
               pragma Unreferenced (Frame_View);
               --  Build 5-byte gRPC framing + payload into Inner.
               if End_Of_Outbound then
                  --  Emit empty DATA frame with END_STREAM to half-
                  --  close the request stream.
                  declare
                     Empty : constant RFLX.RFLX_Types.Bytes
                       (1 .. 0) := (others => 0);
                  begin
                     Wire.Encode_Data
                       (Buffer => C.Buf, Last => Data_Last,
                        Stream_Id => Stream_Id,
                        Payload => Empty, End_Stream => True);
                  end;
               else
                  Inner (1) := 0;  --  compression flag = 0
                  declare
                     Len : constant Natural := Natural (Msg_Last);
                  begin
                     Inner (2) := U8 ((Len / 16777216) mod 256);
                     Inner (3) := U8 ((Len / 65536) mod 256);
                     Inner (4) := U8 ((Len / 256) mod 256);
                     Inner (5) := U8 (Len mod 256);
                     for I in 1 .. Len loop
                        Inner (5 + RFLX.RFLX_Types.Index (I)) :=
                          Msg_Buf (RFLX.RFLX_Types.Index (I));
                     end loop;
                  end;
                  Wire.Encode_Data
                    (Buffer => C.Buf, Last => Data_Last,
                     Stream_Id => Stream_Id,
                     Payload => Inner,
                     End_Stream => False);
               end if;

               if FSM.Needs_Data (Ctx, FSM.C_App_Outbox) then
                  FSM.Write
                    (Ctx, FSM.C_App_Outbox,
                     C.Buf.all (C.Buf'First .. Data_Last));
               end if;
            end;
         end if;

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
         end if;

         if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
            declare
               N    : constant RFLX.RFLX_Types.Length :=
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
                  raise RPC_Error
                    with "App_Pending frame header decode failed";
               end if;
               case Hdr.Frame_Type_Value is
                  when RFLX.Http2_Parameters.HEADERS =>
                     Decode_Header_Frame
                       (C, Hdr, View,
                        Response_Headers, Response_Headers_Last);
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
                           for I in 1 .. Integer (Hdr.Length) loop
                              Body_Cursor := Body_Cursor + 1;
                              Response_Body
                                (RFLX.RFLX_Types.Index (Body_Cursor)) :=
                                View
                                  (View'First + 8
                                   + RFLX.RFLX_Types.Index (I));
                           end loop;
                        end;
                        Account_Inbound_Data (C, Hdr.Length, Stream_Id);
                     end if;
                     if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                        Stream_Closed := True;
                     end if;
                  when RFLX.Http2_Parameters.RST_STREAM =>
                     FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
                     Transport.Close (C.Trans);
                     raise RPC_Error with "peer reset stream";
                  when others =>
                     Handle_Connection_Frame (C, Hdr, View);
               end case;
            end;
         end if;

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
   end Client_Stream;

   ---------------------------------------------------------------------
   --  Bidi_Stream — N requests ↔ N responses, interleaved.
   --  Uses Stream::Bidi_Stream FSM (Try_Send / Try_Recv alternation).
   ---------------------------------------------------------------------

   procedure Bidi_Stream
     (C                     : in out Connection;
      Request_Headers       : Hpack.Header_Block;
      Response_Headers      : in out Hpack.Header_Block;
      Response_Headers_Last : out Natural)
   is
      package FSM renames RFLX.Stream.Bidi_Stream.FSM;
      Ctx : FSM.Context;

      Stream_Id : constant Bit_Len := C.Next_Stream_Id;
      Hdrs_Last : RFLX.RFLX_Types.Index;

      Got_Headers   : Boolean := False;
      Stream_Closed : Boolean := False;

      Msg_Buf  : RFLX.RFLX_Types.Bytes (1 .. 8192) := (others => 0);
      Msg_Last : RFLX.RFLX_Types.Index;

      End_Of_Outbound : Boolean := False;
   begin
      Response_Headers_Last := Response_Headers'First - 1;
      C.Next_Stream_Id      := C.Next_Stream_Id + 2;

      Encode_Request_Headers
        (C, Request_Headers, Stream_Id, False, Hdrs_Last);

      FSM.Initialize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
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

         if FSM.Needs_Data (Ctx, FSM.C_App_Outbox)
           and then not End_Of_Outbound
         then
            declare
               Has_Msg : constant Boolean :=
                 Next_Outbound (Msg_Buf, Msg_Last);
            begin
               if not Has_Msg then
                  End_Of_Outbound := True;
               end if;
            end;
            declare
               Data_Last : RFLX.RFLX_Types.Index;
            begin
               if End_Of_Outbound then
                  declare
                     Empty : constant RFLX.RFLX_Types.Bytes (1 .. 0) :=
                       (others => 0);
                  begin
                     Wire.Encode_Data
                       (Buffer => C.Buf, Last => Data_Last,
                        Stream_Id => Stream_Id,
                        Payload => Empty, End_Stream => True);
                  end;
               else
                  declare
                     Len : constant Natural := Natural (Msg_Last);
                     Inner : RFLX.RFLX_Types.Bytes
                       (1 .. 5 + RFLX.RFLX_Types.Index (Len));
                  begin
                     Inner (1) := 0;
                     Inner (2) := U8 ((Len / 16777216) mod 256);
                     Inner (3) := U8 ((Len / 65536) mod 256);
                     Inner (4) := U8 ((Len / 256) mod 256);
                     Inner (5) := U8 (Len mod 256);
                     for I in 1 .. Len loop
                        Inner (5 + RFLX.RFLX_Types.Index (I)) :=
                          Msg_Buf (RFLX.RFLX_Types.Index (I));
                     end loop;
                     Wire.Encode_Data
                       (Buffer => C.Buf, Last => Data_Last,
                        Stream_Id => Stream_Id,
                        Payload => Inner, End_Stream => False);
                  end;
               end if;
               if FSM.Needs_Data (Ctx, FSM.C_App_Outbox) then
                  FSM.Write
                    (Ctx, FSM.C_App_Outbox,
                     C.Buf.all (C.Buf'First .. Data_Last));
               end if;
            end;
         end if;

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
         end if;

         if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
            declare
               N    : constant RFLX.RFLX_Types.Length :=
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
                  raise RPC_Error
                    with "App_Pending frame header decode failed";
               end if;
               case Hdr.Frame_Type_Value is
                  when RFLX.Http2_Parameters.HEADERS =>
                     Decode_Header_Frame
                       (C, Hdr, View,
                        Response_Headers, Response_Headers_Last);
                     Got_Headers := True;
                     if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                        Stream_Closed := True;
                     end if;
                  when RFLX.Http2_Parameters.DATA =>
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
                              On_Inbound (Msg);
                           end if;
                        end;
                        Account_Inbound_Data (C, Hdr.Length, Stream_Id);
                     end if;
                     if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                        Stream_Closed := True;
                     end if;
                  when RFLX.Http2_Parameters.RST_STREAM =>
                     FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
                     Transport.Close (C.Trans);
                     raise RPC_Error with "peer reset stream";
                  when others =>
                     Handle_Connection_Frame (C, Hdr, View);
               end case;
            end;
         end if;

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
   end Bidi_Stream;

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

   function Get_Transport (C : aliased in out Connection)
     return Transport_Channel_Acc is
   begin
      return C.Trans'Unchecked_Access;
   end Get_Transport;

end Http2_Core.Connection;
