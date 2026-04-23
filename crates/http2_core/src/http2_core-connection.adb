with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.RFLX_Builtin_Types;
with RFLX.Http2_Parameters;

with Http2_Core.Wire;

package body Http2_Core.Connection is

   use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;
   use type RFLX.RFLX_Builtin_Types.Bit_Length;
   use type RFLX.RFLX_Builtin_Types.Byte;
   use type RFLX.Http2_Parameters.HTTP_2_Frame_Type_Enum;

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
      if C.Buf = null then
         C.Buf :=
           new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
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

      --  Read frames until we've seen both the peer's SETTINGS (which
      --  we ACK) and the ACK to our own SETTINGS. §6.5.3 says the
      --  preface MUST be followed by a SETTINGS frame; the very
      --  first frame the peer sends is its initial SETTINGS.
      while not (Got_Peer_Settings and Got_Settings_Ack) loop
         Read_Frame (C, Header, Last, Read_OK);
         if not Read_OK then
            Transport.Close (C.Trans);
            raise Connect_Error
              with "preface/SETTINGS handshake failed";
         end if;

         if Header.Frame_Type_Value = RFLX.Http2_Parameters.SETTINGS then
            if (Header.Flags and Wire.Flag_ACK) /= 0 then
               --  Empty-body ACK confirming our SETTINGS.
               if Header.Length /= 0 then
                  Transport.Close (C.Trans);
                  raise Connect_Error
                    with "non-empty SETTINGS-ACK from peer";
               end if;
               Got_Settings_Ack := True;
            else
               --  Peer's initial SETTINGS — ACK it.
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
            --  §6.5: any non-SETTINGS frame before peer's initial
            --  SETTINGS is a protocol error. Tolerate WINDOW_UPDATE
            --  in case the peer sends it interleaved (some servers
            --  do); reject anything else.
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
   --  Round_Trip — synchronous unary RPC.
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
      Stream_Id : constant Bit_Len := C.Next_Stream_Id;
      Last      : RFLX.RFLX_Types.Index;
      Header    : Wire.Frame_Header;
      Read_OK   : Boolean;
      End_Stream_Out : constant Boolean := Request_Body'Length = 0;
      Body_Cursor    : Integer := Integer (Response_Body'First) - 1;

      Got_Headers   : Boolean := False;
      Stream_Closed : Boolean := False;
   begin
      Response_Headers_Last := Response_Headers'First - 1;
      Response_Body_Last    := Integer (Response_Body'First) - 1;
      C.Next_Stream_Id      := C.Next_Stream_Id + 2;

      --  Encode HPACK fragment for the request headers into a
      --  scratch slice of C.Buf that does NOT overlap the eventual
      --  HEADERS frame target — easier to compose by encoding into
      --  the back of the buffer, then copy forward when wrapping.
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

         --  Wrap as HEADERS frame in C.Buf.
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
               Last       => Last,
               Stream_Id  => Stream_Id,
               Fragment   => Frag_Bytes,
               End_Stream => End_Stream_Out);
            Transport.Send (C.Trans, C.Buf.all (C.Buf'First .. Last));
         end;
      end;

      if not End_Stream_Out then
         Wire.Encode_Data
           (Buffer     => C.Buf,
            Last       => Last,
            Stream_Id  => Stream_Id,
            Payload    => Request_Body,
            End_Stream => True);
         Transport.Send (C.Trans, C.Buf.all (C.Buf'First .. Last));
      end if;

      --  Drive inbound until the stream closes.
      while not Stream_Closed loop
         Read_Frame (C, Header, Last, Read_OK);
         if not Read_OK then
            raise RPC_Error with "EOF or socket error";
         end if;

         --  Connection-level frames — handle then loop.
         if Header.Stream_Identifier = 0 then
            case Header.Frame_Type_Value is
               when RFLX.Http2_Parameters.PING =>
                  if (Header.Flags and Wire.Flag_ACK) = 0 then
                     declare
                        Ack_Last : RFLX.RFLX_Types.Index;
                        Echo : constant RFLX.RFLX_Types.Bytes :=
                          C.Buf.all
                            (C.Buf'First + 9 ..
                               C.Buf'First + 8 + 8);
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
                  if (Header.Flags and Wire.Flag_ACK) = 0 then
                     declare
                        Ack_Last : RFLX.RFLX_Types.Index;
                     begin
                        Wire.Encode_Settings_Ack (C.Buf, Ack_Last);
                        Transport.Send
                          (C.Trans,
                           C.Buf.all (C.Buf'First .. Ack_Last));
                     end;
                  end if;
               when RFLX.Http2_Parameters.WINDOW_UPDATE =>
                  --  Connection window grew — fine, ignore for v0.2
                  --  (we don't proactively manage flow control).
                  null;
               when RFLX.Http2_Parameters.GOAWAY =>
                  raise RPC_Error with "peer sent GOAWAY";
               when others =>
                  --  Unknown stream-0 frame — §4.1 says "ignore."
                  null;
            end case;

         elsif Header.Stream_Identifier = Stream_Id then
            case Header.Frame_Type_Value is
               when RFLX.Http2_Parameters.HEADERS =>
                  if (Header.Flags and Wire.Flag_END_HEADERS) = 0 then
                     raise RPC_Error
                       with "CONTINUATION not supported in v0.2";
                  end if;
                  if (Header.Flags and Wire.Flag_PADDED) /= 0 then
                     raise RPC_Error
                       with "PADDED HEADERS not supported in v0.2";
                  end if;
                  --  Skip optional priority prefix (5 bytes) if set.
                  declare
                     Frag_First : RFLX.RFLX_Types.Index :=
                       C.Buf'First + 9;
                     Frag_Last  : constant RFLX.RFLX_Types.Index :=
                       Last;
                  begin
                     if (Header.Flags and Wire.Flag_PRIORITY) /= 0 then
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
                               (C.Buf.all
                                  (Frag_First +
                                     RFLX.RFLX_Types.Index (I) - 1));
                        end loop;
                        Hpack.Decode
                          (Input        => Frag,
                           Headers      => Response_Headers,
                           Headers_Last => Response_Headers_Last,
                           Output_OK    => Read_OK);
                        if not Read_OK then
                           raise RPC_Error
                             with "HPACK decode failed";
                        end if;
                     end;
                  end;
                  Got_Headers := True;
                  if (Header.Flags and Wire.Flag_END_STREAM) /= 0 then
                     Stream_Closed := True;
                  end if;

               when RFLX.Http2_Parameters.DATA =>
                  if Header.Length > 0 then
                     declare
                        Need : constant Integer := Body_Cursor + 1
                                                 + Integer (Header.Length);
                     begin
                        if Need > Integer (Response_Body'Last) then
                           raise RPC_Error
                             with "response body overflow";
                        end if;
                        for I in 0 .. Integer (Header.Length) - 1 loop
                           Body_Cursor := Body_Cursor + 1;
                           Response_Body
                             (RFLX.RFLX_Types.Index (Body_Cursor)) :=
                             C.Buf.all
                               (C.Buf'First + 9
                                + RFLX.RFLX_Types.Index (I));
                        end loop;
                     end;
                  end if;
                  if (Header.Flags and Wire.Flag_END_STREAM) /= 0 then
                     Stream_Closed := True;
                  end if;

               when RFLX.Http2_Parameters.RST_STREAM =>
                  raise RPC_Error with "peer reset stream";

               when others =>
                  --  Unknown stream-N frame: §4.1 says ignore.
                  null;
            end case;
         end if;
      end loop;

      if not Got_Headers then
         raise RPC_Error with "stream closed before HEADERS arrived";
      end if;
      Response_Body_Last := Body_Cursor;
   end Round_Trip;

   ---------------------------------------------------------------------
   --  Close — emit GOAWAY(NO_ERROR) and close socket.
   ---------------------------------------------------------------------

   procedure Close (C : in out Connection) is
      Last : RFLX.RFLX_Types.Index;
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
      if C.Buf /= null then
         RFLX.RFLX_Types.Free (C.Buf);
      end if;
   end Close;

end Http2_Core.Connection;
