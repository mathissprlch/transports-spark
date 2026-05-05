with RFLX.Http2_Parameters;

with Http2_Core.Wire;

package body Http2_Core.Mux_Server.Frames is

   use type RFLX.RFLX_Types.Index;

   subtype U8 is RFLX.RFLX_Types.Byte;

   procedure Send_Settings_Initial
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
          Value      => Max_Streams));
   begin
      Wire.Encode_Settings (L.Buf, Last, Params);
      Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
   end Send_Settings_Initial;

   procedure Send_Settings_Ack
     (L    : in out Listener;
      Chan : Transport.Channel)
   is
      Last : RFLX.RFLX_Types.Index;
   begin
      Wire.Encode_Settings_Ack (L.Buf, Last);
      Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
   end Send_Settings_Ack;

   procedure Send_Ping_Ack
     (L    : in out Listener;
      Chan : Transport.Channel;
      Echo : RFLX.RFLX_Types.Bytes)
   is
      Last : RFLX.RFLX_Types.Index;
   begin
      Wire.Encode_Ping
        (Buffer => L.Buf, Last => Last,
         Opaque_Data => Echo, Ack => True);
      Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
   end Send_Ping_Ack;

   procedure Send_Goaway
     (L              : in out Listener;
      Chan           : Transport.Channel;
      Last_Stream_Id : Bit_Len)
   is
      Last : RFLX.RFLX_Types.Index;
      Empty : constant RFLX.RFLX_Types.Bytes (1 .. 0) := (others => 0);
   begin
      Wire.Encode_Goaway
        (Buffer         => L.Buf,
         Last           => Last,
         Last_Stream_Id => Last_Stream_Id,
         Error_Code     => 0,
         Debug_Data     => Empty);
      Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
   exception
      when others => null;
   end Send_Goaway;

   procedure Send_Rst_Stream
     (L          : in out Listener;
      Chan       : Transport.Channel;
      Stream_Id  : Bit_Len;
      Error_Code : Bit_Len)
   is
      Last : RFLX.RFLX_Types.Index;
   begin
      Wire.Encode_Rst_Stream
        (Buffer => L.Buf, Last => Last,
         Stream_Id => Stream_Id, Error_Code => Error_Code);
      Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
   end Send_Rst_Stream;

   procedure Send_Window_Update
     (L         : in out Listener;
      Chan      : Transport.Channel;
      Stream_Id : Bit_Len;
      Increment : Bit_Len)
   is
      Last : RFLX.RFLX_Types.Index;
   begin
      Wire.Encode_Window_Update
        (Buffer => L.Buf, Last => Last,
         Stream_Id => Stream_Id, Increment => Increment);
      Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
   end Send_Window_Update;

   procedure Send_Headers_Frame
     (L          : in out Listener;
      Chan       : Transport.Channel;
      Stream_Id  : Bit_Len;
      Headers_In : Hpack.Header_Block;
      End_Stream : Boolean)
   is
      --  RFC 9113 default SETTINGS_MAX_FRAME_SIZE; we don't yet
      --  honor a peer override so this is the conservative ceiling
      --  for any single frame we emit.
      Max_Frame_Payload : constant := 16384;
      Frag_Out  : Hpack.Octet_Array
        (1 .. Hpack.Max_Header_Length * Hpack.Max_Headers);
      Frag_Last : Natural;
      Frag_OK   : Boolean;
      Frame_Last : RFLX.RFLX_Types.Index;
   begin
      Hpack.Encode
        (Headers     => Headers_In,
         Output      => Frag_Out,
         Output_Last => Frag_Last,
         Output_OK   => Frag_OK);
      if not Frag_OK then
         raise Mux_Server_Error with "HPACK encode failed";
      end if;
      declare
         Frag_Bytes : RFLX.RFLX_Types.Bytes
           (1 .. RFLX.RFLX_Types.Index (Frag_Last));
      begin
         for I in 1 .. Frag_Last loop
            Frag_Bytes (RFLX.RFLX_Types.Index (I)) :=
              U8 (Frag_Out (I));
         end loop;

         if Frag_Last <= Max_Frame_Payload then
            --  Fits in a single frame — emit HEADERS with
            --  END_HEADERS. Common case; gRPC headers are tiny.
            Wire.Encode_Headers
              (Buffer => L.Buf, Last => Frame_Last,
               Stream_Id => Stream_Id, Fragment => Frag_Bytes,
               End_Stream => End_Stream);
            Transport.Send
              (Chan, L.Buf.all (L.Buf'First .. Frame_Last));
         else
            --  RFC §6.10: split into HEADERS (no END_HEADERS) +
            --  N CONTINUATION frames; only the last frame in the
            --  run carries END_HEADERS.
            declare
               First_Slice : constant RFLX.RFLX_Types.Bytes :=
                 Frag_Bytes (1 .. Max_Frame_Payload);
            begin
               Wire.Encode_Headers
                 (Buffer => L.Buf, Last => Frame_Last,
                  Stream_Id => Stream_Id, Fragment => First_Slice,
                  End_Stream => End_Stream,
                  End_Headers => False);
               Transport.Send
                 (Chan, L.Buf.all (L.Buf'First .. Frame_Last));
            end;
            declare
               Off : Natural := Max_Frame_Payload;
            begin
               while Off < Frag_Last loop
                  declare
                     Take : constant Natural :=
                       Natural'Min
                         (Max_Frame_Payload, Frag_Last - Off);
                     Slice : constant RFLX.RFLX_Types.Bytes :=
                       Frag_Bytes
                         (RFLX.RFLX_Types.Index (Off + 1)
                          .. RFLX.RFLX_Types.Index (Off + Take));
                     Final : constant Boolean :=
                       Off + Take = Frag_Last;
                  begin
                     Wire.Encode_Continuation
                       (Buffer => L.Buf, Last => Frame_Last,
                        Stream_Id => Stream_Id, Fragment => Slice,
                        End_Headers => Final);
                     Transport.Send
                       (Chan,
                        L.Buf.all (L.Buf'First .. Frame_Last));
                     Off := Off + Take;
                  end;
               end loop;
            end;
         end if;
      end;
   end Send_Headers_Frame;

   procedure Send_Data_Frame
     (L          : in out Listener;
      Chan       : Transport.Channel;
      Stream_Id  : Bit_Len;
      Payload    : RFLX.RFLX_Types.Bytes;
      End_Stream : Boolean)
   is
      Last : RFLX.RFLX_Types.Index;
   begin
      Wire.Encode_Data
        (Buffer => L.Buf, Last => Last,
         Stream_Id => Stream_Id, Payload => Payload,
         End_Stream => End_Stream);
      Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
      --  RFC 9113 §6.9 outbound bookkeeping: every DATA byte we
      --  send (the payload, not the 9-byte frame header) draws
      --  down BOTH the connection-level window (Peer_Send_Window)
      --  and the matching stream-level window. Underflow on either
      --  is clamped at 0 — the streaming hook layer is responsible
      --  for not pumping replies when either window is too small.
      declare
         use type Bit_Len;
         Sent : constant Bit_Len := Bit_Len (Payload'Length);
      begin
         if L.Peer_Send_Window >= Sent then
            L.Peer_Send_Window := L.Peer_Send_Window - Sent;
         else
            L.Peer_Send_Window := 0;
         end if;

         for I in L.Slots'Range loop
            if L.Slots (I).Stream_Id = Stream_Id
              and then L.Slots (I).Phase /= Free
            then
               if L.Slots (I).Stream_Send_Window >= Sent then
                  L.Slots (I).Stream_Send_Window :=
                    L.Slots (I).Stream_Send_Window - Sent;
               else
                  L.Slots (I).Stream_Send_Window := 0;
               end if;
               exit;
            end if;
         end loop;
      end;
   end Send_Data_Frame;

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
                 View'First + 5
                 + RFLX.RFLX_Types.Index (Msg_Len) - 1);
         end;
      end;
   end Strip_Grpc_Frame;

end Http2_Core.Mux_Server.Frames;
