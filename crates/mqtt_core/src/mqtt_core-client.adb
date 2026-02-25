with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.Connack;
with RFLX.Connect;
with Mqtt_Core.Wire;

package body Mqtt_Core.Client is

   use type RFLX.Control_Packet.Packet_Identifier;

   --  Single re-usable buffer size. v0.2 caps at 1-byte Remaining
   --  Length, so any packet fits comfortably in 256 bytes.
   Buffer_Capacity : constant := 256;

   --  Allocate a fresh zero-filled buffer. Caller frees.
   function Fresh_Buffer return RFLX.RFLX_Types.Bytes_Ptr;

   function Fresh_Buffer return RFLX.RFLX_Types.Bytes_Ptr is
   begin
      return new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
   end Fresh_Buffer;

   --  Read the next full MQTT packet from the socket into Buf.
   --  v0.2 assumes single-byte Remaining Length form: byte 1 is the
   --  fixed-header byte, byte 2 is RL (0..127), then RL more bytes.
   --  Sets Success := False on EOF / socket error.
   procedure Read_Full_Packet
     (C       : in out Client;
      Buf     : in out RFLX.RFLX_Types.Bytes_Ptr;
      Last    :    out RFLX.RFLX_Types.Index;
      Success :    out Boolean);

   procedure Read_Full_Packet
     (C       : in out Client;
      Buf     : in out RFLX.RFLX_Types.Bytes_Ptr;
      Last    :    out RFLX.RFLX_Types.Index;
      Success :    out Boolean)
   is
      Two_Bytes_Ok : Boolean;
      Body_Ok      : Boolean;
      RL           : Natural;
   begin
      Last    := Buf'First;  --  not meaningful unless Success = True
      Success := False;
      Transport.Receive_Full
        (C.Trans, Buf.all (Buf'First .. Buf'First + 1), Two_Bytes_Ok);
      if not Two_Bytes_Ok then
         return;
      end if;
      RL := Natural (Buf.all (Buf'First + 1));
      if RL = 0 then
         Last    := Buf'First + 1;
         Success := True;
         return;
      end if;
      if Buf'First + 1 + RFLX.RFLX_Types.Index (RL) > Buf'Last then
         --  Not enough room — refuse.
         return;
      end if;
      Transport.Receive_Full
        (C.Trans,
         Buf.all (Buf'First + 2 .. Buf'First + 1 + RFLX.RFLX_Types.Index (RL)),
         Body_Ok);
      if not Body_Ok then
         return;
      end if;
      Last    := Buf'First + 1 + RFLX.RFLX_Types.Index (RL);
      Success := True;
   end Read_Full_Packet;

   ---------------------------------------------------------------------
   --  Open
   ---------------------------------------------------------------------

   procedure Open
     (C             : in out Client;
      Host          : String;
      Port          : Natural := 1883;
      Client_Id     : String;
      Keep_Alive_S  : Natural := 60;
      Clean_Session : Boolean := True)
   is
      Buf  : RFLX.RFLX_Types.Bytes_Ptr := Fresh_Buffer;
      Last : RFLX.RFLX_Types.Index;
      Connack_Ok       : Boolean;
      Session_Present  : Boolean;
      Code             : Wire.Return_Code;
      use type Wire.Return_Code;
   begin
      Transport.Connect (C.Trans, Host, Port);
      --  Encode CONNECT.
      Wire.Encode_Connect
        (Buf, Last,
         Client_Id     => Client_Id,
         Keep_Alive_S  => RFLX.Connect.Keep_Alive (Keep_Alive_S),
         Clean_Session => Clean_Session);
      Transport.Send (C.Trans, Buf.all (Buf'First .. Last));
      RFLX.RFLX_Types.Free (Buf);

      --  Read CONNACK.
      Buf := Fresh_Buffer;
      declare
         Ok : Boolean;
      begin
         Read_Full_Packet (C, Buf, Last, Ok);
         if not Ok then
            RFLX.RFLX_Types.Free (Buf);
            Transport.Close (C.Trans);
            raise Connect_Failure with "no CONNACK";
         end if;
      end;
      Wire.Decode_Connack (Buf, Last, Connack_Ok, Session_Present, Code);
      RFLX.RFLX_Types.Free (Buf);
      if not Connack_Ok or Code /= RFLX.Connack.ACCEPTED then
         Transport.Close (C.Trans);
         raise Connect_Failure with "broker refused CONNECT";
      end if;
   end Open;

   ---------------------------------------------------------------------
   --  Publish (QoS 0)
   ---------------------------------------------------------------------

   procedure Publish
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes)
   is
      Buf  : RFLX.RFLX_Types.Bytes_Ptr := Fresh_Buffer;
      Last : RFLX.RFLX_Types.Index;
   begin
      Wire.Encode_Publish_Qos0 (Buf, Last, Topic, Payload);
      Transport.Send (C.Trans, Buf.all (Buf'First .. Last));
      RFLX.RFLX_Types.Free (Buf);
   end Publish;

   ---------------------------------------------------------------------
   --  Subscribe (single topic)
   ---------------------------------------------------------------------

   procedure Subscribe
     (C     : in out Client;
      Topic : String;
      QoS   : RFLX.Control_Packet.QoS_Level :=
        RFLX.Control_Packet.QOS_0)
   is
      Buf  : RFLX.RFLX_Types.Bytes_Ptr := Fresh_Buffer;
      Last : RFLX.RFLX_Types.Index;
      Pid  : constant Wire.Packet_Identifier := C.Next_Packet_Id;
      Ok            : Boolean;
      Reply_Pid     : Wire.Packet_Identifier;
      Reply_Code    : Wire.Suback_Return_Code;
      use type Wire.Suback_Return_Code;
   begin
      C.Next_Packet_Id := C.Next_Packet_Id + 1;

      Wire.Encode_Subscribe_Single
        (Buf, Last, Pid, Topic, QoS);
      Transport.Send (C.Trans, Buf.all (Buf'First .. Last));
      RFLX.RFLX_Types.Free (Buf);

      Buf := Fresh_Buffer;
      Read_Full_Packet (C, Buf, Last, Ok);
      if not Ok then
         RFLX.RFLX_Types.Free (Buf);
         raise Subscribe_Failure with "no SUBACK";
      end if;
      Wire.Decode_Suback_Single (Buf, Last, Ok, Reply_Pid, Reply_Code);
      RFLX.RFLX_Types.Free (Buf);
      if not Ok or Reply_Pid /= Pid or Reply_Code = Wire.Failure then
         raise Subscribe_Failure with "broker refused subscription";
      end if;
   end Subscribe;

   ---------------------------------------------------------------------
   --  Receive_Publish — block until next PUBLISH (skipping PINGRESP).
   ---------------------------------------------------------------------

   procedure Receive_Publish
     (C            : in out Client;
      Topic        : in out String;
      Topic_Last   :    out Natural;
      Payload      : in out RFLX.RFLX_Types.Bytes;
      Payload_Last :    out RFLX.RFLX_Types.Length)
   is
      use type RFLX.Control_Packet.Packet_Type;
      Buf  : RFLX.RFLX_Types.Bytes_Ptr;
      Last : RFLX.RFLX_Types.Index;
      Ok   : Boolean;
      Kind : RFLX.Control_Packet.Packet_Type;
      Pkt_Valid : Boolean;
   begin
      Topic_Last   := Topic'First - 1;
      Payload_Last := 0;

      loop
         Buf := Fresh_Buffer;
         Read_Full_Packet (C, Buf, Last, Ok);
         if not Ok then
            RFLX.RFLX_Types.Free (Buf);
            raise Receive_Failure with "EOF or socket error";
         end if;
         Kind := Wire.Peek_Packet_Type (Buf.all (Buf'First .. Last));
         if Kind = RFLX.Control_Packet.PUBLISH then
            Wire.Decode_Publish_Qos0
              (Buf, Last, Pkt_Valid, Topic, Topic_Last,
               Payload, Payload_Last);
            RFLX.RFLX_Types.Free (Buf);
            if not Pkt_Valid then
               raise Receive_Failure with "malformed PUBLISH";
            end if;
            return;
         else
            --  PINGRESP / other: discard and keep listening.
            RFLX.RFLX_Types.Free (Buf);
         end if;
      end loop;
   end Receive_Publish;

   ---------------------------------------------------------------------
   --  Close
   ---------------------------------------------------------------------

   procedure Close (C : in out Client) is
      Buf  : RFLX.RFLX_Types.Bytes_Ptr := Fresh_Buffer;
      Last : RFLX.RFLX_Types.Index;
   begin
      Wire.Encode_Disconnect (Buf, Last);
      Transport.Send (C.Trans, Buf.all (Buf'First .. Last));
      RFLX.RFLX_Types.Free (Buf);
      Transport.Close (C.Trans);
   exception
      when others =>
         --  Best-effort close; swallow socket errors on shutdown.
         if Transport.Is_Open (C.Trans) then
            Transport.Close (C.Trans);
         end if;
   end Close;

end Mqtt_Core.Client;
