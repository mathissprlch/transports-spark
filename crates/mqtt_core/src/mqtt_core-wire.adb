with RFLX.Control_Packet;
with RFLX.Pingreq.Packet;
with RFLX.Pingresp.Packet;
with RFLX.Disconnect.Packet;
with RFLX.Connack.Packet;
with RFLX.Connect.Packet;
with RFLX.Publish.Packet;

package body Mqtt_Core.Wire
with SPARK_Mode
is

   use type RFLX.RFLX_Types.Index;

   --  String → RFLX_Types.Bytes conversion. Used for UTF-8 fields.
   function To_Bytes (S : String) return RFLX.RFLX_Types.Bytes
   with Post => To_Bytes'Result'Length = S'Length;

   function To_Bytes (S : String) return RFLX.RFLX_Types.Bytes is
      Result : RFLX.RFLX_Types.Bytes (1 .. S'Length);
      Idx    : RFLX.RFLX_Types.Index := Result'First;
   begin
      for C of S loop
         Result (Idx) := RFLX.RFLX_Types.Byte (Character'Pos (C));
         Idx := Idx + 1;
      end loop;
      return Result;
   end To_Bytes;

   ---------------------------------------------------------------------
   --  Encode_Pingreq
   ---------------------------------------------------------------------

   procedure Encode_Pingreq
     (Buffer : in out Bytes_Ptr;
      Last   :    out Index)
   is
      Ctx : RFLX.Pingreq.Packet.Context;
   begin
      RFLX.Pingreq.Packet.Initialize (Ctx, Buffer);
      RFLX.Pingreq.Packet.Set_Packet_Type
        (Ctx, RFLX.Control_Packet.PINGREQ);
      RFLX.Pingreq.Packet.Set_Reserved (Ctx, 0);
      RFLX.Pingreq.Packet.Set_Remaining_Length (Ctx, 0);
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Pingreq.Packet.Message_Last (Ctx));
      RFLX.Pingreq.Packet.Take_Buffer (Ctx, Buffer);
   end Encode_Pingreq;

   ---------------------------------------------------------------------
   --  Encode_Disconnect
   ---------------------------------------------------------------------

   procedure Encode_Disconnect
     (Buffer : in out Bytes_Ptr;
      Last   :    out Index)
   is
      Ctx : RFLX.Disconnect.Packet.Context;
   begin
      RFLX.Disconnect.Packet.Initialize (Ctx, Buffer);
      RFLX.Disconnect.Packet.Set_Packet_Type
        (Ctx, RFLX.Control_Packet.DISCONNECT);
      RFLX.Disconnect.Packet.Set_Reserved (Ctx, 0);
      RFLX.Disconnect.Packet.Set_Remaining_Length (Ctx, 0);
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Disconnect.Packet.Message_Last (Ctx));
      RFLX.Disconnect.Packet.Take_Buffer (Ctx, Buffer);
   end Encode_Disconnect;

   ---------------------------------------------------------------------
   --  Encode_Connect
   --
   --  Layout (v0.2 minimal, no auth, no will):
   --    Byte 1   : 0x10 (CONNECT type, reserved=0)
   --    Byte 2   : Remaining Length (1-byte varint)
   --    Bytes 3-8: "MQTT" length-prefixed (00 04 4D 51 54 54)
   --    Byte 9   : Protocol Level = 4
   --    Byte 10  : Connect Flags (Clean_Session bit only)
   --    Bytes 11-12: Keep Alive (16-bit big-endian)
   --    Byte 13-14: Client Id length (16-bit big-endian)
   --    Byte 15+ : Client Id bytes
   ---------------------------------------------------------------------

   procedure Encode_Connect
     (Buffer        : in out Bytes_Ptr;
      Last          :    out Index;
      Client_Id     : String;
      Keep_Alive_S  : Keep_Alive;
      Clean_Session : Boolean := True)
   is
      Ctx : RFLX.Connect.Packet.Context;
      RL  : constant RFLX.Connect.Remaining_Length :=
        RFLX.Connect.Remaining_Length (12 + Client_Id'Length);
   begin
      RFLX.Connect.Packet.Initialize (Ctx, Buffer);
      RFLX.Connect.Packet.Set_Packet_Type
        (Ctx, RFLX.Control_Packet.CONNECT);
      RFLX.Connect.Packet.Set_Reserved (Ctx, 0);
      RFLX.Connect.Packet.Set_Remaining_Length (Ctx, RL);
      RFLX.Connect.Packet.Set_Protocol_Name_Length (Ctx, 4);
      RFLX.Connect.Packet.Set_Protocol_Name
        (Ctx, To_Bytes ("MQTT"));
      RFLX.Connect.Packet.Set_Protocol_Level (Ctx, 4);
      --  Connect Flags byte (high to low: User, Pass, WillRet, WillQ,
      --  WillF, Clean, Reserved). v0.2 has User=Pass=WillX=Reserved=0.
      RFLX.Connect.Packet.Set_User_Name_Flag (Ctx, False);
      RFLX.Connect.Packet.Set_Password_Flag  (Ctx, False);
      RFLX.Connect.Packet.Set_Will_Retain    (Ctx, 0);
      RFLX.Connect.Packet.Set_Will_QoS       (Ctx, 0);
      RFLX.Connect.Packet.Set_Will_Flag      (Ctx, 0);
      RFLX.Connect.Packet.Set_Clean_Session  (Ctx, Clean_Session);
      RFLX.Connect.Packet.Set_Reserved_Connect_Flag (Ctx, 0);
      RFLX.Connect.Packet.Set_Keep_Alive (Ctx, Keep_Alive_S);
      RFLX.Connect.Packet.Set_Client_Id_Length
        (Ctx, RFLX.Control_Packet.String_Length (Client_Id'Length));
      RFLX.Connect.Packet.Set_Client_Id (Ctx, To_Bytes (Client_Id));
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Connect.Packet.Message_Last (Ctx));
      RFLX.Connect.Packet.Take_Buffer (Ctx, Buffer);
   end Encode_Connect;

   ---------------------------------------------------------------------
   --  Decode_Connack
   ---------------------------------------------------------------------

   procedure Decode_Connack
     (Buffer          : in out Bytes_Ptr;
      Valid           :    out Boolean;
      Session_Present :    out Boolean;
      Code            :    out Return_Code)
   is
      Ctx : RFLX.Connack.Packet.Context;
   begin
      RFLX.Connack.Packet.Initialize (Ctx, Buffer);
      RFLX.Connack.Packet.Verify_Message (Ctx);
      if RFLX.Connack.Packet.Well_Formed_Message (Ctx) then
         Valid           := True;
         Session_Present := RFLX.Connack.Packet.Get_Session_Present (Ctx);
         Code            := RFLX.Connack.Packet.Get_Return_Code (Ctx);
      else
         Valid           := False;
         Session_Present := False;
         Code            := RFLX.Connack.ACCEPTED;
      end if;
      RFLX.Connack.Packet.Take_Buffer (Ctx, Buffer);
   end Decode_Connack;

   ---------------------------------------------------------------------
   --  Encode_Publish_Qos0
   ---------------------------------------------------------------------

   procedure Encode_Publish_Qos0
     (Buffer  : in out Bytes_Ptr;
      Last    :    out Index;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes)
   is
      Ctx : RFLX.Publish.Packet.Context;
      RL  : constant RFLX.Publish.Remaining_Length :=
        RFLX.Publish.Remaining_Length (2 + Topic'Length + Payload'Length);
   begin
      RFLX.Publish.Packet.Initialize (Ctx, Buffer);
      RFLX.Publish.Packet.Set_Packet_Type
        (Ctx, RFLX.Control_Packet.PUBLISH);
      RFLX.Publish.Packet.Set_DUP    (Ctx, False);
      RFLX.Publish.Packet.Set_QoS    (Ctx, RFLX.Control_Packet.QOS_0);
      RFLX.Publish.Packet.Set_Retain (Ctx, 0);
      RFLX.Publish.Packet.Set_Remaining_Length (Ctx, RL);
      RFLX.Publish.Packet.Set_Topic_Name_Length
        (Ctx, RFLX.Control_Packet.String_Length (Topic'Length));
      RFLX.Publish.Packet.Set_Topic_Name (Ctx, To_Bytes (Topic));
      if Payload'Length = 0 then
         RFLX.Publish.Packet.Set_Payload_Empty (Ctx);
      else
         RFLX.Publish.Packet.Set_Payload (Ctx, Payload);
      end if;
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Publish.Packet.Message_Last (Ctx));
      RFLX.Publish.Packet.Take_Buffer (Ctx, Buffer);
   end Encode_Publish_Qos0;

   ---------------------------------------------------------------------
   --  Decode_Pingresp
   ---------------------------------------------------------------------

   procedure Decode_Pingresp
     (Buffer : in out Bytes_Ptr;
      Valid  :    out Boolean)
   is
      Ctx : RFLX.Pingresp.Packet.Context;
   begin
      RFLX.Pingresp.Packet.Initialize (Ctx, Buffer);
      RFLX.Pingresp.Packet.Verify_Message (Ctx);
      Valid := RFLX.Pingresp.Packet.Well_Formed_Message (Ctx);
      RFLX.Pingresp.Packet.Take_Buffer (Ctx, Buffer);
   end Decode_Pingresp;

end Mqtt_Core.Wire;
