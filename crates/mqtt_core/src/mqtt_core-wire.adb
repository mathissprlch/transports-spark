with RFLX.Control_Packet;
with RFLX.Pingreq.Packet;
with RFLX.Pingresp.Packet;
with RFLX.Disconnect.Packet;
with RFLX.Connack.Packet;
with RFLX.Connect.Packet;
with RFLX.Publish.Packet;
with RFLX.Subscribe.Packet;
with RFLX.Subscribe.Subscription;
with RFLX.Subscribe.Subscription_List;
with RFLX.Suback.Packet;
with RFLX.Suback.Return_Code_List;

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

   ---------------------------------------------------------------------
   --  Encode_Subscribe_Single
   --
   --  Layout for one subscription:
   --    fixed header: 0x82 + RL (= 5 + Topic'Length, single varint byte)
   --    var header:   Packet Identifier (16-bit big-endian)
   --    payload:      Topic Filter length (16-bit) + Topic_Filter bytes
   --                + Requested QoS byte (high 6 bits = 0)
   ---------------------------------------------------------------------

   procedure Encode_Subscribe_Single
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Topic     : String;
      QoS       : QoS_Level := RFLX.Control_Packet.QOS_0)
   is
      Pkt_Ctx  : RFLX.Subscribe.Packet.Context;
      Seq_Ctx  : RFLX.Subscribe.Subscription_List.Context;
      Elem_Ctx : RFLX.Subscribe.Subscription.Context;
      RL       : constant RFLX.Subscribe.Remaining_Length :=
        RFLX.Subscribe.Remaining_Length (5 + Topic'Length);
   begin
      RFLX.Subscribe.Packet.Initialize (Pkt_Ctx, Buffer);
      RFLX.Subscribe.Packet.Set_Packet_Type
        (Pkt_Ctx, RFLX.Control_Packet.SUBSCRIBE);
      RFLX.Subscribe.Packet.Set_Reserved (Pkt_Ctx, 2);
      RFLX.Subscribe.Packet.Set_Remaining_Length (Pkt_Ctx, RL);
      RFLX.Subscribe.Packet.Set_Packet_Identifier (Pkt_Ctx, Packet_Id);
      --  Switch into the Subscriptions sequence; the buffer hops from
      --  Pkt_Ctx → Seq_Ctx → Elem_Ctx and back along the same chain.
      RFLX.Subscribe.Packet.Switch_To_Subscriptions (Pkt_Ctx, Seq_Ctx);
      RFLX.Subscribe.Subscription_List.Switch (Seq_Ctx, Elem_Ctx);
      RFLX.Subscribe.Subscription.Set_Topic_Filter_Length
        (Elem_Ctx, RFLX.Control_Packet.String_Length (Topic'Length));
      RFLX.Subscribe.Subscription.Set_Topic_Filter
        (Elem_Ctx, To_Bytes (Topic));
      RFLX.Subscribe.Subscription.Set_Reserved_Sub_QoS (Elem_Ctx, 0);
      RFLX.Subscribe.Subscription.Set_Requested_QoS (Elem_Ctx, QoS);
      RFLX.Subscribe.Subscription_List.Update (Seq_Ctx, Elem_Ctx);
      RFLX.Subscribe.Packet.Update_Subscriptions (Pkt_Ctx, Seq_Ctx);
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Subscribe.Packet.Message_Last (Pkt_Ctx));
      RFLX.Subscribe.Packet.Take_Buffer (Pkt_Ctx, Buffer);
   end Encode_Subscribe_Single;

   ---------------------------------------------------------------------
   --  Decode_Suback_Single
   ---------------------------------------------------------------------

   procedure Decode_Suback_Single
     (Buffer    : in out Bytes_Ptr;
      Valid     :    out Boolean;
      Packet_Id :    out Packet_Identifier;
      Code      :    out Suback_Return_Code)
   is
      Pkt_Ctx : RFLX.Suback.Packet.Context;
      Seq_Ctx : RFLX.Suback.Return_Code_List.Context;
      use type RFLX.Suback.Return_Code;
   begin
      Valid     := False;
      Packet_Id := 1;
      Code      := Failure;

      RFLX.Suback.Packet.Initialize (Pkt_Ctx, Buffer);
      RFLX.Suback.Packet.Verify_Message (Pkt_Ctx);
      if not RFLX.Suback.Packet.Well_Formed_Message (Pkt_Ctx) then
         RFLX.Suback.Packet.Take_Buffer (Pkt_Ctx, Buffer);
         return;
      end if;
      Packet_Id := RFLX.Suback.Packet.Get_Packet_Identifier (Pkt_Ctx);
      RFLX.Suback.Packet.Switch_To_Return_Codes (Pkt_Ctx, Seq_Ctx);
      if RFLX.Suback.Return_Code_List.Has_Element (Seq_Ctx) then
         declare
            Rc : constant RFLX.Suback.Return_Code :=
              RFLX.Suback.Return_Code_List.Head (Seq_Ctx);
         begin
            case Rc is
               when RFLX.Suback.SUCCESS_QOS_0 => Code := Granted_QoS_0;
               when RFLX.Suback.SUCCESS_QOS_1 => Code := Granted_QoS_1;
               when RFLX.Suback.SUCCESS_QOS_2 => Code := Granted_QoS_2;
               when RFLX.Suback.FAILURE       => Code := Failure;
            end case;
            Valid := True;
         end;
      end if;
      RFLX.Suback.Packet.Update_Return_Codes (Pkt_Ctx, Seq_Ctx);
      RFLX.Suback.Packet.Take_Buffer (Pkt_Ctx, Buffer);
   end Decode_Suback_Single;

   ---------------------------------------------------------------------
   --  Decode_Publish_Qos0
   ---------------------------------------------------------------------

   procedure Decode_Publish_Qos0
     (Buffer        : in out Bytes_Ptr;
      Valid         :    out Boolean;
      Topic         : in out String;
      Topic_Last    :    out Natural;
      Payload       : in out RFLX.RFLX_Types.Bytes;
      Payload_Last  :    out RFLX.RFLX_Types.Length)
   is
      Ctx : RFLX.Publish.Packet.Context;
   begin
      Valid        := False;
      Topic_Last   := Topic'First - 1;
      Payload_Last := 0;

      RFLX.Publish.Packet.Initialize (Ctx, Buffer);
      RFLX.Publish.Packet.Verify_Message (Ctx);
      if not RFLX.Publish.Packet.Well_Formed_Message (Ctx) then
         RFLX.Publish.Packet.Take_Buffer (Ctx, Buffer);
         return;
      end if;

      declare
         T_Bytes : constant RFLX.RFLX_Types.Bytes :=
           RFLX.Publish.Packet.Get_Topic_Name (Ctx);
         P_Bytes : constant RFLX.RFLX_Types.Bytes :=
           RFLX.Publish.Packet.Get_Payload (Ctx);
         T_Len   : constant Natural := T_Bytes'Length;
         P_Len   : constant Natural := P_Bytes'Length;
      begin
         if T_Len > Topic'Length or P_Len > Payload'Length then
            RFLX.Publish.Packet.Take_Buffer (Ctx, Buffer);
            return;
         end if;
         Topic_Last := Topic'First + T_Len - 1;
         for K in 0 .. T_Len - 1 loop
            Topic (Topic'First + K) :=
              Character'Val
                (Natural (T_Bytes (T_Bytes'First
                                   + RFLX.RFLX_Types.Index (K))));
         end loop;
         Payload_Last := RFLX.RFLX_Types.Length (P_Len);
         for K in 0 .. P_Len - 1 loop
            Payload (Payload'First + RFLX.RFLX_Types.Index (K)) :=
              P_Bytes (P_Bytes'First + RFLX.RFLX_Types.Index (K));
         end loop;
         Valid := True;
      end;
      RFLX.Publish.Packet.Take_Buffer (Ctx, Buffer);
   end Decode_Publish_Qos0;

   ---------------------------------------------------------------------
   --  Peek_Packet_Type
   ---------------------------------------------------------------------

   function Peek_Packet_Type
     (Buffer : RFLX.RFLX_Types.Bytes)
      return RFLX.Control_Packet.Packet_Type
   is
      Hi_Nibble : constant Natural :=
        Natural (Buffer (Buffer'First)) / 16;
   begin
      return RFLX.Control_Packet.Packet_Type'Enum_Val (Hi_Nibble);
   end Peek_Packet_Type;

end Mqtt_Core.Wire;
