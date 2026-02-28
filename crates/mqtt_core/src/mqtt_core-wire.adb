with RFLX.Control_Packet;
with RFLX.Pingreq.Packet;
with RFLX.Pingresp.Packet;
with RFLX.Disconnect.Packet;
with RFLX.Connack.Packet;
with RFLX.Connect.Packet;
with RFLX.Publish.Packet;
with RFLX.Puback.Packet;
with RFLX.Subscribe.Packet;
with RFLX.Subscribe.Subscription;
with RFLX.Subscribe.Subscription_List;
with RFLX.Suback.Packet;
with RFLX.Suback.Return_Code_List;
with RFLX.Unsubscribe.Packet;
with RFLX.Unsubscribe.Topic_Filter_List;
with RFLX.Unsuback.Packet;
with RFLX.Control_Packet.UTF8_String;

package body Mqtt_Core.Wire
with SPARK_Mode
is

   use type RFLX.RFLX_Types.Index;
   use type RFLX.RFLX_Types.Bit_Length;

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
      Last            : Index;
      Valid           :    out Boolean;
      Session_Present :    out Boolean;
      Code            :    out Return_Code)
   is
      Ctx : RFLX.Connack.Packet.Context;
   begin
      RFLX.Connack.Packet.Initialize
        (Ctx, Buffer,
         Written_Last => RFLX.RFLX_Types.Bit_Length (Last) * 8);
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
   --  Encode_Publish_Qos1
   --
   --  Like Qos0 but with QoS=1 in the flag nibble and a 16-bit Packet
   --  Identifier wedged between the Topic Name and the Payload (§3.3.2.2).
   ---------------------------------------------------------------------

   procedure Encode_Publish_Qos1
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Topic     : String;
      Payload   : RFLX.RFLX_Types.Bytes)
   is
      Ctx : RFLX.Publish.Packet.Context;
      RL  : constant RFLX.Publish.Remaining_Length :=
        RFLX.Publish.Remaining_Length
          (4 + Topic'Length + Payload'Length);
   begin
      RFLX.Publish.Packet.Initialize (Ctx, Buffer);
      RFLX.Publish.Packet.Set_Packet_Type
        (Ctx, RFLX.Control_Packet.PUBLISH);
      RFLX.Publish.Packet.Set_DUP    (Ctx, False);
      RFLX.Publish.Packet.Set_QoS    (Ctx, RFLX.Control_Packet.QOS_1);
      RFLX.Publish.Packet.Set_Retain (Ctx, 0);
      RFLX.Publish.Packet.Set_Remaining_Length (Ctx, RL);
      RFLX.Publish.Packet.Set_Topic_Name_Length
        (Ctx, RFLX.Control_Packet.String_Length (Topic'Length));
      RFLX.Publish.Packet.Set_Topic_Name (Ctx, To_Bytes (Topic));
      RFLX.Publish.Packet.Set_Packet_Identifier (Ctx, Packet_Id);
      if Payload'Length = 0 then
         RFLX.Publish.Packet.Set_Payload_Empty (Ctx);
      else
         RFLX.Publish.Packet.Set_Payload (Ctx, Payload);
      end if;
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Publish.Packet.Message_Last (Ctx));
      RFLX.Publish.Packet.Take_Buffer (Ctx, Buffer);
   end Encode_Publish_Qos1;

   ---------------------------------------------------------------------
   --  Decode_Puback
   ---------------------------------------------------------------------

   procedure Decode_Puback
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Packet_Id :    out Packet_Identifier)
   is
      Ctx : RFLX.Puback.Packet.Context;
   begin
      Valid     := False;
      Packet_Id := 1;

      RFLX.Puback.Packet.Initialize
        (Ctx, Buffer,
         Written_Last => RFLX.RFLX_Types.Bit_Length (Last) * 8);
      RFLX.Puback.Packet.Verify_Message (Ctx);
      if RFLX.Puback.Packet.Well_Formed_Message (Ctx) then
         Packet_Id := RFLX.Puback.Packet.Get_Packet_Identifier (Ctx);
         Valid     := True;
      end if;
      RFLX.Puback.Packet.Take_Buffer (Ctx, Buffer);
   end Decode_Puback;

   ---------------------------------------------------------------------
   --  Decode_Pingresp
   ---------------------------------------------------------------------

   procedure Decode_Pingresp
     (Buffer : in out Bytes_Ptr;
      Last   : Index;
      Valid  :    out Boolean)
   is
      Ctx : RFLX.Pingresp.Packet.Context;
   begin
      RFLX.Pingresp.Packet.Initialize
        (Ctx, Buffer,
         Written_Last => RFLX.RFLX_Types.Bit_Length (Last) * 8);
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
      Last      : Index;
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

      RFLX.Suback.Packet.Initialize
        (Pkt_Ctx, Buffer,
         Written_Last => RFLX.RFLX_Types.Bit_Length (Last) * 8);
      RFLX.Suback.Packet.Verify_Message (Pkt_Ctx);
      if not RFLX.Suback.Packet.Well_Formed_Message (Pkt_Ctx) then
         RFLX.Suback.Packet.Take_Buffer (Pkt_Ctx, Buffer);
         return;
      end if;
      Packet_Id := RFLX.Suback.Packet.Get_Packet_Identifier (Pkt_Ctx);
      RFLX.Suback.Packet.Switch_To_Return_Codes (Pkt_Ctx, Seq_Ctx);
      if RFLX.Suback.Return_Code_List.Has_Element (Seq_Ctx)
        and then RFLX.Suback.Return_Code_List.Valid_Element (Seq_Ctx)
      then
         RFLX.Suback.Return_Code_List.Next (Seq_Ctx);
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
   --  Encode_Unsubscribe_Single
   --
   --  Layout for one Topic Filter:
   --    fixed header: 0xA2 + RL (= 4 + Topic'Length, single varint byte)
   --    var header:   Packet Identifier (16-bit big-endian)
   --    payload:      Topic Filter length (16-bit) + Topic Filter bytes
   ---------------------------------------------------------------------

   procedure Encode_Unsubscribe_Single
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Topic     : String)
   is
      Pkt_Ctx  : RFLX.Unsubscribe.Packet.Context;
      Seq_Ctx  : RFLX.Unsubscribe.Topic_Filter_List.Context;
      Elem_Ctx : RFLX.Control_Packet.UTF8_String.Context;
      RL       : constant RFLX.Unsubscribe.Remaining_Length :=
        RFLX.Unsubscribe.Remaining_Length (4 + Topic'Length);
   begin
      RFLX.Unsubscribe.Packet.Initialize (Pkt_Ctx, Buffer);
      RFLX.Unsubscribe.Packet.Set_Packet_Type
        (Pkt_Ctx, RFLX.Control_Packet.UNSUBSCRIBE);
      RFLX.Unsubscribe.Packet.Set_Reserved (Pkt_Ctx, 2);
      RFLX.Unsubscribe.Packet.Set_Remaining_Length (Pkt_Ctx, RL);
      RFLX.Unsubscribe.Packet.Set_Packet_Identifier (Pkt_Ctx, Packet_Id);
      RFLX.Unsubscribe.Packet.Switch_To_Topic_Filters (Pkt_Ctx, Seq_Ctx);
      RFLX.Unsubscribe.Topic_Filter_List.Switch (Seq_Ctx, Elem_Ctx);
      RFLX.Control_Packet.UTF8_String.Set_Length
        (Elem_Ctx, RFLX.Control_Packet.String_Length (Topic'Length));
      RFLX.Control_Packet.UTF8_String.Set_Data (Elem_Ctx, To_Bytes (Topic));
      RFLX.Unsubscribe.Topic_Filter_List.Update (Seq_Ctx, Elem_Ctx);
      RFLX.Unsubscribe.Packet.Update_Topic_Filters (Pkt_Ctx, Seq_Ctx);
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Unsubscribe.Packet.Message_Last (Pkt_Ctx));
      RFLX.Unsubscribe.Packet.Take_Buffer (Pkt_Ctx, Buffer);
   end Encode_Unsubscribe_Single;

   ---------------------------------------------------------------------
   --  Decode_Unsuback
   ---------------------------------------------------------------------

   procedure Decode_Unsuback
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Packet_Id :    out Packet_Identifier)
   is
      Ctx : RFLX.Unsuback.Packet.Context;
   begin
      Valid     := False;
      Packet_Id := 1;

      RFLX.Unsuback.Packet.Initialize
        (Ctx, Buffer,
         Written_Last => RFLX.RFLX_Types.Bit_Length (Last) * 8);
      RFLX.Unsuback.Packet.Verify_Message (Ctx);
      if RFLX.Unsuback.Packet.Well_Formed_Message (Ctx) then
         Packet_Id := RFLX.Unsuback.Packet.Get_Packet_Identifier (Ctx);
         Valid     := True;
      end if;
      RFLX.Unsuback.Packet.Take_Buffer (Ctx, Buffer);
   end Decode_Unsuback;

   ---------------------------------------------------------------------
   --  Decode_Publish_Qos0
   ---------------------------------------------------------------------

   procedure Decode_Publish_Qos0
     (Buffer        : in out Bytes_Ptr;
      Last          : Index;
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

      RFLX.Publish.Packet.Initialize
        (Ctx, Buffer,
         Written_Last => RFLX.RFLX_Types.Bit_Length (Last) * 8);
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
         declare
            Src : RFLX.RFLX_Types.Index := T_Bytes'First;
            Dst : Natural               := Topic'First;
         begin
            while Dst <= Topic_Last loop
               Topic (Dst) :=
                 Character'Val (Natural (T_Bytes (Src)));
               exit when Dst = Topic_Last;
               Dst := Dst + 1;
               Src := Src + 1;
            end loop;
         end;
         Payload_Last := RFLX.RFLX_Types.Length (P_Len);
         if P_Len > 0 then
            declare
               Src : RFLX.RFLX_Types.Index := P_Bytes'First;
               Dst : RFLX.RFLX_Types.Index := Payload'First;
               Last_Dst : constant RFLX.RFLX_Types.Index :=
                 Payload'First + RFLX.RFLX_Types.Index (P_Len - 1);
            begin
               while Dst <= Last_Dst loop
                  Payload (Dst) := P_Bytes (Src);
                  exit when Dst = Last_Dst;
                  Dst := Dst + 1;
                  Src := Src + 1;
               end loop;
            end;
         end if;
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
