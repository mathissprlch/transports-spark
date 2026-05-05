with RFLX.Pingreq.Packet;
with RFLX.Pingresp.Packet;
with RFLX.Disconnect.Packet;
with RFLX.Connack.Packet;
with RFLX.Connect.Packet;
with RFLX.Publish.Packet;
with RFLX.Puback.Packet;
with RFLX.Pubrec.Packet;
with RFLX.Pubrel.Packet;
with RFLX.Pubcomp.Packet;
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
   use type RFLX.RFLX_Types.Length;
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
   --  Decode_Connect (broker side)
   ---------------------------------------------------------------------

   procedure Decode_Connect
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Client_Id : out String;
      Cid_Last  : out Natural;
      User_Name      : out String;
      User_Name_Last : out Natural;
      Password       : out RFLX.RFLX_Types.Bytes;
      Password_Last  : out Natural)
   is
      Ctx : RFLX.Connect.Packet.Context;
   begin
      Valid    := False;
      Client_Id := (others => ' ');
      Cid_Last := 0;
      User_Name := (others => ' ');
      User_Name_Last := 0;
      Password  := (others => 0);
      Password_Last  := 0;
      RFLX.Connect.Packet.Initialize
        (Ctx, Buffer,
         Written_Last => RFLX.RFLX_Types.Bit_Length (Last) * 8);
      RFLX.Connect.Packet.Verify_Message (Ctx);
      if RFLX.Connect.Packet.Well_Formed_Message (Ctx) then
         declare
            Cid_Bytes : RFLX.RFLX_Types.Bytes (1 .. 256) :=
              (others => 0);
            CL : constant Natural := Natural
              (RFLX.Connect.Packet.Get_Client_Id_Length (Ctx));
         begin
            if CL > 0 and then CL <= Client_Id'Length
              and then CL <= Cid_Bytes'Length
            then
               RFLX.Connect.Packet.Get_Client_Id
                 (Ctx, Cid_Bytes (1 .. RFLX.RFLX_Types.Index (CL)));
               for I in 1 .. CL loop
                  Client_Id (Client_Id'First + I - 1) :=
                    Character'Val (Natural (Cid_Bytes
                      (RFLX.RFLX_Types.Index (I))));
               end loop;
               Cid_Last := CL;
               Valid := True;
            end if;
         end;

         --  §3.1.3.4 / §3.1.3.5 — username + password are present
         --  only when the corresponding flag in §3.1.2.8/9 is set.
         --  Section 3.1.2.9 also stipulates Password_Flag=1 implies
         --  User_Name_Flag=1; we honor RFLX's parse-time enforcement
         --  rather than re-checking here.
         if Valid
           and then RFLX.Connect.Packet.Get_User_Name_Flag (Ctx)
         then
            declare
               UL : constant Natural := Natural
                 (RFLX.Connect.Packet.Get_User_Name_Length (Ctx));
               U_Bytes : RFLX.RFLX_Types.Bytes (1 .. 256) :=
                 (others => 0);
            begin
               if UL > 0 and then UL <= User_Name'Length
                 and then UL <= U_Bytes'Length
               then
                  RFLX.Connect.Packet.Get_User_Name
                    (Ctx, U_Bytes (1 .. RFLX.RFLX_Types.Index (UL)));
                  for I in 1 .. UL loop
                     User_Name (User_Name'First + I - 1) :=
                       Character'Val (Natural (U_Bytes
                         (RFLX.RFLX_Types.Index (I))));
                  end loop;
                  User_Name_Last := UL;
               end if;
            end;
         end if;

         if Valid
           and then RFLX.Connect.Packet.Get_Password_Flag (Ctx)
         then
            declare
               PL : constant Natural := Natural
                 (RFLX.Connect.Packet.Get_Password_Length (Ctx));
            begin
               if PL > 0 and then PL <= Password'Length then
                  RFLX.Connect.Packet.Get_Password
                    (Ctx, Password
                       (Password'First
                        .. Password'First
                           + RFLX.RFLX_Types.Index (PL) - 1));
                  Password_Last := PL;
               end if;
            end;
         end if;
      end if;
      RFLX.Connect.Packet.Take_Buffer (Ctx, Buffer);
   end Decode_Connect;

   ---------------------------------------------------------------------
   --  Encode_Connack (broker side)
   ---------------------------------------------------------------------

   procedure Encode_Connack
     (Buffer          : in out Bytes_Ptr;
      Last            :    out Index;
      Session_Present : Boolean := False;
      Return_Code     : RFLX.Connack.Connect_Return_Code :=
                          RFLX.Connack.ACCEPTED)
   is
      Ctx : RFLX.Connack.Packet.Context;
   begin
      RFLX.Connack.Packet.Initialize (Ctx, Buffer);
      RFLX.Connack.Packet.Set_Packet_Type
        (Ctx, RFLX.Control_Packet.CONNACK);
      RFLX.Connack.Packet.Set_Reserved (Ctx, 0);
      RFLX.Connack.Packet.Set_Remaining_Length (Ctx, 2);
      RFLX.Connack.Packet.Set_Reserved_Ack_Flags (Ctx, 0);
      RFLX.Connack.Packet.Set_Session_Present (Ctx, Session_Present);
      RFLX.Connack.Packet.Set_Return_Code (Ctx, Return_Code);
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Connack.Packet.Message_Last (Ctx));
      RFLX.Connack.Packet.Take_Buffer (Ctx, Buffer);
   end Encode_Connack;

   ---------------------------------------------------------------------
   --  Encode_Publish_Qos0
   ---------------------------------------------------------------------

   procedure Encode_Publish_Qos0
     (Buffer  : in out Bytes_Ptr;
      Last    :    out Index;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes;
      Retain  : Boolean := False)
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
      RFLX.Publish.Packet.Set_Retain (Ctx, (if Retain then 1 else 0));
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
      Payload   : RFLX.RFLX_Types.Bytes;
      Retain    : Boolean := False)
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
      RFLX.Publish.Packet.Set_Retain (Ctx, (if Retain then 1 else 0));
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
   --  Encode_Publish_Qos2
   ---------------------------------------------------------------------

   procedure Encode_Publish_Qos2
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Topic     : String;
      Payload   : RFLX.RFLX_Types.Bytes;
      Retain    : Boolean := False)
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
      RFLX.Publish.Packet.Set_QoS    (Ctx, RFLX.Control_Packet.QOS_2);
      RFLX.Publish.Packet.Set_Retain (Ctx, (if Retain then 1 else 0));
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
   end Encode_Publish_Qos2;

   ---------------------------------------------------------------------
   --  Decode_Pubrec
   ---------------------------------------------------------------------

   procedure Decode_Pubrec
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Packet_Id :    out Packet_Identifier)
   is
      Ctx : RFLX.Pubrec.Packet.Context;
   begin
      Valid     := False;
      Packet_Id := 1;

      RFLX.Pubrec.Packet.Initialize
        (Ctx, Buffer,
         Written_Last => RFLX.RFLX_Types.Bit_Length (Last) * 8);
      RFLX.Pubrec.Packet.Verify_Message (Ctx);
      if RFLX.Pubrec.Packet.Well_Formed_Message (Ctx) then
         Packet_Id := RFLX.Pubrec.Packet.Get_Packet_Identifier (Ctx);
         Valid     := True;
      end if;
      RFLX.Pubrec.Packet.Take_Buffer (Ctx, Buffer);
   end Decode_Pubrec;

   ---------------------------------------------------------------------
   --  Encode_Pubrec
   ---------------------------------------------------------------------

   procedure Encode_Pubrec
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier)
   is
      Ctx : RFLX.Pubrec.Packet.Context;
   begin
      RFLX.Pubrec.Packet.Initialize (Ctx, Buffer);
      RFLX.Pubrec.Packet.Set_Packet_Type
        (Ctx, RFLX.Control_Packet.PUBREC);
      RFLX.Pubrec.Packet.Set_Reserved (Ctx, 0);
      RFLX.Pubrec.Packet.Set_Remaining_Length (Ctx, 2);
      RFLX.Pubrec.Packet.Set_Packet_Identifier (Ctx, Packet_Id);
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Pubrec.Packet.Message_Last (Ctx));
      RFLX.Pubrec.Packet.Take_Buffer (Ctx, Buffer);
   end Encode_Pubrec;

   ---------------------------------------------------------------------
   --  Encode_Pubrel
   ---------------------------------------------------------------------

   procedure Encode_Pubrel
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier)
   is
      Ctx : RFLX.Pubrel.Packet.Context;
   begin
      RFLX.Pubrel.Packet.Initialize (Ctx, Buffer);
      RFLX.Pubrel.Packet.Set_Packet_Type
        (Ctx, RFLX.Control_Packet.PUBREL);
      RFLX.Pubrel.Packet.Set_Reserved (Ctx, 2);
      RFLX.Pubrel.Packet.Set_Remaining_Length (Ctx, 2);
      RFLX.Pubrel.Packet.Set_Packet_Identifier (Ctx, Packet_Id);
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Pubrel.Packet.Message_Last (Ctx));
      RFLX.Pubrel.Packet.Take_Buffer (Ctx, Buffer);
   end Encode_Pubrel;

   ---------------------------------------------------------------------
   --  Decode_Pubrel
   ---------------------------------------------------------------------

   procedure Decode_Pubrel
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Packet_Id :    out Packet_Identifier)
   is
      Ctx : RFLX.Pubrel.Packet.Context;
   begin
      Valid     := False;
      Packet_Id := 1;

      RFLX.Pubrel.Packet.Initialize
        (Ctx, Buffer,
         Written_Last => RFLX.RFLX_Types.Bit_Length (Last) * 8);
      RFLX.Pubrel.Packet.Verify_Message (Ctx);
      if RFLX.Pubrel.Packet.Well_Formed_Message (Ctx) then
         Packet_Id := RFLX.Pubrel.Packet.Get_Packet_Identifier (Ctx);
         Valid     := True;
      end if;
      RFLX.Pubrel.Packet.Take_Buffer (Ctx, Buffer);
   end Decode_Pubrel;

   ---------------------------------------------------------------------
   --  Encode_Pubcomp
   ---------------------------------------------------------------------

   procedure Encode_Pubcomp
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier)
   is
      Ctx : RFLX.Pubcomp.Packet.Context;
   begin
      RFLX.Pubcomp.Packet.Initialize (Ctx, Buffer);
      RFLX.Pubcomp.Packet.Set_Packet_Type
        (Ctx, RFLX.Control_Packet.PUBCOMP);
      RFLX.Pubcomp.Packet.Set_Reserved (Ctx, 0);
      RFLX.Pubcomp.Packet.Set_Remaining_Length (Ctx, 2);
      RFLX.Pubcomp.Packet.Set_Packet_Identifier (Ctx, Packet_Id);
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Pubcomp.Packet.Message_Last (Ctx));
      RFLX.Pubcomp.Packet.Take_Buffer (Ctx, Buffer);
   end Encode_Pubcomp;

   ---------------------------------------------------------------------
   --  Decode_Pubcomp
   ---------------------------------------------------------------------

   procedure Decode_Pubcomp
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Packet_Id :    out Packet_Identifier)
   is
      Ctx : RFLX.Pubcomp.Packet.Context;
   begin
      Valid     := False;
      Packet_Id := 1;

      RFLX.Pubcomp.Packet.Initialize
        (Ctx, Buffer,
         Written_Last => RFLX.RFLX_Types.Bit_Length (Last) * 8);
      RFLX.Pubcomp.Packet.Verify_Message (Ctx);
      if RFLX.Pubcomp.Packet.Well_Formed_Message (Ctx) then
         Packet_Id := RFLX.Pubcomp.Packet.Get_Packet_Identifier (Ctx);
         Valid     := True;
      end if;
      RFLX.Pubcomp.Packet.Take_Buffer (Ctx, Buffer);
   end Decode_Pubcomp;

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
   --  Encode_Puback
   ---------------------------------------------------------------------

   procedure Encode_Puback
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier)
   is
      Ctx : RFLX.Puback.Packet.Context;
   begin
      RFLX.Puback.Packet.Initialize (Ctx, Buffer);
      RFLX.Puback.Packet.Set_Packet_Type
        (Ctx, RFLX.Control_Packet.PUBACK);
      RFLX.Puback.Packet.Set_Reserved (Ctx, 0);
      RFLX.Puback.Packet.Set_Remaining_Length (Ctx, 2);
      RFLX.Puback.Packet.Set_Packet_Identifier (Ctx, Packet_Id);
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Puback.Packet.Message_Last (Ctx));
      RFLX.Puback.Packet.Take_Buffer (Ctx, Buffer);
   end Encode_Puback;

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
   --  Make_Subscription / Make_Topic_Filter
   ---------------------------------------------------------------------

   function Make_Subscription
     (Topic : String;
      QoS   : QoS_Level := RFLX.Control_Packet.QOS_0)
      return Subscription_Filter
   is
      Result : Subscription_Filter;
   begin
      Result.Topic (1 .. Topic'Length) := Topic;
      Result.Topic_Last                := Topic'Length;
      Result.QoS                       := QoS;
      return Result;
   end Make_Subscription;

   function Make_Topic_Filter (Topic : String) return Topic_Filter is
      Result : Topic_Filter;
   begin
      Result.Topic (1 .. Topic'Length) := Topic;
      Result.Topic_Last                := Topic'Length;
      return Result;
   end Make_Topic_Filter;

   ---------------------------------------------------------------------
   --  Encode_Subscribe (multi-topic)
   --
   --  Layout per filter:
   --    Topic Filter length (16-bit) + Topic_Filter bytes
   --    + Requested QoS byte (high 6 bits = 0)
   --
   --  Each loop iteration calls Switch on the sequence to obtain a
   --  fresh element context, populates it, and Update returns the
   --  buffer to the sequence. Per RFLX_Message_Sequence post-
   --  conditions, Sequence_Last advances by Element_Size each cycle,
   --  so subsequent Switch calls write at the next free position.
   ---------------------------------------------------------------------

   procedure Encode_Subscribe
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Filters   : Subscription_Filters)
   is
      Pkt_Ctx  : RFLX.Subscribe.Packet.Context;
      Seq_Ctx  : RFLX.Subscribe.Subscription_List.Context;
      Elem_Ctx : RFLX.Subscribe.Subscription.Context;
      Total    : Natural := 2;  --  Packet Identifier
   begin
      for F of Filters loop
         Total := Total + 3 + F.Topic_Last;
      end loop;

      RFLX.Subscribe.Packet.Initialize (Pkt_Ctx, Buffer);
      RFLX.Subscribe.Packet.Set_Packet_Type
        (Pkt_Ctx, RFLX.Control_Packet.SUBSCRIBE);
      RFLX.Subscribe.Packet.Set_Reserved (Pkt_Ctx, 2);
      RFLX.Subscribe.Packet.Set_Remaining_Length
        (Pkt_Ctx, RFLX.Subscribe.Remaining_Length (Total));
      RFLX.Subscribe.Packet.Set_Packet_Identifier (Pkt_Ctx, Packet_Id);
      RFLX.Subscribe.Packet.Switch_To_Subscriptions (Pkt_Ctx, Seq_Ctx);
      for F of Filters loop
         RFLX.Subscribe.Subscription_List.Switch (Seq_Ctx, Elem_Ctx);
         RFLX.Subscribe.Subscription.Set_Topic_Filter_Length
           (Elem_Ctx, RFLX.Control_Packet.String_Length (F.Topic_Last));
         RFLX.Subscribe.Subscription.Set_Topic_Filter
           (Elem_Ctx, To_Bytes (F.Topic (1 .. F.Topic_Last)));
         RFLX.Subscribe.Subscription.Set_Reserved_Sub_QoS (Elem_Ctx, 0);
         RFLX.Subscribe.Subscription.Set_Requested_QoS (Elem_Ctx, F.QoS);
         RFLX.Subscribe.Subscription_List.Update (Seq_Ctx, Elem_Ctx);
      end loop;
      RFLX.Subscribe.Packet.Update_Subscriptions (Pkt_Ctx, Seq_Ctx);
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Subscribe.Packet.Message_Last (Pkt_Ctx));
      RFLX.Subscribe.Packet.Take_Buffer (Pkt_Ctx, Buffer);
   end Encode_Subscribe;

   ---------------------------------------------------------------------
   --  Decode_Subscribe (broker side, single-filter only for v0.2)
   ---------------------------------------------------------------------

   procedure Decode_Subscribe
     (Buffer       : in out Bytes_Ptr;
      Last         : Index;
      Valid        :    out Boolean;
      Packet_Id    :    out Packet_Identifier;
      Topic_Filter : out String;
      Filter_Last  : out Natural;
      Requested_QoS : out RFLX.Control_Packet.QoS_Level)
   is
      Pkt_Ctx  : RFLX.Subscribe.Packet.Context;
      Seq_Ctx  : RFLX.Subscribe.Subscription_List.Context;
      Elem_Ctx : RFLX.Subscribe.Subscription.Context;
   begin
      Valid         := False;
      Packet_Id     := 1;
      Topic_Filter  := (others => ' ');
      Filter_Last   := 0;
      Requested_QoS := RFLX.Control_Packet.QOS_0;

      RFLX.Subscribe.Packet.Initialize
        (Pkt_Ctx, Buffer,
         Written_Last => RFLX.RFLX_Types.Bit_Length (Last) * 8);
      RFLX.Subscribe.Packet.Verify_Message (Pkt_Ctx);
      if not RFLX.Subscribe.Packet.Well_Formed_Message (Pkt_Ctx) then
         RFLX.Subscribe.Packet.Take_Buffer (Pkt_Ctx, Buffer);
         return;
      end if;
      Packet_Id := RFLX.Subscribe.Packet.Get_Packet_Identifier (Pkt_Ctx);
      RFLX.Subscribe.Packet.Switch_To_Subscriptions (Pkt_Ctx, Seq_Ctx);

      if RFLX.Subscribe.Subscription_List.Has_Element (Seq_Ctx) then
         RFLX.Subscribe.Subscription_List.Switch (Seq_Ctx, Elem_Ctx);
         RFLX.Subscribe.Subscription.Verify_Message (Elem_Ctx);
         if RFLX.Subscribe.Subscription.Well_Formed_Message (Elem_Ctx) then
            declare
               TL : constant Natural := Natural
                 (RFLX.Subscribe.Subscription.Get_Topic_Filter_Length
                    (Elem_Ctx));
               Topic_Bytes : RFLX.RFLX_Types.Bytes (1 .. 256) :=
                 (others => 0);
            begin
               if TL > 0 and then TL <= Topic_Filter'Length
                 and then TL <= Topic_Bytes'Length
               then
                  RFLX.Subscribe.Subscription.Get_Topic_Filter
                    (Elem_Ctx,
                     Topic_Bytes (1 .. RFLX.RFLX_Types.Index (TL)));
                  for I in 1 .. TL loop
                     Topic_Filter (Topic_Filter'First + I - 1) :=
                       Character'Val (Natural (Topic_Bytes
                         (RFLX.RFLX_Types.Index (I))));
                  end loop;
                  Filter_Last := TL;
                  Requested_QoS :=
                    RFLX.Subscribe.Subscription.Get_Requested_QoS
                      (Elem_Ctx);
                  Valid := True;
               end if;
            end;
         end if;
         RFLX.Subscribe.Subscription_List.Update
           (Seq_Ctx, Elem_Ctx);
      end if;

      RFLX.Subscribe.Packet.Update_Subscriptions (Pkt_Ctx, Seq_Ctx);
      RFLX.Subscribe.Packet.Take_Buffer (Pkt_Ctx, Buffer);
   end Decode_Subscribe;

   ---------------------------------------------------------------------
   --  Decode_Subscribe_Filters — multi-filter version. Iterates the
   --  Subscription_List up to the caller-supplied array length.
   ---------------------------------------------------------------------

   procedure Decode_Subscribe_Filters
     (Buffer       : in out Bytes_Ptr;
      Last         : Index;
      Valid        :    out Boolean;
      Packet_Id    :    out Packet_Identifier;
      Filter_Topics : out Filter_Topic_Array;
      Filter_Lasts  : out Filter_Last_Array;
      Filter_QoS    : out Filter_QoS_Array;
      Filter_Count  : out Natural)
   is
      Pkt_Ctx  : RFLX.Subscribe.Packet.Context;
      Seq_Ctx  : RFLX.Subscribe.Subscription_List.Context;
      Elem_Ctx : RFLX.Subscribe.Subscription.Context;
   begin
      Valid := False;
      Packet_Id := 1;
      Filter_Topics := (others => (others => ' '));
      Filter_Lasts := (others => 0);
      Filter_QoS := (others => RFLX.Control_Packet.QOS_0);
      Filter_Count := 0;

      RFLX.Subscribe.Packet.Initialize
        (Pkt_Ctx, Buffer,
         Written_Last => RFLX.RFLX_Types.Bit_Length (Last) * 8);
      RFLX.Subscribe.Packet.Verify_Message (Pkt_Ctx);
      if not RFLX.Subscribe.Packet.Well_Formed_Message (Pkt_Ctx) then
         RFLX.Subscribe.Packet.Take_Buffer (Pkt_Ctx, Buffer);
         return;
      end if;
      Packet_Id := RFLX.Subscribe.Packet.Get_Packet_Identifier (Pkt_Ctx);
      RFLX.Subscribe.Packet.Switch_To_Subscriptions (Pkt_Ctx, Seq_Ctx);

      while RFLX.Subscribe.Subscription_List.Has_Element (Seq_Ctx)
        and then Filter_Count < Filter_Topics'Length
      loop
         RFLX.Subscribe.Subscription_List.Switch (Seq_Ctx, Elem_Ctx);
         RFLX.Subscribe.Subscription.Verify_Message (Elem_Ctx);
         if RFLX.Subscribe.Subscription.Well_Formed_Message (Elem_Ctx) then
            declare
               TL : constant Natural := Natural
                 (RFLX.Subscribe.Subscription.Get_Topic_Filter_Length
                    (Elem_Ctx));
               Topic_Bytes : RFLX.RFLX_Types.Bytes (1 .. 256) :=
                 (others => 0);
               Slot : constant Positive :=
                 Filter_Topics'First + Filter_Count;
            begin
               if TL > 0 and then TL <= 256 then
                  RFLX.Subscribe.Subscription.Get_Topic_Filter
                    (Elem_Ctx,
                     Topic_Bytes (1 .. RFLX.RFLX_Types.Index (TL)));
                  for I in 1 .. TL loop
                     Filter_Topics (Slot) (I) :=
                       Character'Val (Natural (Topic_Bytes
                         (RFLX.RFLX_Types.Index (I))));
                  end loop;
                  Filter_Lasts (Slot) := TL;
                  Filter_QoS (Slot) :=
                    RFLX.Subscribe.Subscription.Get_Requested_QoS
                      (Elem_Ctx);
                  Filter_Count := Filter_Count + 1;
               end if;
            end;
         end if;
         RFLX.Subscribe.Subscription_List.Update (Seq_Ctx, Elem_Ctx);
      end loop;

      Valid := Filter_Count > 0;

      RFLX.Subscribe.Packet.Update_Subscriptions (Pkt_Ctx, Seq_Ctx);
      RFLX.Subscribe.Packet.Take_Buffer (Pkt_Ctx, Buffer);
   end Decode_Subscribe_Filters;

   ---------------------------------------------------------------------
   --  Encode_Suback (multi return code)
   ---------------------------------------------------------------------

   procedure Encode_Suback
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Codes     : Suback_Wire_Codes)
   is
      Pkt_Ctx : RFLX.Suback.Packet.Context;
      Seq_Ctx : RFLX.Suback.Return_Code_List.Context;
   begin
      RFLX.Suback.Packet.Initialize (Pkt_Ctx, Buffer);
      RFLX.Suback.Packet.Set_Packet_Type
        (Pkt_Ctx, RFLX.Control_Packet.SUBACK);
      RFLX.Suback.Packet.Set_Reserved (Pkt_Ctx, 0);
      RFLX.Suback.Packet.Set_Remaining_Length
        (Pkt_Ctx, RFLX.Suback.Remaining_Length (2 + Codes'Length));
      RFLX.Suback.Packet.Set_Packet_Identifier (Pkt_Ctx, Packet_Id);
      RFLX.Suback.Packet.Switch_To_Return_Codes (Pkt_Ctx, Seq_Ctx);
      for I in Codes'Range loop
         RFLX.Suback.Return_Code_List.Append_Element
           (Seq_Ctx, Codes (I));
      end loop;
      RFLX.Suback.Packet.Update_Return_Codes (Pkt_Ctx, Seq_Ctx);
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Suback.Packet.Message_Last (Pkt_Ctx));
      RFLX.Suback.Packet.Take_Buffer (Pkt_Ctx, Buffer);
   end Encode_Suback;

   ---------------------------------------------------------------------
   --  Encode_Suback_Single (broker side)
   ---------------------------------------------------------------------

   procedure Encode_Suback_Single
     (Buffer      : in out Bytes_Ptr;
      Last        :    out Index;
      Packet_Id   : Packet_Identifier;
      Granted_QoS : RFLX.Suback.Return_Code := RFLX.Suback.SUCCESS_QOS_0)
   is
      Pkt_Ctx  : RFLX.Suback.Packet.Context;
      Seq_Ctx  : RFLX.Suback.Return_Code_List.Context;
   begin
      RFLX.Suback.Packet.Initialize (Pkt_Ctx, Buffer);
      RFLX.Suback.Packet.Set_Packet_Type
        (Pkt_Ctx, RFLX.Control_Packet.SUBACK);
      RFLX.Suback.Packet.Set_Reserved (Pkt_Ctx, 0);
      --  RL = 2 (packet id) + 1 (one return code)
      RFLX.Suback.Packet.Set_Remaining_Length (Pkt_Ctx, 3);
      RFLX.Suback.Packet.Set_Packet_Identifier (Pkt_Ctx, Packet_Id);
      RFLX.Suback.Packet.Switch_To_Return_Codes (Pkt_Ctx, Seq_Ctx);
      RFLX.Suback.Return_Code_List.Append_Element (Seq_Ctx, Granted_QoS);
      RFLX.Suback.Packet.Update_Return_Codes (Pkt_Ctx, Seq_Ctx);
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Suback.Packet.Message_Last (Pkt_Ctx));
      RFLX.Suback.Packet.Take_Buffer (Pkt_Ctx, Buffer);
   end Encode_Suback_Single;

   ---------------------------------------------------------------------
   --  Encode_Pingresp (broker side)
   ---------------------------------------------------------------------

   procedure Encode_Pingresp
     (Buffer : in out Bytes_Ptr;
      Last   :    out Index)
   is
      Ctx : RFLX.Pingresp.Packet.Context;
   begin
      RFLX.Pingresp.Packet.Initialize (Ctx, Buffer);
      RFLX.Pingresp.Packet.Set_Packet_Type
        (Ctx, RFLX.Control_Packet.PINGRESP);
      RFLX.Pingresp.Packet.Set_Reserved (Ctx, 0);
      RFLX.Pingresp.Packet.Set_Remaining_Length (Ctx, 0);
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Pingresp.Packet.Message_Last (Ctx));
      RFLX.Pingresp.Packet.Take_Buffer (Ctx, Buffer);
   end Encode_Pingresp;

   ---------------------------------------------------------------------
   --  Decode_Unsubscribe_Pid (broker side)
   ---------------------------------------------------------------------

   procedure Decode_Unsubscribe_Pid
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Packet_Id : out Packet_Identifier)
   is
      Ctx : RFLX.Unsubscribe.Packet.Context;
   begin
      Valid     := False;
      Packet_Id := 1;
      RFLX.Unsubscribe.Packet.Initialize
        (Ctx, Buffer,
         Written_Last => RFLX.RFLX_Types.Bit_Length (Last) * 8);
      RFLX.Unsubscribe.Packet.Verify_Message (Ctx);
      if RFLX.Unsubscribe.Packet.Well_Formed_Message (Ctx) then
         Packet_Id :=
           RFLX.Unsubscribe.Packet.Get_Packet_Identifier (Ctx);
         Valid := True;
      end if;
      RFLX.Unsubscribe.Packet.Take_Buffer (Ctx, Buffer);
   end Decode_Unsubscribe_Pid;

   ---------------------------------------------------------------------
   --  Encode_Unsuback (broker side)
   ---------------------------------------------------------------------

   procedure Encode_Unsuback
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier)
   is
      Ctx : RFLX.Unsuback.Packet.Context;
   begin
      RFLX.Unsuback.Packet.Initialize (Ctx, Buffer);
      RFLX.Unsuback.Packet.Set_Packet_Type
        (Ctx, RFLX.Control_Packet.UNSUBACK);
      RFLX.Unsuback.Packet.Set_Reserved (Ctx, 0);
      RFLX.Unsuback.Packet.Set_Remaining_Length (Ctx, 2);
      RFLX.Unsuback.Packet.Set_Packet_Identifier (Ctx, Packet_Id);
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Unsuback.Packet.Message_Last (Ctx));
      RFLX.Unsuback.Packet.Take_Buffer (Ctx, Buffer);
   end Encode_Unsuback;

   ---------------------------------------------------------------------
   --  Encode_Subscribe_Single — wraps Encode_Subscribe.
   ---------------------------------------------------------------------

   procedure Encode_Subscribe_Single
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Topic     : String;
      QoS       : QoS_Level := RFLX.Control_Packet.QOS_0)
   is
      Filters : constant Subscription_Filters (1 .. 1) :=
        (1 => Make_Subscription (Topic, QoS));
   begin
      Encode_Subscribe (Buffer, Last, Packet_Id, Filters);
   end Encode_Subscribe_Single;

   ---------------------------------------------------------------------
   --  Decode_Suback (multi return code)
   ---------------------------------------------------------------------

   procedure Decode_Suback
     (Buffer     : in out Bytes_Ptr;
      Last       : Index;
      Valid      :    out Boolean;
      Packet_Id  :    out Packet_Identifier;
      Codes      : in out Suback_Code_Array;
      Codes_Last :    out Natural)
   is
      Pkt_Ctx : RFLX.Suback.Packet.Context;
      Seq_Ctx : RFLX.Suback.Return_Code_List.Context;
      Idx     : Natural := Codes'First - 1;
      use type RFLX.Suback.Return_Code;
   begin
      Valid      := False;
      Packet_Id  := 1;
      Codes_Last := Codes'First - 1;

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
      while RFLX.Suback.Return_Code_List.Has_Element (Seq_Ctx)
        and then RFLX.Suback.Return_Code_List.Valid_Element (Seq_Ctx)
        and then Idx < Codes'Last
      loop
         RFLX.Suback.Return_Code_List.Next (Seq_Ctx);
         Idx := Idx + 1;
         declare
            Rc : constant RFLX.Suback.Return_Code :=
              RFLX.Suback.Return_Code_List.Head (Seq_Ctx);
         begin
            case Rc is
               when RFLX.Suback.SUCCESS_QOS_0 => Codes (Idx) := Granted_QoS_0;
               when RFLX.Suback.SUCCESS_QOS_1 => Codes (Idx) := Granted_QoS_1;
               when RFLX.Suback.SUCCESS_QOS_2 => Codes (Idx) := Granted_QoS_2;
               when RFLX.Suback.FAILURE       => Codes (Idx) := Failure;
            end case;
         end;
      end loop;
      Codes_Last := Idx;
      Valid      := Idx >= Codes'First;
      RFLX.Suback.Packet.Update_Return_Codes (Pkt_Ctx, Seq_Ctx);
      RFLX.Suback.Packet.Take_Buffer (Pkt_Ctx, Buffer);
   end Decode_Suback;

   ---------------------------------------------------------------------
   --  Decode_Suback_Single — wraps Decode_Suback.
   ---------------------------------------------------------------------

   procedure Decode_Suback_Single
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Packet_Id :    out Packet_Identifier;
      Code      :    out Suback_Return_Code)
   is
      Codes      : Suback_Code_Array (1 .. 1) := (1 => Failure);
      Codes_Last : Natural;
   begin
      Decode_Suback (Buffer, Last, Valid, Packet_Id, Codes, Codes_Last);
      if Valid and then Codes_Last >= Codes'First then
         Code := Codes (Codes'First);
      else
         Code  := Failure;
         Valid := False;
      end if;
   end Decode_Suback_Single;

   ---------------------------------------------------------------------
   --  Encode_Unsubscribe (multi-topic)
   --
   --  Layout per filter: 16-bit length prefix + Topic Filter bytes.
   ---------------------------------------------------------------------

   procedure Encode_Unsubscribe
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Filters   : Topic_Filters)
   is
      Pkt_Ctx  : RFLX.Unsubscribe.Packet.Context;
      Seq_Ctx  : RFLX.Unsubscribe.Topic_Filter_List.Context;
      Elem_Ctx : RFLX.Control_Packet.UTF8_String.Context;
      Total    : Natural := 2;  --  Packet Identifier
   begin
      for F of Filters loop
         Total := Total + 2 + F.Topic_Last;
      end loop;

      RFLX.Unsubscribe.Packet.Initialize (Pkt_Ctx, Buffer);
      RFLX.Unsubscribe.Packet.Set_Packet_Type
        (Pkt_Ctx, RFLX.Control_Packet.UNSUBSCRIBE);
      RFLX.Unsubscribe.Packet.Set_Reserved (Pkt_Ctx, 2);
      RFLX.Unsubscribe.Packet.Set_Remaining_Length
        (Pkt_Ctx, RFLX.Unsubscribe.Remaining_Length (Total));
      RFLX.Unsubscribe.Packet.Set_Packet_Identifier (Pkt_Ctx, Packet_Id);
      RFLX.Unsubscribe.Packet.Switch_To_Topic_Filters (Pkt_Ctx, Seq_Ctx);
      for F of Filters loop
         RFLX.Unsubscribe.Topic_Filter_List.Switch (Seq_Ctx, Elem_Ctx);
         RFLX.Control_Packet.UTF8_String.Set_Length
           (Elem_Ctx,
            RFLX.Control_Packet.String_Length (F.Topic_Last));
         RFLX.Control_Packet.UTF8_String.Set_Data
           (Elem_Ctx, To_Bytes (F.Topic (1 .. F.Topic_Last)));
         RFLX.Unsubscribe.Topic_Filter_List.Update (Seq_Ctx, Elem_Ctx);
      end loop;
      RFLX.Unsubscribe.Packet.Update_Topic_Filters (Pkt_Ctx, Seq_Ctx);
      Last := RFLX.RFLX_Types.To_Index
        (RFLX.Unsubscribe.Packet.Message_Last (Pkt_Ctx));
      RFLX.Unsubscribe.Packet.Take_Buffer (Pkt_Ctx, Buffer);
   end Encode_Unsubscribe;

   ---------------------------------------------------------------------
   --  Encode_Unsubscribe_Single — wraps Encode_Unsubscribe.
   ---------------------------------------------------------------------

   procedure Encode_Unsubscribe_Single
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Topic     : String)
   is
      Filters : constant Topic_Filters (1 .. 1) :=
        (1 => Make_Topic_Filter (Topic));
   begin
      Encode_Unsubscribe (Buffer, Last, Packet_Id, Filters);
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
   --  Decode_Publish
   --
   --  Single decoder that handles every QoS level the spec admits
   --  (QoS 0/1/2 — value 3 is rejected at parse time by the
   --  Control_Packet::QoS_Level enum). The Packet Identifier link in
   --  publish.rflx is conditional on QoS > 0, so we only call
   --  Get_Packet_Identifier when QoS /= QOS_0; otherwise the field is
   --  absent from the message structure and Get_* would fail its
   --  precondition.
   ---------------------------------------------------------------------

   procedure Decode_Publish
     (Buffer       : in out Bytes_Ptr;
      Last         : Index;
      Valid        :    out Boolean;
      QoS          :    out QoS_Level;
      Packet_Id    :    out Packet_Identifier;
      Topic        : in out String;
      Topic_Last   :    out Natural;
      Payload      : in out RFLX.RFLX_Types.Bytes;
      Payload_Last :    out RFLX.RFLX_Types.Length;
      Retain       :    out Boolean)
   is
      Ctx : RFLX.Publish.Packet.Context;
      use type RFLX.Control_Packet.QoS_Level;
      use type RFLX.Publish.Retain_Flag;
   begin
      Valid        := False;
      QoS          := RFLX.Control_Packet.QOS_0;
      Packet_Id    := 1;
      Topic_Last   := Topic'First - 1;
      Payload_Last := 0;
      Retain       := False;

      RFLX.Publish.Packet.Initialize
        (Ctx, Buffer,
         Written_Last => RFLX.RFLX_Types.Bit_Length (Last) * 8);
      RFLX.Publish.Packet.Verify_Message (Ctx);
      if not RFLX.Publish.Packet.Well_Formed_Message (Ctx) then
         RFLX.Publish.Packet.Take_Buffer (Ctx, Buffer);
         return;
      end if;

      QoS := RFLX.Publish.Packet.Get_QoS (Ctx);
      if QoS /= RFLX.Control_Packet.QOS_0 then
         Packet_Id := RFLX.Publish.Packet.Get_Packet_Identifier (Ctx);
      end if;
      Retain := RFLX.Publish.Packet.Get_Retain (Ctx) = 1;

      --  The function-form Get_Topic_Name / Get_Payload are Ghost in
      --  the generated spec; SPARK rejects them in non-Ghost code.
      --  Use the procedure form which fills a caller-sized buffer.
      --  Field_Size returns bits; To_Length converts to bytes.
      declare
         T_Len : constant RFLX.RFLX_Types.Length :=
           RFLX.RFLX_Types.To_Length
             (RFLX.Publish.Packet.Field_Size
                (Ctx, RFLX.Publish.Packet.F_Topic_Name));
         P_Len : constant RFLX.RFLX_Types.Length :=
           RFLX.RFLX_Types.To_Length
             (RFLX.Publish.Packet.Field_Size
                (Ctx, RFLX.Publish.Packet.F_Payload));
      begin
         if Natural (T_Len) > Topic'Length
           or P_Len > Payload'Length
         then
            RFLX.Publish.Packet.Take_Buffer (Ctx, Buffer);
            return;
         end if;

         if T_Len > 0 then
            declare
               T_Bytes : RFLX.RFLX_Types.Bytes
                 (1 .. RFLX.RFLX_Types.Index (T_Len));
               Idx     : Natural := 0;
            begin
               RFLX.Publish.Packet.Get_Topic_Name (Ctx, T_Bytes);
               Topic_Last := Topic'First + Natural (T_Len) - 1;
               for B of T_Bytes loop
                  Topic (Topic'First + Idx) :=
                    Character'Val (Natural (B));
                  Idx := Idx + 1;
               end loop;
            end;
         end if;

         Payload_Last := P_Len;
         if P_Len > 0 then
            --  Get_Payload writes directly into a slice of the
            --  caller's buffer — its precondition requires
            --  Data'Length = Field_Size, which holds by construction.
            RFLX.Publish.Packet.Get_Payload
              (Ctx,
               Payload
                 (Payload'First ..
                    Payload'First + RFLX.RFLX_Types.Index (P_Len) - 1));
         end if;
         Valid := True;
      end;
      RFLX.Publish.Packet.Take_Buffer (Ctx, Buffer);
   end Decode_Publish;

   ---------------------------------------------------------------------
   --  Decode_Publish_Header
   ---------------------------------------------------------------------

   procedure Decode_Publish_Header
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      QoS       :    out QoS_Level;
      Packet_Id :    out Packet_Identifier)
   is
      Ctx : RFLX.Publish.Packet.Context;
      use type RFLX.Control_Packet.QoS_Level;
   begin
      Valid     := False;
      QoS       := RFLX.Control_Packet.QOS_0;
      Packet_Id := 1;

      RFLX.Publish.Packet.Initialize
        (Ctx, Buffer,
         Written_Last => RFLX.RFLX_Types.Bit_Length (Last) * 8);
      RFLX.Publish.Packet.Verify_Message (Ctx);
      if RFLX.Publish.Packet.Well_Formed_Message (Ctx) then
         QoS := RFLX.Publish.Packet.Get_QoS (Ctx);
         if QoS /= RFLX.Control_Packet.QOS_0 then
            Packet_Id := RFLX.Publish.Packet.Get_Packet_Identifier (Ctx);
         end if;
         Valid := True;
      end if;
      RFLX.Publish.Packet.Take_Buffer (Ctx, Buffer);
   end Decode_Publish_Header;

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
