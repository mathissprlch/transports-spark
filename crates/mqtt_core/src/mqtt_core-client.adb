with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.RFLX_Builtin_Types;
with RFLX.Connack;
with RFLX.Connect;
with RFLX.Session.Connect_Handshake.FSM;
with RFLX.Session.Publish_Qos1.FSM;
with RFLX.Session.Subscribing.FSM;
with RFLX.Session.Unsubscribing.FSM;
with RFLX.Session.Receive.FSM;
with Mqtt_Core.Wire;

package body Mqtt_Core.Client is

   use type RFLX.Control_Packet.Packet_Identifier;
   use type RFLX.Control_Packet.Packet_Type;
   use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;

   --  Read the next full MQTT control packet from the socket into
   --  C.Buf. Single-byte Remaining-Length form: byte 1 fixed-header,
   --  byte 2 RL (0..127), then RL more bytes. Sets Success := False
   --  on EOF / socket error.
   procedure Read_Full_Packet
     (C       : in out Client;
      Last    :    out RFLX.RFLX_Types.Index;
      Success :    out Boolean);

   procedure Read_Full_Packet
     (C       : in out Client;
      Last    :    out RFLX.RFLX_Types.Index;
      Success :    out Boolean)
   is
      Two_Bytes_Ok : Boolean;
      Body_Ok      : Boolean;
      RL           : Natural;
      Buf          : RFLX.RFLX_Types.Bytes_Ptr renames C.Buf;
   begin
      Last    := Buf'First;
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
         return;
      end if;
      Transport.Receive_Full
        (C.Trans,
         Buf.all (Buf'First + 2 ..
                    Buf'First + 1 + RFLX.RFLX_Types.Index (RL)),
         Body_Ok);
      if not Body_Ok then
         return;
      end if;
      Last    := Buf'First + 1 + RFLX.RFLX_Types.Index (RL);
      Success := True;
   end Read_Full_Packet;

   --  Append a queued inbound PUBLISH (still wrapped as
   --  Incoming_Packet bytes) into the Client's pending slots. If the
   --  queue is full the packet is dropped — bounded memory matters
   --  more than spec-strict no-drop guarantee at this v0.x stage; a
   --  future revision can return back-pressure to the FSM.
   procedure Enqueue_Pending (C : in out Client;
                              View : RFLX.RFLX_Types.Bytes);

   procedure Enqueue_Pending (C : in out Client;
                              View : RFLX.RFLX_Types.Bytes)
   is
   begin
      for I in C.Pending'Range loop
         if not C.Pending (I).In_Use then
            C.Pending (I).Buf
              (C.Pending (I).Buf'First ..
                 C.Pending (I).Buf'First +
                 RFLX.RFLX_Types.Index (View'Length) - 1) := View;
            C.Pending (I).Last :=
              C.Pending (I).Buf'First +
              RFLX.RFLX_Types.Index (View'Length) - 1;
            C.Pending (I).In_Use := True;
            return;
         end if;
      end loop;
      --  Queue full — drop.
   end Enqueue_Pending;

   ---------------------------------------------------------------------
   --  Open — drive Connect_Handshake FSM.
   ---------------------------------------------------------------------

   procedure Open
     (C             : in out Client;
      Host          : String;
      Port          : Natural := 1883;
      Client_Id     : String;
      Keep_Alive_S  : Natural := 60;
      Clean_Session : Boolean := True)
   is
      package FSM renames RFLX.Session.Connect_Handshake.FSM;
      Ctx         : FSM.Context;
      Last        : RFLX.RFLX_Types.Index;
      Read_Ok     : Boolean;
      Got_Connack : Boolean := False;
      Connack_Ok  : Boolean := False;
      Sess_Pres   : Boolean := False;
      Code        : Wire.Return_Code := RFLX.Connack.ACCEPTED;
      use type Wire.Return_Code;
   begin
      if C.Buf = null then
         C.Buf := new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
      end if;

      Transport.Connect (C.Trans, Host, Port);

      --  Encode CONNECT into C.Buf, then hand it to the FSM.
      Wire.Encode_Connect
        (C.Buf, Last,
         Client_Id     => Client_Id,
         Keep_Alive_S  => RFLX.Connect.Keep_Alive (Keep_Alive_S),
         Clean_Session => Clean_Session);

      FSM.Initialize (Ctx);
      if FSM.Needs_Data (Ctx, FSM.C_App_Outbox) then
         FSM.Write
           (Ctx, FSM.C_App_Outbox,
            C.Buf.all (C.Buf'First .. Last));
      end if;

      Drive_Loop :
      loop
         FSM.Run (Ctx);
         exit Drive_Loop when not FSM.Active (Ctx);

         if FSM.Has_Data (Ctx, FSM.C_Network) then
            declare
               N    : constant RFLX.RFLX_Types.Length :=
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
            begin
               FSM.Read (Ctx, FSM.C_App_Pending, View);
               --  Connect_Handshake only emits a CONNACK on
               --  App_Pending; its Awaiting_Connack state rejects
               --  anything else as protocol-violation.
               if View'Length >= 4
                 and then Wire.Peek_Packet_Type (View)
                          = RFLX.Control_Packet.CONNACK
               then
                  C.Buf.all (View'Range) := View;
                  Wire.Decode_Connack
                    (C.Buf, View'Last, Connack_Ok, Sess_Pres, Code);
                  Got_Connack := True;
               end if;
            end;
         end if;

         if FSM.Needs_Data (Ctx, FSM.C_Network) then
            Read_Full_Packet (C, Last, Read_Ok);
            if not Read_Ok then
               FSM.Finalize (Ctx);
               Transport.Close (C.Trans);
               raise Connect_Failure with "no CONNACK";
            end if;
            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               FSM.Write
                 (Ctx, FSM.C_Network,
                  C.Buf.all (C.Buf'First .. Last));
            end if;
         end if;
      end loop Drive_Loop;

      FSM.Finalize (Ctx);

      if not Got_Connack or not Connack_Ok then
         Transport.Close (C.Trans);
         raise Connect_Failure with "no CONNACK or malformed";
      end if;
      if Code /= RFLX.Connack.ACCEPTED then
         Transport.Close (C.Trans);
         raise Connect_Failure with "broker refused CONNECT";
      end if;
   end Open;

   ---------------------------------------------------------------------
   --  Publish (QoS 0) — fire-and-forget. Hand-written, no FSM (no
   --  reply, no dispatch needed).
   ---------------------------------------------------------------------

   procedure Publish
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes)
   is
      Last : RFLX.RFLX_Types.Index;
   begin
      Wire.Encode_Publish_Qos0 (C.Buf, Last, Topic, Payload);
      Transport.Send (C.Trans, C.Buf.all (C.Buf'First .. Last));
   end Publish;

   ---------------------------------------------------------------------
   --  Publish_Qos1 — drive Publish_Qos1 FSM.
   ---------------------------------------------------------------------

   procedure Publish_Qos1
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes)
   is
      package FSM renames RFLX.Session.Publish_Qos1.FSM;
      Ctx        : FSM.Context;
      Last       : RFLX.RFLX_Types.Index;
      Pid        : constant Wire.Packet_Identifier := C.Next_Packet_Id;
      Read_Ok    : Boolean;
      Got_Puback : Boolean := False;
      Puback_Pid : Wire.Packet_Identifier := 1;
   begin
      C.Next_Packet_Id := C.Next_Packet_Id + 1;

      Wire.Encode_Publish_Qos1 (C.Buf, Last, Pid, Topic, Payload);

      FSM.Initialize (Ctx);
      if FSM.Needs_Data (Ctx, FSM.C_App_Outbox) then
         FSM.Write
           (Ctx, FSM.C_App_Outbox,
            C.Buf.all (C.Buf'First .. Last));
      end if;

      Drive_Loop :
      loop
         FSM.Run (Ctx);
         exit Drive_Loop when not FSM.Active (Ctx);

         if FSM.Has_Data (Ctx, FSM.C_Network) then
            declare
               N    : constant RFLX.RFLX_Types.Length :=
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
            begin
               FSM.Read (Ctx, FSM.C_App_Pending, View);
               if View'Length >= 4
                 and then Wire.Peek_Packet_Type (View)
                          = RFLX.Control_Packet.PUBACK
               then
                  C.Buf.all (View'Range) := View;
                  declare
                     Decode_Ok : Boolean;
                     Pkt_Id    : Wire.Packet_Identifier;
                  begin
                     Wire.Decode_Puback
                       (C.Buf, View'Last, Decode_Ok, Pkt_Id);
                     if Decode_Ok then
                        Got_Puback := True;
                        Puback_Pid := Pkt_Id;
                     end if;
                  end;
               elsif View'Length >= 2
                 and then Wire.Peek_Packet_Type (View)
                          = RFLX.Control_Packet.PUBLISH
               then
                  Enqueue_Pending (C, View);
               end if;
            end;
         end if;

         if FSM.Needs_Data (Ctx, FSM.C_Network) then
            Read_Full_Packet (C, Last, Read_Ok);
            if not Read_Ok then
               FSM.Finalize (Ctx);
               raise Publish_Failure with "EOF or socket error";
            end if;
            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               FSM.Write
                 (Ctx, FSM.C_Network,
                  C.Buf.all (C.Buf'First .. Last));
            end if;
         end if;
      end loop Drive_Loop;

      FSM.Finalize (Ctx);
      if not Got_Puback then
         raise Publish_Failure with "no PUBACK";
      elsif Puback_Pid /= Pid then
         raise Publish_Failure with "PUBACK Packet_Identifier mismatch";
      end if;
   end Publish_Qos1;

   ---------------------------------------------------------------------
   --  Subscribe — drive Subscribing FSM.
   ---------------------------------------------------------------------

   procedure Subscribe
     (C     : in out Client;
      Topic : String;
      QoS   : RFLX.Control_Packet.QoS_Level :=
        RFLX.Control_Packet.QOS_0)
   is
      package FSM renames RFLX.Session.Subscribing.FSM;
      Ctx        : FSM.Context;
      Last       : RFLX.RFLX_Types.Index;
      Pid        : constant Wire.Packet_Identifier := C.Next_Packet_Id;
      Read_Ok    : Boolean;
      Got_Suback : Boolean := False;
      Reply_Pid  : Wire.Packet_Identifier := 1;
      Reply_Code : Wire.Suback_Return_Code := Wire.Failure;
      use type Wire.Suback_Return_Code;
   begin
      C.Next_Packet_Id := C.Next_Packet_Id + 1;

      Wire.Encode_Subscribe_Single (C.Buf, Last, Pid, Topic, QoS);

      FSM.Initialize (Ctx);
      if FSM.Needs_Data (Ctx, FSM.C_App_Outbox) then
         FSM.Write
           (Ctx, FSM.C_App_Outbox,
            C.Buf.all (C.Buf'First .. Last));
      end if;

      Drive_Loop :
      loop
         FSM.Run (Ctx);
         exit Drive_Loop when not FSM.Active (Ctx);

         if FSM.Has_Data (Ctx, FSM.C_Network) then
            declare
               N    : constant RFLX.RFLX_Types.Length :=
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
            begin
               FSM.Read (Ctx, FSM.C_App_Pending, View);
               if View'Length >= 5
                 and then Wire.Peek_Packet_Type (View)
                          = RFLX.Control_Packet.SUBACK
               then
                  C.Buf.all (View'Range) := View;
                  declare
                     Decode_Ok : Boolean;
                  begin
                     Wire.Decode_Suback_Single
                       (C.Buf, View'Last, Decode_Ok,
                        Reply_Pid, Reply_Code);
                     if Decode_Ok then
                        Got_Suback := True;
                     end if;
                  end;
               elsif View'Length >= 2
                 and then Wire.Peek_Packet_Type (View)
                          = RFLX.Control_Packet.PUBLISH
               then
                  Enqueue_Pending (C, View);
               end if;
            end;
         end if;

         if FSM.Needs_Data (Ctx, FSM.C_Network) then
            Read_Full_Packet (C, Last, Read_Ok);
            if not Read_Ok then
               FSM.Finalize (Ctx);
               raise Subscribe_Failure with "EOF or socket error";
            end if;
            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               FSM.Write
                 (Ctx, FSM.C_Network,
                  C.Buf.all (C.Buf'First .. Last));
            end if;
         end if;
      end loop Drive_Loop;

      FSM.Finalize (Ctx);
      if not Got_Suback then
         raise Subscribe_Failure with "no SUBACK";
      elsif Reply_Pid /= Pid then
         raise Subscribe_Failure with "SUBACK Packet_Identifier mismatch";
      elsif Reply_Code = Wire.Failure then
         raise Subscribe_Failure with "broker refused subscription";
      end if;
   end Subscribe;

   ---------------------------------------------------------------------
   --  Unsubscribe — drive Unsubscribing FSM.
   ---------------------------------------------------------------------

   procedure Unsubscribe
     (C     : in out Client;
      Topic : String)
   is
      package FSM renames RFLX.Session.Unsubscribing.FSM;
      Ctx          : FSM.Context;
      Last         : RFLX.RFLX_Types.Index;
      Pid          : constant Wire.Packet_Identifier := C.Next_Packet_Id;
      Read_Ok      : Boolean;
      Got_Unsuback : Boolean := False;
      Reply_Pid    : Wire.Packet_Identifier := 1;
   begin
      C.Next_Packet_Id := C.Next_Packet_Id + 1;

      Wire.Encode_Unsubscribe_Single (C.Buf, Last, Pid, Topic);

      FSM.Initialize (Ctx);
      if FSM.Needs_Data (Ctx, FSM.C_App_Outbox) then
         FSM.Write
           (Ctx, FSM.C_App_Outbox,
            C.Buf.all (C.Buf'First .. Last));
      end if;

      Drive_Loop :
      loop
         FSM.Run (Ctx);
         exit Drive_Loop when not FSM.Active (Ctx);

         if FSM.Has_Data (Ctx, FSM.C_Network) then
            declare
               N    : constant RFLX.RFLX_Types.Length :=
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
            begin
               FSM.Read (Ctx, FSM.C_App_Pending, View);
               if View'Length >= 4
                 and then Wire.Peek_Packet_Type (View)
                          = RFLX.Control_Packet.UNSUBACK
               then
                  C.Buf.all (View'Range) := View;
                  declare
                     Decode_Ok : Boolean;
                  begin
                     Wire.Decode_Unsuback
                       (C.Buf, View'Last, Decode_Ok, Reply_Pid);
                     if Decode_Ok then
                        Got_Unsuback := True;
                     end if;
                  end;
               elsif View'Length >= 2
                 and then Wire.Peek_Packet_Type (View)
                          = RFLX.Control_Packet.PUBLISH
               then
                  Enqueue_Pending (C, View);
               end if;
            end;
         end if;

         if FSM.Needs_Data (Ctx, FSM.C_Network) then
            Read_Full_Packet (C, Last, Read_Ok);
            if not Read_Ok then
               FSM.Finalize (Ctx);
               raise Unsubscribe_Failure with "EOF or socket error";
            end if;
            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               FSM.Write
                 (Ctx, FSM.C_Network,
                  C.Buf.all (C.Buf'First .. Last));
            end if;
         end if;
      end loop Drive_Loop;

      FSM.Finalize (Ctx);
      if not Got_Unsuback then
         raise Unsubscribe_Failure with "no UNSUBACK";
      elsif Reply_Pid /= Pid then
         raise Unsubscribe_Failure
           with "UNSUBACK Packet_Identifier mismatch";
      end if;
   end Unsubscribe;

   ---------------------------------------------------------------------
   --  Receive_Publish — drain pending queue first, else drive
   --  Receive FSM.
   --
   --  Decodes the head Pending_Slot bytes (or a fresh PUBLISH that
   --  the FSM emitted on App_Pending) into the caller's
   --  Topic / Payload buffers.
   ---------------------------------------------------------------------

   --  Decode an Incoming_Packet-shaped PUBLISH from `Slot_Bytes`
   --  (which is `View` from a Pending slot or App_Pending) into the
   --  caller's buffers. Re-uses Wire.Decode_Publish_Qos0 by writing
   --  the bytes through C.Buf.
   procedure Decode_Pending_Publish
     (C            : in out Client;
      View         : RFLX.RFLX_Types.Bytes;
      Topic        : in out String;
      Topic_Last   :    out Natural;
      Payload      : in out RFLX.RFLX_Types.Bytes;
      Payload_Last :    out RFLX.RFLX_Types.Length;
      Ok           :    out Boolean);

   procedure Decode_Pending_Publish
     (C            : in out Client;
      View         : RFLX.RFLX_Types.Bytes;
      Topic        : in out String;
      Topic_Last   :    out Natural;
      Payload      : in out RFLX.RFLX_Types.Bytes;
      Payload_Last :    out RFLX.RFLX_Types.Length;
      Ok           :    out Boolean)
   is
      Last_Idx : constant RFLX.RFLX_Types.Index :=
        C.Buf'First + RFLX.RFLX_Types.Index (View'Length) - 1;
   begin
      C.Buf.all (C.Buf'First .. Last_Idx) := View;
      Wire.Decode_Publish_Qos0
        (C.Buf, Last_Idx, Ok, Topic, Topic_Last, Payload, Payload_Last);
   end Decode_Pending_Publish;

   procedure Receive_Publish
     (C            : in out Client;
      Topic        : in out String;
      Topic_Last   :    out Natural;
      Payload      : in out RFLX.RFLX_Types.Bytes;
      Payload_Last :    out RFLX.RFLX_Types.Length)
   is
      Decode_Ok : Boolean;
   begin
      --  Drain one queued PUBLISH if any.
      for I in C.Pending'Range loop
         if C.Pending (I).In_Use then
            declare
               View : constant RFLX.RFLX_Types.Bytes :=
                 C.Pending (I).Buf
                   (C.Pending (I).Buf'First .. C.Pending (I).Last);
            begin
               Decode_Pending_Publish
                 (C, View, Topic, Topic_Last,
                  Payload, Payload_Last, Decode_Ok);
            end;
            C.Pending (I).In_Use := False;
            if not Decode_Ok then
               raise Receive_Failure with "malformed queued PUBLISH";
            end if;
            return;
         end if;
      end loop;

      --  Queue empty — drive the Receive FSM. The Receive FSM has no
      --  Loading state; its Reading state needs Network data on the
      --  very first Run, so we feed it before entering the loop.
      declare
         package FSM renames RFLX.Session.Receive.FSM;
         Ctx     : FSM.Context;
         Last    : RFLX.RFLX_Types.Index;
         Read_Ok : Boolean;
         Got     : Boolean := False;
      begin
         FSM.Initialize (Ctx);

         --  Pre-feed Network data so the first Reading transition
         --  has bytes to Verify against.
         Read_Full_Packet (C, Last, Read_Ok);
         if not Read_Ok then
            FSM.Finalize (Ctx);
            raise Receive_Failure with "EOF or socket error";
         end if;
         if FSM.Needs_Data (Ctx, FSM.C_Network) then
            FSM.Write
              (Ctx, FSM.C_Network,
               C.Buf.all (C.Buf'First .. Last));
         end if;

         Drive_Loop :
         loop
            FSM.Run (Ctx);
            exit Drive_Loop when not FSM.Active (Ctx);

            if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
               declare
                  N    : constant RFLX.RFLX_Types.Length :=
                    FSM.Read_Buffer_Size (Ctx, FSM.C_App_Pending);
                  View : RFLX.RFLX_Types.Bytes
                    (C.Buf'First ..
                       C.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
               begin
                  FSM.Read (Ctx, FSM.C_App_Pending, View);
                  if View'Length >= 2
                    and then Wire.Peek_Packet_Type (View)
                             = RFLX.Control_Packet.PUBLISH
                  then
                     Decode_Pending_Publish
                       (C, View, Topic, Topic_Last,
                        Payload, Payload_Last, Decode_Ok);
                     if Decode_Ok then
                        Got := True;
                     end if;
                  end if;
               end;
            end if;

            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               Read_Full_Packet (C, Last, Read_Ok);
               if not Read_Ok then
                  FSM.Finalize (Ctx);
                  raise Receive_Failure with "EOF or socket error";
               end if;
               if FSM.Needs_Data (Ctx, FSM.C_Network) then
                  FSM.Write
                    (Ctx, FSM.C_Network,
                     C.Buf.all (C.Buf'First .. Last));
               end if;
            end if;
         end loop Drive_Loop;

         FSM.Finalize (Ctx);
         if not Got then
            raise Receive_Failure with "FSM exited without PUBLISH";
         end if;
      end;
   end Receive_Publish;

   ---------------------------------------------------------------------
   --  Close — hand-written. Just send DISCONNECT.
   ---------------------------------------------------------------------

   procedure Close (C : in out Client) is
      Last : RFLX.RFLX_Types.Index;
   begin
      if C.Buf /= null and Transport.Is_Open (C.Trans) then
         begin
            Wire.Encode_Disconnect (C.Buf, Last);
            Transport.Send (C.Trans, C.Buf.all (C.Buf'First .. Last));
         exception
            when others =>
               null;
         end;
      end if;
      if Transport.Is_Open (C.Trans) then
         Transport.Close (C.Trans);
      end if;
      if C.Buf /= null then
         RFLX.RFLX_Types.Free (C.Buf);
      end if;
   end Close;

end Mqtt_Core.Client;
