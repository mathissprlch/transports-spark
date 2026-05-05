with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.RFLX_Builtin_Types;
with RFLX.Connack;
with RFLX.Connect;
with RFLX.Session.Connect_Handshake.FSM;
with RFLX.Session.Publish_Qos1.FSM;
with RFLX.Session.Publish_Qos2.FSM;
with RFLX.Session.Subscribing.FSM;
with RFLX.Session.Unsubscribing.FSM;
with RFLX.Session.Receive.FSM;
with RFLX.Session.Receive_Qos2.FSM;

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

   --  Decode `View` as a PUBLISH (any QoS) and, if QoS=1, encode the
   --  matching PUBACK into C.Buf and send it to the broker. §4.3.2 of
   --  MQTT 3.1.1 obligates the receiver of a QoS 1 PUBLISH to PUBACK;
   --  doing it as soon as we see the bytes (rather than at delivery)
   --  prevents the broker from retransmitting with DUP=1 while the
   --  application is still draining its queue.
   --
   --  View must contain bytes already copied INTO C.Buf — the decode
   --  contexts mutate the buffer pointer (Initialize/Take_Buffer
   --  cycle) and the caller is expected to have written the inbound
   --  bytes into C.Buf before calling.
   procedure Puback_If_Qos1 (C : in out Client;
                             View_Last : RFLX.RFLX_Types.Index);

   procedure Puback_If_Qos1 (C : in out Client;
                             View_Last : RFLX.RFLX_Types.Index)
   is
      use type RFLX.Control_Packet.QoS_Level;
      Decoded_Ok  : Boolean;
      QoS         : RFLX.Control_Packet.QoS_Level;
      Pid         : RFLX.Control_Packet.Packet_Identifier;
      Puback_Last : RFLX.RFLX_Types.Index;
   begin
      Wire.Decode_Publish_Header
        (C.Buf, View_Last, Decoded_Ok, QoS, Pid);
      if Decoded_Ok and then QoS = RFLX.Control_Packet.QOS_1 then
         Wire.Encode_Puback (C.Buf, Puback_Last, Pid);
         Transport.Send
           (C.Trans, C.Buf.all (C.Buf'First .. Puback_Last));
      end if;
   end Puback_If_Qos1;

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
      --  Buffers are caller-supplied via Attach_Buffers. The
      --  library NEVER calls `new`. Fail loudly if Open is called
      --  without the buffers being attached first.
      if C.Buf = null
        or else C.Inbound_Buf = null
        or else C.Outgoing_Buf = null
      then
         raise Connect_Failure
           with "Mqtt_Core.Client.Attach_Buffers must be called before Open";
      end if;

      Transport.Connect (C.Trans, Host, Port);

      --  Encode CONNECT into C.Buf, then hand it to the FSM.
      Wire.Encode_Connect
        (C.Buf, Last,
         Client_Id     => Client_Id,
         Keep_Alive_S  => RFLX.Connect.Keep_Alive (Keep_Alive_S),
         Clean_Session => Clean_Session);

      FSM.Initialize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
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
               FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
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

      FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);

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
      Payload : RFLX.RFLX_Types.Bytes;
      Retain  : Boolean := False)
   is
      Last : RFLX.RFLX_Types.Index;
   begin
      Wire.Encode_Publish_Qos0
        (C.Buf, Last, Topic, Payload, Retain);
      Transport.Send (C.Trans, C.Buf.all (C.Buf'First .. Last));
   end Publish;

   ---------------------------------------------------------------------
   --  Publish_Qos1 — drive Publish_Qos1 FSM.
   ---------------------------------------------------------------------

   procedure Publish_Qos1
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes;
      Retain  : Boolean := False)
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

      Wire.Encode_Publish_Qos1
        (C.Buf, Last, Pid, Topic, Payload, Retain);

      FSM.Initialize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
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
                  C.Buf.all (View'Range) := View;
                  Puback_If_Qos1 (C, View'Last);
               end if;
            end;
         end if;

         if FSM.Needs_Data (Ctx, FSM.C_Network) then
            Read_Full_Packet (C, Last, Read_Ok);
            if not Read_Ok then
               FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
               raise Publish_Failure with "EOF or socket error";
            end if;
            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               FSM.Write
                 (Ctx, FSM.C_Network,
                  C.Buf.all (C.Buf'First .. Last));
            end if;
         end if;
      end loop Drive_Loop;

      FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
      if not Got_Puback then
         raise Publish_Failure with "no PUBACK";
      elsif Puback_Pid /= Pid then
         raise Publish_Failure with "PUBACK Packet_Identifier mismatch";
      end if;
   end Publish_Qos1;

   ---------------------------------------------------------------------
   --  Publish_Qos2 — drive Publish_Qos2 FSM (4-step handshake).
   --
   --  The FSM models the two read-and-dispatch states; the PUBREL
   --  emission between them is hand-written by the driver after the
   --  PUBREC bytes are forwarded on App_Pending. From the FSM's
   --  perspective, Awaiting_Pubcomp simply reads from Network — it
   --  doesn't know we sent PUBREL out of band.
   ---------------------------------------------------------------------

   procedure Publish_Qos2
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes;
      Retain  : Boolean := False)
   is
      package FSM renames RFLX.Session.Publish_Qos2.FSM;
      Ctx          : FSM.Context;
      Last         : RFLX.RFLX_Types.Index;
      Pid          : constant Wire.Packet_Identifier := C.Next_Packet_Id;
      Read_Ok      : Boolean;
      Got_Pubrec   : Boolean := False;
      Got_Pubcomp  : Boolean := False;
      Pubrec_Pid   : Wire.Packet_Identifier := 1;
      Pubcomp_Pid  : Wire.Packet_Identifier := 1;
      Pubrel_Last  : RFLX.RFLX_Types.Index;
   begin
      C.Next_Packet_Id := C.Next_Packet_Id + 1;

      Wire.Encode_Publish_Qos2
        (C.Buf, Last, Pid, Topic, Payload, Retain);

      FSM.Initialize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
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
                          = RFLX.Control_Packet.PUBREC
               then
                  C.Buf.all (View'Range) := View;
                  declare
                     Decode_Ok : Boolean;
                  begin
                     Wire.Decode_Pubrec
                       (C.Buf, View'Last, Decode_Ok, Pubrec_Pid);
                     if Decode_Ok then
                        Got_Pubrec := True;
                        --  Hand-emit PUBREL on the wire; the FSM's
                        --  next state is Awaiting_Pubcomp which just
                        --  reads from Network.
                        Wire.Encode_Pubrel
                          (C.Buf, Pubrel_Last, Pubrec_Pid);
                        Transport.Send
                          (C.Trans,
                           C.Buf.all (C.Buf'First .. Pubrel_Last));
                     end if;
                  end;
               elsif View'Length >= 4
                 and then Wire.Peek_Packet_Type (View)
                          = RFLX.Control_Packet.PUBCOMP
               then
                  C.Buf.all (View'Range) := View;
                  declare
                     Decode_Ok : Boolean;
                  begin
                     Wire.Decode_Pubcomp
                       (C.Buf, View'Last, Decode_Ok, Pubcomp_Pid);
                     if Decode_Ok then
                        Got_Pubcomp := True;
                     end if;
                  end;
               elsif View'Length >= 2
                 and then Wire.Peek_Packet_Type (View)
                          = RFLX.Control_Packet.PUBLISH
               then
                  Enqueue_Pending (C, View);
                  C.Buf.all (View'Range) := View;
                  Puback_If_Qos1 (C, View'Last);
               end if;
            end;
         end if;

         if FSM.Needs_Data (Ctx, FSM.C_Network) then
            Read_Full_Packet (C, Last, Read_Ok);
            if not Read_Ok then
               FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
               raise Publish_Failure with "EOF or socket error";
            end if;
            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               FSM.Write
                 (Ctx, FSM.C_Network,
                  C.Buf.all (C.Buf'First .. Last));
            end if;
         end if;
      end loop Drive_Loop;

      FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
      if not Got_Pubrec then
         raise Publish_Failure with "no PUBREC";
      elsif Pubrec_Pid /= Pid then
         raise Publish_Failure with "PUBREC Packet_Identifier mismatch";
      elsif not Got_Pubcomp then
         raise Publish_Failure with "no PUBCOMP";
      elsif Pubcomp_Pid /= Pid then
         raise Publish_Failure with "PUBCOMP Packet_Identifier mismatch";
      end if;
   end Publish_Qos2;

   ---------------------------------------------------------------------
   --  Subscribe / Subscribe_Many — drive Subscribing FSM.
   --
   --  The single-topic Subscribe is a thin wrapper around Subscribe_Many
   --  with a 1-element filter array; only one FSM driver loop to
   --  maintain.
   ---------------------------------------------------------------------

   procedure Subscribe_Many
     (C       : in out Client;
      Filters : Subscription_Filters)
   is
      package FSM renames RFLX.Session.Subscribing.FSM;
      Ctx        : FSM.Context;
      Last       : RFLX.RFLX_Types.Index;
      Pid        : constant Wire.Packet_Identifier := C.Next_Packet_Id;
      Read_Ok    : Boolean;
      Got_Suback : Boolean := False;
      Reply_Pid  : Wire.Packet_Identifier := 1;
      Codes      : Wire.Suback_Code_Array (Filters'Range) :=
        (others => Wire.Failure);
      Codes_Last : Natural := Codes'First - 1;
      use type Wire.Suback_Return_Code;
   begin
      C.Next_Packet_Id := C.Next_Packet_Id + 1;

      Wire.Encode_Subscribe (C.Buf, Last, Pid, Filters);

      FSM.Initialize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
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
                     Wire.Decode_Suback
                       (C.Buf, View'Last, Decode_Ok,
                        Reply_Pid, Codes, Codes_Last);
                     if Decode_Ok then
                        Got_Suback := True;
                     end if;
                  end;
               elsif View'Length >= 2
                 and then Wire.Peek_Packet_Type (View)
                          = RFLX.Control_Packet.PUBLISH
               then
                  Enqueue_Pending (C, View);
                  C.Buf.all (View'Range) := View;
                  Puback_If_Qos1 (C, View'Last);
               end if;
            end;
         end if;

         if FSM.Needs_Data (Ctx, FSM.C_Network) then
            Read_Full_Packet (C, Last, Read_Ok);
            if not Read_Ok then
               FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
               raise Subscribe_Failure with "EOF or socket error";
            end if;
            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               FSM.Write
                 (Ctx, FSM.C_Network,
                  C.Buf.all (C.Buf'First .. Last));
            end if;
         end if;
      end loop Drive_Loop;

      FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
      if not Got_Suback then
         raise Subscribe_Failure with "no SUBACK";
      elsif Reply_Pid /= Pid then
         raise Subscribe_Failure with "SUBACK Packet_Identifier mismatch";
      elsif Codes_Last < Codes'Last then
         raise Subscribe_Failure
           with "SUBACK return-code count < SUBSCRIBE filter count";
      else
         for I in Codes'Range loop
            if Codes (I) = Wire.Failure then
               raise Subscribe_Failure
                 with "broker refused at least one subscription";
            end if;
         end loop;
      end if;
   end Subscribe_Many;

   procedure Subscribe
     (C     : in out Client;
      Topic : String;
      QoS   : RFLX.Control_Packet.QoS_Level :=
        RFLX.Control_Packet.QOS_0)
   is
      Filters : constant Subscription_Filters (1 .. 1) :=
        (1 => Wire.Make_Subscription (Topic, QoS));
   begin
      Subscribe_Many (C, Filters);
   end Subscribe;

   ---------------------------------------------------------------------
   --  Unsubscribe / Unsubscribe_Many — drive Unsubscribing FSM. Same
   --  delegation pattern as Subscribe / Subscribe_Many.
   ---------------------------------------------------------------------

   procedure Unsubscribe_Many
     (C       : in out Client;
      Filters : Topic_Filters)
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

      Wire.Encode_Unsubscribe (C.Buf, Last, Pid, Filters);

      FSM.Initialize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
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
                  C.Buf.all (View'Range) := View;
                  Puback_If_Qos1 (C, View'Last);
               end if;
            end;
         end if;

         if FSM.Needs_Data (Ctx, FSM.C_Network) then
            Read_Full_Packet (C, Last, Read_Ok);
            if not Read_Ok then
               FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
               raise Unsubscribe_Failure with "EOF or socket error";
            end if;
            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               FSM.Write
                 (Ctx, FSM.C_Network,
                  C.Buf.all (C.Buf'First .. Last));
            end if;
         end if;
      end loop Drive_Loop;

      FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
      if not Got_Unsuback then
         raise Unsubscribe_Failure with "no UNSUBACK";
      elsif Reply_Pid /= Pid then
         raise Unsubscribe_Failure
           with "UNSUBACK Packet_Identifier mismatch";
      end if;
   end Unsubscribe_Many;

   procedure Unsubscribe
     (C     : in out Client;
      Topic : String)
   is
      Filters : constant Topic_Filters (1 .. 1) :=
        (1 => Wire.Make_Topic_Filter (Topic));
   begin
      Unsubscribe_Many (C, Filters);
   end Unsubscribe;

   ---------------------------------------------------------------------
   --  Receive_Publish — drain pending queue first, else drive
   --  Receive FSM.
   --
   --  Decodes the head Pending_Slot bytes (or a fresh PUBLISH that
   --  the FSM emitted on App_Pending) into the caller's
   --  Topic / Payload buffers.
   ---------------------------------------------------------------------

   --  Decode an Incoming_Packet-shaped PUBLISH from `View` (either a
   --  Pending slot or App_Pending bytes) into the caller's buffers,
   --  while also reporting QoS + Packet Identifier so the caller can
   --  decide whether to PUBACK.
   procedure Decode_Pending_Publish
     (C            : in out Client;
      View         : RFLX.RFLX_Types.Bytes;
      QoS          :    out RFLX.Control_Packet.QoS_Level;
      Pid          :    out RFLX.Control_Packet.Packet_Identifier;
      Topic        : in out String;
      Topic_Last   :    out Natural;
      Payload      : in out RFLX.RFLX_Types.Bytes;
      Payload_Last :    out RFLX.RFLX_Types.Length;
      Ok           :    out Boolean);

   procedure Decode_Pending_Publish
     (C            : in out Client;
      View         : RFLX.RFLX_Types.Bytes;
      QoS          :    out RFLX.Control_Packet.QoS_Level;
      Pid          :    out RFLX.Control_Packet.Packet_Identifier;
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
      declare
         Retain : Boolean;
      begin
         Wire.Decode_Publish
           (C.Buf, Last_Idx, Ok, QoS, Pid,
            Topic, Topic_Last, Payload, Payload_Last, Retain);
      end;
   end Decode_Pending_Publish;

   --  Drive Receive_Qos2 FSM through PUBREC → await PUBREL →
   --  hand-write PUBCOMP. Mirrors Publish_Qos2 outbound's split:
   --  the FSM enforces the dispatch table for Awaiting_Pubrel; the
   --  driver hand-writes the trailing PUBCOMP after the FSM exits.
   procedure Drive_Qos2_Inbound_Ack
     (C   : in out Client;
      Pid : RFLX.Control_Packet.Packet_Identifier);

   procedure Drive_Qos2_Inbound_Ack
     (C   : in out Client;
      Pid : RFLX.Control_Packet.Packet_Identifier)
   is
      package FSM renames RFLX.Session.Receive_Qos2.FSM;
      Ctx          : FSM.Context;
      Last         : RFLX.RFLX_Types.Index;
      Read_Ok      : Boolean;
      Got_Pubrel   : Boolean := False;
      Pubrel_Pid   : RFLX.Control_Packet.Packet_Identifier := Pid;
   begin
      --  Encode PUBREC into C.Buf, hand to FSM.C_App_Outbox.
      Wire.Encode_Pubrec (C.Buf, Last, Pid);

      FSM.Initialize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
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
               Decode_Ok : Boolean;
            begin
               FSM.Read (Ctx, FSM.C_App_Pending, View);
               --  FSM only forwards PUBREL to App_Pending in this
               --  machine; verify and pull the Packet Identifier.
               if View'Length >= 4
                 and then Wire.Peek_Packet_Type (View)
                          = RFLX.Control_Packet.PUBREL
               then
                  C.Buf.all (View'Range) := View;
                  Wire.Decode_Pubrel
                    (C.Buf, View'Last, Decode_Ok, Pubrel_Pid);
                  if Decode_Ok then
                     Got_Pubrel := True;
                  end if;
               end if;
            end;
         end if;

         if FSM.Needs_Data (Ctx, FSM.C_Network) then
            Read_Full_Packet (C, Last, Read_Ok);
            if not Read_Ok then
               FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);
               raise Receive_Failure
                 with "QoS 2 inbound: EOF awaiting PUBREL";
            end if;
            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               FSM.Write
                 (Ctx, FSM.C_Network,
                  C.Buf.all (C.Buf'First .. Last));
            end if;
         end if;
      end loop Drive_Loop;

      FSM.Finalize (Ctx, C.Inbound_Buf, C.Outgoing_Buf);

      if not Got_Pubrel then
         raise Receive_Failure
           with "QoS 2 inbound: FSM exited without PUBREL";
      end if;

      --  Hand-written final leg: PUBCOMP with the same Packet
      --  Identifier (echo) goes back to broker.
      declare
         Pubcomp_Last : RFLX.RFLX_Types.Index;
      begin
         Wire.Encode_Pubcomp (C.Buf, Pubcomp_Last, Pubrel_Pid);
         Transport.Send
           (C.Trans, C.Buf.all (C.Buf'First .. Pubcomp_Last));
      end;
   end Drive_Qos2_Inbound_Ack;

   procedure Receive_Publish
     (C            : in out Client;
      Topic        : in out String;
      Topic_Last   :    out Natural;
      Payload      : in out RFLX.RFLX_Types.Bytes;
      Payload_Last :    out RFLX.RFLX_Types.Length)
   is
      use type RFLX.Control_Packet.QoS_Level;
      Decode_Ok : Boolean;
      QoS       : RFLX.Control_Packet.QoS_Level;
      Pid       : RFLX.Control_Packet.Packet_Identifier;
   begin
      --  Drain one queued PUBLISH if any.
      --
      --  QoS 1: PUBACK was already emitted at enqueue time
      --     (in Subscribe / Unsubscribe / Publish_Qos1), so a drain
      --     MUST NOT re-PUBACK — that would be a duplicate ack.
      --  QoS 2: no ack has been sent yet — the four-step
      --     PUBREC/PUBREL/PUBCOMP flow runs on drain.
      for I in C.Pending'Range loop
         if C.Pending (I).In_Use then
            declare
               View : constant RFLX.RFLX_Types.Bytes :=
                 C.Pending (I).Buf
                   (C.Pending (I).Buf'First .. C.Pending (I).Last);
            begin
               Decode_Pending_Publish
                 (C, View, QoS, Pid, Topic, Topic_Last,
                  Payload, Payload_Last, Decode_Ok);
            end;
            C.Pending (I).In_Use := False;
            if not Decode_Ok then
               raise Receive_Failure with "malformed queued PUBLISH";
            end if;
            if QoS = RFLX.Control_Packet.QOS_2 then
               Drive_Qos2_Inbound_Ack (C, Pid);
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
         --  Receive machine has only an Inbound message variable
         --  (no Outgoing) — its Initialize/Finalize take a single
         --  Bytes_Ptr.
         FSM.Initialize (Ctx, C.Inbound_Buf);

         --  Pre-feed Network data so the first Reading transition
         --  has bytes to Verify against.
         Read_Full_Packet (C, Last, Read_Ok);
         if not Read_Ok then
            FSM.Finalize (Ctx, C.Inbound_Buf);
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
                       (C, View, QoS, Pid, Topic, Topic_Last,
                        Payload, Payload_Last, Decode_Ok);
                     if Decode_Ok then
                        Got := True;
                        --  Fresh delivery from the wire — PUBACK if
                        --  QoS=1 (§4.3.2). Drain-from-queue path
                        --  above does not, having already PUBACKed
                        --  at enqueue.
                        if QoS = RFLX.Control_Packet.QOS_1 then
                           declare
                              Puback_Last : RFLX.RFLX_Types.Index;
                           begin
                              Wire.Encode_Puback
                                (C.Buf, Puback_Last, Pid);
                              Transport.Send
                                (C.Trans,
                                 C.Buf.all
                                   (C.Buf'First .. Puback_Last));
                           end;
                        end if;
                        --  QoS 2 case is dispatched AFTER FSM.Finalize
                        --  below — Receive_Qos2 needs C.Inbound_Buf
                        --  back from the Receive FSM first.
                     end if;
                  end if;
               end;
            end if;

            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               Read_Full_Packet (C, Last, Read_Ok);
               if not Read_Ok then
                  FSM.Finalize (Ctx, C.Inbound_Buf);
                  raise Receive_Failure with "EOF or socket error";
               end if;
               if FSM.Needs_Data (Ctx, FSM.C_Network) then
                  FSM.Write
                    (Ctx, FSM.C_Network,
                     C.Buf.all (C.Buf'First .. Last));
               end if;
            end if;
         end loop Drive_Loop;

         FSM.Finalize (Ctx, C.Inbound_Buf);
         if not Got then
            raise Receive_Failure with "FSM exited without PUBLISH";
         end if;
      end;

      --  QoS 2 inbound ack (deferred until after Receive FSM Finalize
      --  returned C.Inbound_Buf — Receive_Qos2 needs it).
      if QoS = RFLX.Control_Packet.QOS_2 then
         Drive_Qos2_Inbound_Ack (C, Pid);
      end if;
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
      --  Buffer ownership stays with the application; Close does
      --  NOT free. Use Detach_Buffers to recover the buffers and
      --  let the application free them (or re-use them for a new
      --  session).
   end Close;

   procedure Attach_Buffers
     (C            : in out Client;
      Buf          : in out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : in out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : in out RFLX.RFLX_Types.Bytes_Ptr) is
   begin
      C.Buf          := Buf;          Buf          := null;
      C.Inbound_Buf  := Inbound_Buf;  Inbound_Buf  := null;
      C.Outgoing_Buf := Outgoing_Buf; Outgoing_Buf := null;
   end Attach_Buffers;

   procedure Detach_Buffers
     (C            : in out Client;
      Buf          : out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : out RFLX.RFLX_Types.Bytes_Ptr) is
   begin
      Buf          := C.Buf;          C.Buf          := null;
      Inbound_Buf  := C.Inbound_Buf;  C.Inbound_Buf  := null;
      Outgoing_Buf := C.Outgoing_Buf; C.Outgoing_Buf := null;
   end Detach_Buffers;

end Mqtt_Core.Client;
