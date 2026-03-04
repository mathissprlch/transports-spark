with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.RFLX_Builtin_Types;
with RFLX.Connack;
with RFLX.Connect;
with RFLX.Session.Publish_Qos1.FSM;
use type RFLX.Session.Publish_Qos1.FSM.State;
with Mqtt_Core.Wire;

package body Mqtt_Core.Client is

   use type RFLX.Control_Packet.Packet_Identifier;
   use type RFLX.Control_Packet.Packet_Type;
   use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;

   --  Read the next full MQTT control packet from the socket into
   --  C.Buf. Assumes the single-byte Remaining-Length form: byte 1 is
   --  the fixed-header byte, byte 2 is RL (0..127), then RL more bytes.
   --  Sets Success := False on EOF / socket error.
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
      Last : RFLX.RFLX_Types.Index;
      Connack_Ok       : Boolean;
      Session_Present  : Boolean;
      Code             : Wire.Return_Code;
      Read_Ok          : Boolean;
      use type Wire.Return_Code;
   begin
      --  One allocation per Client lifetime; Close frees it. The buffer
      --  hops back and forth between this record and RecordFlux contexts
      --  via Initialize / Take_Buffer, never touching the heap again.
      if C.Buf = null then
         C.Buf := new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
      end if;

      Transport.Connect (C.Trans, Host, Port);

      --  CONNECT.
      Wire.Encode_Connect
        (C.Buf, Last,
         Client_Id     => Client_Id,
         Keep_Alive_S  => RFLX.Connect.Keep_Alive (Keep_Alive_S),
         Clean_Session => Clean_Session);
      Transport.Send (C.Trans, C.Buf.all (C.Buf'First .. Last));

      --  CONNACK.
      Read_Full_Packet (C, Last, Read_Ok);
      if not Read_Ok then
         Transport.Close (C.Trans);
         raise Connect_Failure with "no CONNACK";
      end if;
      Wire.Decode_Connack (C.Buf, Last, Connack_Ok, Session_Present, Code);
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
      Last : RFLX.RFLX_Types.Index;
   begin
      Wire.Encode_Publish_Qos0 (C.Buf, Last, Topic, Payload);
      Transport.Send (C.Trans, C.Buf.all (C.Buf'First .. Last));
   end Publish;

   ---------------------------------------------------------------------
   --  Publish_Qos1 — send PUBLISH (QoS 1) and await PUBACK.
   ---------------------------------------------------------------------

   procedure Publish_Qos1
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes)
   is
      Last      : RFLX.RFLX_Types.Index;
      Pid       : constant Wire.Packet_Identifier := C.Next_Packet_Id;
      Read_Ok   : Boolean;
      Reply_Pid : Wire.Packet_Identifier;
   begin
      C.Next_Packet_Id := C.Next_Packet_Id + 1;

      Wire.Encode_Publish_Qos1 (C.Buf, Last, Pid, Topic, Payload);
      Transport.Send (C.Trans, C.Buf.all (C.Buf'First .. Last));

      Read_Full_Packet (C, Last, Read_Ok);
      if not Read_Ok then
         raise Publish_Failure with "no PUBACK";
      end if;
      Wire.Decode_Puback (C.Buf, Last, Read_Ok, Reply_Pid);
      if not Read_Ok or Reply_Pid /= Pid then
         raise Publish_Failure with "broker PUBACK mismatch";
      end if;
   end Publish_Qos1;

   ---------------------------------------------------------------------
   --  Publish_Qos1_FSM — drive the generated session.rflx machine.
   ---------------------------------------------------------------------

   procedure Publish_Qos1_FSM
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes)
   is
      package FSM renames RFLX.Session.Publish_Qos1.FSM;
      Ctx           : FSM.Context;
      Last          : RFLX.RFLX_Types.Index;
      Pid           : constant Wire.Packet_Identifier := C.Next_Packet_Id;
      Read_Ok       : Boolean;
      Got_Puback    : Boolean := False;
      Puback_Pid    : Wire.Packet_Identifier := 1;
   begin
      C.Next_Packet_Id := C.Next_Packet_Id + 1;

      --  Build the outgoing PUBLISH using the existing wire encoder,
      --  then push the bytes into the FSM's App_Outbox channel.
      Wire.Encode_Publish_Qos1 (C.Buf, Last, Pid, Topic, Payload);

      FSM.Initialize (Ctx);
      if FSM.Needs_Data (Ctx, FSM.C_App_Outbox) then
         FSM.Write
           (Ctx, FSM.C_App_Outbox,
            C.Buf.all (C.Buf'First .. Last));
      end if;

      --  Drive the state machine until it terminates.
      Drive_Loop :
      loop
         FSM.Run (Ctx);
         exit Drive_Loop when not FSM.Active (Ctx);

         --  FSM has bytes to send out on the network.
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
               C.Buf.all (View'Range) := View;  -- keep buf in sync
            end;
         end if;

         --  FSM has produced bytes on App_Pending — either a PUBLISH
         --  echo to forward to the application, or the PUBACK we are
         --  waiting for. Distinguish by Packet_Type. Inbound PUBLISH
         --  forwarding to Receive_Publish is the next iteration; for
         --  now we drain and note the PUBACK arrival.
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
                  --  Decode for the Packet Identifier match check.
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
               end if;
               --  Else: an inbound PUBLISH echoed by the broker. The
               --  next iteration of the FSM-driven receive path will
               --  enqueue these for the application to drain via
               --  Receive_Publish. For now: silently discarded,
               --  matching the hand-written QoS 1 path's behavior.
            end;
         end if;

         --  FSM needs more bytes from the network: assemble a full
         --  packet via Read_Full_Packet (already handles the
         --  fixed-header + RL framing) and feed it in.
         if FSM.Needs_Data (Ctx, FSM.C_Network) then
            Read_Full_Packet (C, Last, Read_Ok);
            if not Read_Ok then
               FSM.Finalize (Ctx);
               raise Publish_Failure with "EOF or socket error";
            end if;
            declare
               Pkt : constant RFLX.RFLX_Types.Bytes :=
                 C.Buf.all (C.Buf'First .. Last);
            begin
               if FSM.Needs_Data (Ctx, FSM.C_Network) then
                  FSM.Write (Ctx, FSM.C_Network, Pkt);
               end if;
            end;
         end if;
      end loop Drive_Loop;

      --  Outcome: success requires that we drained a PUBACK on
      --  App_Pending and that its Packet_Identifier matches what we
      --  sent. Anything else is a protocol/peer error.
      FSM.Finalize (Ctx);
      if not Got_Puback then
         raise Publish_Failure with "no PUBACK received";
      elsif Puback_Pid /= Pid then
         raise Publish_Failure with "PUBACK Packet_Identifier mismatch";
      end if;
   end Publish_Qos1_FSM;

   ---------------------------------------------------------------------
   --  Subscribe (single topic)
   ---------------------------------------------------------------------

   procedure Subscribe
     (C     : in out Client;
      Topic : String;
      QoS   : RFLX.Control_Packet.QoS_Level :=
        RFLX.Control_Packet.QOS_0)
   is
      Last       : RFLX.RFLX_Types.Index;
      Pid        : constant Wire.Packet_Identifier := C.Next_Packet_Id;
      Read_Ok    : Boolean;
      Reply_Pid  : Wire.Packet_Identifier;
      Reply_Code : Wire.Suback_Return_Code;
      use type Wire.Suback_Return_Code;
   begin
      C.Next_Packet_Id := C.Next_Packet_Id + 1;

      Wire.Encode_Subscribe_Single
        (C.Buf, Last, Pid, Topic, QoS);
      Transport.Send (C.Trans, C.Buf.all (C.Buf'First .. Last));

      Read_Full_Packet (C, Last, Read_Ok);
      if not Read_Ok then
         raise Subscribe_Failure with "no SUBACK";
      end if;
      Wire.Decode_Suback_Single (C.Buf, Last, Read_Ok, Reply_Pid, Reply_Code);
      if not Read_Ok
        or Reply_Pid /= Pid
        or Reply_Code = Wire.Failure
      then
         raise Subscribe_Failure with "broker refused subscription";
      end if;
   end Subscribe;

   ---------------------------------------------------------------------
   --  Unsubscribe (single topic)
   ---------------------------------------------------------------------

   procedure Unsubscribe
     (C     : in out Client;
      Topic : String)
   is
      Last      : RFLX.RFLX_Types.Index;
      Pid       : constant Wire.Packet_Identifier := C.Next_Packet_Id;
      Read_Ok   : Boolean;
      Reply_Pid : Wire.Packet_Identifier;
   begin
      C.Next_Packet_Id := C.Next_Packet_Id + 1;

      Wire.Encode_Unsubscribe_Single (C.Buf, Last, Pid, Topic);
      Transport.Send (C.Trans, C.Buf.all (C.Buf'First .. Last));

      Read_Full_Packet (C, Last, Read_Ok);
      if not Read_Ok then
         raise Unsubscribe_Failure with "no UNSUBACK";
      end if;
      Wire.Decode_Unsuback (C.Buf, Last, Read_Ok, Reply_Pid);
      if not Read_Ok or Reply_Pid /= Pid then
         raise Unsubscribe_Failure with "broker UNSUBACK mismatch";
      end if;
   end Unsubscribe;

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
      Last      : RFLX.RFLX_Types.Index;
      Read_Ok   : Boolean;
      Kind      : RFLX.Control_Packet.Packet_Type;
      Pkt_Valid : Boolean;
   begin
      Topic_Last   := Topic'First - 1;
      Payload_Last := 0;

      loop
         Read_Full_Packet (C, Last, Read_Ok);
         if not Read_Ok then
            raise Receive_Failure with "EOF or socket error";
         end if;
         Kind := Wire.Peek_Packet_Type (C.Buf.all (C.Buf'First .. Last));
         if Kind = RFLX.Control_Packet.PUBLISH then
            Wire.Decode_Publish_Qos0
              (C.Buf, Last, Pkt_Valid, Topic, Topic_Last,
               Payload, Payload_Last);
            if not Pkt_Valid then
               raise Receive_Failure with "malformed PUBLISH";
            end if;
            return;
         end if;
         --  PINGRESP / other: discard and keep listening.
      end loop;
   end Receive_Publish;

   ---------------------------------------------------------------------
   --  Close
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
               null;  --  best-effort: socket may already be torn down
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
