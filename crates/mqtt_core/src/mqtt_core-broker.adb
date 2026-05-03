with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.Suback;
with RFLX.Session.Broker_Reading.FSM;

with Mqtt_Core.Wire;

package body Mqtt_Core.Broker is

   use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;
   use type RFLX.RFLX_Types.Length;
   use type RFLX.Control_Packet.Packet_Type;
   use type RFLX.Control_Packet.QoS_Level;

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural := 1883)
   is
   begin
      Transport.Listen (L.Trans, Host, Port);
   end Listen;

   procedure Stop (L : in out Listener) is
   begin
      if Transport.Is_Listening (L.Trans) then
         Transport.Stop (L.Trans);
      end if;
   end Stop;

   procedure Attach_Buffers
     (L            : in out Listener;
      Buf          : in out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : in out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : in out RFLX.RFLX_Types.Bytes_Ptr)
   is
   begin
      L.Buf := Buf; L.Inbound_Buf := Inbound_Buf;
      L.Outgoing_Buf := Outgoing_Buf;
      Buf := null; Inbound_Buf := null; Outgoing_Buf := null;
   end Attach_Buffers;

   procedure Detach_Buffers
     (L            : in out Listener;
      Buf          : out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : out RFLX.RFLX_Types.Bytes_Ptr)
   is
   begin
      Buf := L.Buf; Inbound_Buf := L.Inbound_Buf;
      Outgoing_Buf := L.Outgoing_Buf;
      L.Buf := null; L.Inbound_Buf := null; L.Outgoing_Buf := null;
   end Detach_Buffers;

   --  Read one full MQTT control packet from the socket into Buf.
   --  Same single-byte-RL form as the client's Read_Full_Packet.
   procedure Read_Full_Packet
     (Chan    : Transport.Channel;
      Buf     : RFLX.RFLX_Types.Bytes_Ptr;
      Last    :    out RFLX.RFLX_Types.Index;
      Success :    out Boolean);

   procedure Read_Full_Packet
     (Chan    : Transport.Channel;
      Buf     : RFLX.RFLX_Types.Bytes_Ptr;
      Last    :    out RFLX.RFLX_Types.Index;
      Success :    out Boolean)
   is
      Hdr : RFLX.RFLX_Types.Bytes (Buf'First .. Buf'First + 1);
      Hdr_OK : Boolean;
   begin
      Last := Buf'First;
      Success := False;
      Transport.Receive_Full (Chan, Hdr, Hdr_OK);
      if not Hdr_OK then return; end if;
      Buf.all (Buf'First .. Buf'First + 1) := Hdr;
      declare
         RL : constant Natural := Natural (Buf.all (Buf'First + 1));
      begin
         if RL = 0 then
            Last := Buf'First + 1;
            Success := True;
            return;
         end if;
         declare
            Body_Slice : RFLX.RFLX_Types.Bytes
              (Buf'First + 2 ..
                 Buf'First + 1 + RFLX.RFLX_Types.Index (RL));
            Body_OK : Boolean;
         begin
            Transport.Receive_Full (Chan, Body_Slice, Body_OK);
            if not Body_OK then return; end if;
            Buf.all (Body_Slice'Range) := Body_Slice;
            Last := Body_Slice'Last;
            Success := True;
         end;
      end;
   end Read_Full_Packet;

   procedure Accept_And_Serve (L : in out Listener)
   is
      Chan : Transport.Channel;

      package FSM renames RFLX.Session.Broker_Reading.FSM;
      Ctx : FSM.Context;

      Client_Id : String (1 .. 64) := (others => ' ');
      Cid_Last  : Natural := 0;
   begin
      if L.Buf = null
        or else L.Inbound_Buf = null
        or else L.Outgoing_Buf = null
      then
         raise Server_Error with "Attach_Buffers required";
      end if;

      Transport.Accept_One (L.Trans, Chan);

      FSM.Initialize (Ctx, L.Inbound_Buf);

      --  Pre-feed the first packet (CONNECT). The FSM's first state
      --  Awaiting_Connect blocks on Network'Read; without pre-feeding
      --  the FSM goes straight to Final on its first Run.
      declare
         Last : RFLX.RFLX_Types.Index;
         Read_OK : Boolean;
      begin
         Read_Full_Packet (Chan, L.Buf, Last, Read_OK);
         if not Read_OK then
            FSM.Finalize (Ctx, L.Inbound_Buf);
            Transport.Close (Chan);
            raise Server_Error with "EOF before CONNECT";
         end if;
         if FSM.Needs_Data (Ctx, FSM.C_Network) then
            FSM.Write
              (Ctx, FSM.C_Network,
               L.Buf.all (L.Buf'First .. Last));
         end if;
      end;

      --  Main driver loop. The FSM dispatches inbound by Packet_Type;
      --  we react per Packet_Type (decode + ACK + emit On_Event).
      Drive :
      loop
         FSM.Run (Ctx);
         exit Drive when not FSM.Active (Ctx);

         if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
            declare
               N : constant RFLX.RFLX_Types.Length :=
                 FSM.Read_Buffer_Size (Ctx, FSM.C_App_Pending);
               View : RFLX.RFLX_Types.Bytes
                 (L.Buf'First ..
                    L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
            begin
               FSM.Read (Ctx, FSM.C_App_Pending, View);
               if View'Length < 2 then
                  FSM.Finalize (Ctx, L.Inbound_Buf);
                  Transport.Close (Chan);
                  raise Server_Error with "short pending packet";
               end if;
               --  Stash bytes into L.Buf and dispatch by peeked type.
               L.Buf.all (View'Range) := View;
               case Wire.Peek_Packet_Type (View) is
                  when RFLX.Control_Packet.CONNECT =>
                     declare
                        Valid : Boolean;
                     begin
                        Wire.Decode_Connect
                          (L.Buf, View'Last, Valid,
                           Client_Id, Cid_Last);
                        if not Valid then
                           FSM.Finalize (Ctx, L.Inbound_Buf);
                           Transport.Close (Chan);
                           raise Server_Error with "bad CONNECT";
                        end if;
                     end;
                     declare
                        Conn_Last : RFLX.RFLX_Types.Index;
                     begin
                        Wire.Encode_Connack (L.Buf, Conn_Last);
                        Transport.Send
                          (Chan, L.Buf.all (L.Buf'First .. Conn_Last));
                     end;
                     declare
                        Empty : constant RFLX.RFLX_Types.Bytes
                          (1 .. 0) := (others => 0);
                     begin
                        On_Event
                          (Kind => Client_Connected,
                           Client_Id => Client_Id,
                           Client_Id_Last => Cid_Last,
                           Topic => "", Topic_Last => 0,
                           Payload => Empty, Payload_Last => 0,
                           QoS => RFLX.Control_Packet.QOS_0,
                           Packet_Id => 0);
                     end;

                  when RFLX.Control_Packet.SUBSCRIBE =>
                     declare
                        Valid : Boolean;
                        Pid   : Wire.Packet_Identifier;
                        Topic : String (1 .. 256);
                        Topic_Last : Natural;
                        Req_QoS : RFLX.Control_Packet.QoS_Level;
                     begin
                        Wire.Decode_Subscribe
                          (L.Buf, View'Last, Valid, Pid,
                           Topic, Topic_Last, Req_QoS);
                        if Valid then
                           --  Echo SUBACK with granted QoS = requested.
                           declare
                              Sub_Last : RFLX.RFLX_Types.Index;
                              use type RFLX.Control_Packet.QoS_Level;
                           begin
                              Wire.Encode_Suback_Single
                                (L.Buf, Sub_Last, Pid,
                                 Granted_QoS =>
                                   (case Req_QoS is
                                      when RFLX.Control_Packet.QOS_0 =>
                                         RFLX.Suback.SUCCESS_QOS_0,
                                      when RFLX.Control_Packet.QOS_1 =>
                                         RFLX.Suback.SUCCESS_QOS_1,
                                      when RFLX.Control_Packet.QOS_2 =>
                                         RFLX.Suback.SUCCESS_QOS_2));
                              Transport.Send
                                (Chan,
                                 L.Buf.all (L.Buf'First .. Sub_Last));
                           end;
                           declare
                              Empty : constant RFLX.RFLX_Types.Bytes
                                (1 .. 0) := (others => 0);
                           begin
                              On_Event
                                (Kind => Client_Subscribed,
                                 Client_Id => Client_Id,
                                 Client_Id_Last => Cid_Last,
                                 Topic => Topic,
                                 Topic_Last => Topic_Last,
                                 Payload => Empty, Payload_Last => 0,
                                 QoS => Req_QoS,
                                 Packet_Id =>
                                   RFLX.RFLX_Builtin_Types.Bit_Length
                                     (Pid));
                           end;
                        end if;
                     end;

                  when RFLX.Control_Packet.PUBLISH =>
                     declare
                        Topic : String (1 .. 256);
                        Topic_Last : Natural;
                        Payload : RFLX.RFLX_Types.Bytes (1 .. 1024);
                        Payload_Last : RFLX.RFLX_Types.Length;
                        QoS : RFLX.Control_Packet.QoS_Level;
                        Pid : Wire.Packet_Identifier;
                        Decode_OK : Boolean;
                     begin
                        Wire.Decode_Publish
                          (L.Buf, View'Last, Decode_OK,
                           QoS, Pid, Topic, Topic_Last,
                           Payload, Payload_Last);
                        if Decode_OK then
                           if QoS = RFLX.Control_Packet.QOS_1 then
                              declare
                                 Ack_Last : RFLX.RFLX_Types.Index;
                              begin
                                 Wire.Encode_Puback
                                   (L.Buf, Ack_Last, Pid);
                                 Transport.Send
                                   (Chan,
                                    L.Buf.all
                                      (L.Buf'First .. Ack_Last));
                              end;
                           end if;
                           On_Event
                             (Kind => Publish_Received,
                              Client_Id => Client_Id,
                              Client_Id_Last => Cid_Last,
                              Topic => Topic,
                              Topic_Last => Topic_Last,
                              Payload => Payload,
                              Payload_Last => Payload_Last,
                              QoS => QoS,
                              Packet_Id =>
                                RFLX.RFLX_Builtin_Types.Bit_Length
                                  (Pid));
                        end if;
                     end;

                  when RFLX.Control_Packet.PINGREQ =>
                     declare
                        Resp_Last : RFLX.RFLX_Types.Index;
                        Empty : constant RFLX.RFLX_Types.Bytes
                          (1 .. 0) := (others => 0);
                     begin
                        Wire.Encode_Pingresp (L.Buf, Resp_Last);
                        Transport.Send
                          (Chan,
                           L.Buf.all (L.Buf'First .. Resp_Last));
                        On_Event
                          (Kind => Pingreq_Received,
                           Client_Id => Client_Id,
                           Client_Id_Last => Cid_Last,
                           Topic => "", Topic_Last => 0,
                           Payload => Empty, Payload_Last => 0,
                           QoS => RFLX.Control_Packet.QOS_0,
                           Packet_Id => 0);
                     end;

                  when RFLX.Control_Packet.DISCONNECT =>
                     declare
                        Empty : constant RFLX.RFLX_Types.Bytes
                          (1 .. 0) := (others => 0);
                     begin
                        On_Event
                          (Kind => Client_Disconnected,
                           Client_Id => Client_Id,
                           Client_Id_Last => Cid_Last,
                           Topic => "", Topic_Last => 0,
                           Payload => Empty, Payload_Last => 0,
                           QoS => RFLX.Control_Packet.QOS_0,
                           Packet_Id => 0);
                     end;
                     exit Drive;

                  when others =>
                     --  PUBACK / PUBREC / PUBREL / PUBCOMP / UNSUBSCRIBE
                     --  — v0.2 broker has no outbound publish flow
                     --  yet, so these are accepted-and-ignored.
                     null;
               end case;
            end;
         end if;

         if FSM.Needs_Data (Ctx, FSM.C_Network) then
            declare
               Last : RFLX.RFLX_Types.Index;
               Read_OK : Boolean;
            begin
               Read_Full_Packet (Chan, L.Buf, Last, Read_OK);
               if not Read_OK then
                  exit Drive;
               end if;
               if FSM.Needs_Data (Ctx, FSM.C_Network) then
                  FSM.Write
                    (Ctx, FSM.C_Network,
                     L.Buf.all (L.Buf'First .. Last));
               end if;
            end;
         end if;
      end loop Drive;

      FSM.Finalize (Ctx, L.Inbound_Buf);
      if Transport.Is_Open (Chan) then
         Transport.Close (Chan);
      end if;
   end Accept_And_Serve;

end Mqtt_Core.Broker;
