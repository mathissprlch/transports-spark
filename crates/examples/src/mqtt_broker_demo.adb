--  mqtt_broker_demo — first Ada-implemented MQTT 3.1.1 broker.
--
--  Single-client v0.2 broker. Accepts one TCP connection on
--  port 1883 (default), drives the Session::Broker_Reading FSM
--  through CONNECT/CONNACK + dispatch loop, prints each inbound
--  application packet, ACKs at protocol level (CONNACK / SUBACK
--  / PUBACK / PINGRESP). No topic routing — broker is a sink.
--
--  Verified against:
--    * mqtt_demo (Ada client)
--    * mosquitto_pub / mosquitto_sub
--
--  Run:
--    ./bin/mqtt_broker_demo [port]
--    (then in another shell, e.g.):
--    docker exec mqtt-soak-mosq mosquitto_pub -p 1883 -t test -m hello

with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Exceptions;

with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.RFLX_Builtin_Types;
with RFLX.Control_Packet;

with Mqtt_Core.Broker;

procedure Mqtt_Broker_Demo is
   use Ada.Text_IO;

   procedure On_Event
     (Kind         : Mqtt_Core.Broker.Event_Kind;
      Client_Id    : String;
      Client_Id_Last : Natural;
      Topic        : String;
      Topic_Last   : Natural;
      Payload      : RFLX.RFLX_Types.Bytes;
      Payload_Last : RFLX.RFLX_Types.Length;
      QoS          : RFLX.Control_Packet.QoS_Level;
      Packet_Id    : RFLX.RFLX_Builtin_Types.Bit_Length);

   procedure On_Event
     (Kind         : Mqtt_Core.Broker.Event_Kind;
      Client_Id    : String;
      Client_Id_Last : Natural;
      Topic        : String;
      Topic_Last   : Natural;
      Payload      : RFLX.RFLX_Types.Bytes;
      Payload_Last : RFLX.RFLX_Types.Length;
      QoS          : RFLX.Control_Packet.QoS_Level;
      Packet_Id    : RFLX.RFLX_Builtin_Types.Bit_Length)
   is
      use type Mqtt_Core.Broker.Event_Kind;
      Cid_View : constant String :=
        Client_Id (Client_Id'First .. Client_Id'First + Client_Id_Last - 1);
   begin
      case Kind is
         when Mqtt_Core.Broker.Client_Connected =>
            Put_Line ("[broker] CONNECT from " & Cid_View);
         when Mqtt_Core.Broker.Client_Subscribed =>
            Put_Line
              ("[broker] SUBSCRIBE pid=" & Packet_Id'Image
               & " topic="
               & Topic (Topic'First .. Topic'First + Topic_Last - 1)
               & " QoS=" & QoS'Image);
         when Mqtt_Core.Broker.Publish_Received =>
            declare
               Payload_Str : String
                 (1 .. Natural (Payload_Last)) := (others => ' ');
            begin
               for I in 1 .. Natural (Payload_Last) loop
                  Payload_Str (I) :=
                    Character'Val (Natural (Payload (Payload'First +
                      RFLX.RFLX_Types.Index (I) - 1)));
               end loop;
               Put_Line
                 ("[broker] PUBLISH topic="
                  & Topic (Topic'First .. Topic'First + Topic_Last - 1)
                  & " QoS=" & QoS'Image
                  & " pid=" & Packet_Id'Image
                  & " payload=""" & Payload_Str & """");
            end;
         when Mqtt_Core.Broker.Pingreq_Received =>
            Put_Line ("[broker] PINGREQ → PINGRESP");
         when Mqtt_Core.Broker.Client_Disconnected =>
            Put_Line ("[broker] DISCONNECT from " & Cid_View);
      end case;
   end On_Event;

   procedure Serve is new Mqtt_Core.Broker.Accept_And_Serve
     (On_Event => On_Event);

   Port : Natural := 1883;
   L    : Mqtt_Core.Broker.Listener;
   Buf  : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. 4096 => 0);
   Inbound_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. 4096 => 0);
   Outgoing_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. 4096 => 0);
begin
   if Ada.Command_Line.Argument_Count >= 1 then
      Port := Natural'Value (Ada.Command_Line.Argument (1));
   end if;

   Mqtt_Core.Broker.Attach_Buffers
     (L, Buf, Inbound_Buf, Outgoing_Buf);
   Mqtt_Core.Broker.Listen (L, "0.0.0.0", Port);
   Put_Line ("mqtt_broker_demo: listening on 0.0.0.0:" & Port'Image);

   loop
      Put_Line ("mqtt_broker_demo: awaiting client...");
      begin
         Serve (L);
      exception
         when E : others =>
            Put_Line ("mqtt_broker_demo: session ended: "
                      & Ada.Exceptions.Exception_Name (E)
                      & ": "
                      & Ada.Exceptions.Exception_Message (E));
      end;
   end loop;
end Mqtt_Broker_Demo;
