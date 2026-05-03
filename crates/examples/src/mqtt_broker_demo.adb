--  mqtt_broker_demo — multi-client MQTT 3.1.1 broker.
--
--  Up to 16 concurrent clients (Mqtt_Core.Broker.Max_Clients) on
--  one TCP port. Topic-routed PUBLISH delivery between subscribers.
--  No retained messages, no will, no persistent session, no MQTT 5.0.
--
--  Run:
--    ./bin/mqtt_broker_demo [port]   # default 1883
--
--  Test (in a second / third shell):
--    mosquitto_sub -V mqttv311 -i sub-1 -t hello/+ -p 1883
--    mosquitto_pub -V mqttv311 -i pub-1 -t hello/world -m 'hi' -p 1883

with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Exceptions;

with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.Control_Packet;

with Mqtt_Core.Broker;

procedure Mqtt_Broker_Demo is
   use Ada.Text_IO;

   procedure On_Event
     (Kind         : Mqtt_Core.Broker.Event_Kind;
      Client_Id    : String;
      Topic        : String;
      Payload      : RFLX.RFLX_Types.Bytes;
      QoS          : RFLX.Control_Packet.QoS_Level;
      Subscriber_Count : Natural);

   procedure On_Event
     (Kind         : Mqtt_Core.Broker.Event_Kind;
      Client_Id    : String;
      Topic        : String;
      Payload      : RFLX.RFLX_Types.Bytes;
      QoS          : RFLX.Control_Packet.QoS_Level;
      Subscriber_Count : Natural)
   is
      use type Mqtt_Core.Broker.Event_Kind;
   begin
      case Kind is
         when Mqtt_Core.Broker.Client_Connected =>
            Put_Line ("[broker] CONNECT from " & Client_Id);
         when Mqtt_Core.Broker.Client_Subscribed =>
            Put_Line
              ("[broker] " & Client_Id & " SUBSCRIBE topic="
               & Topic & " QoS=" & QoS'Image);
         when Mqtt_Core.Broker.Client_Unsubscribed =>
            Put_Line
              ("[broker] " & Client_Id & " UNSUBSCRIBE topic=" & Topic);
         when Mqtt_Core.Broker.Publish_Received =>
            declare
               Payload_Str : String (1 .. Payload'Length) :=
                 (others => ' ');
            begin
               for I in 1 .. Payload'Length loop
                  Payload_Str (I) :=
                    Character'Val (Natural (Payload (Payload'First +
                      RFLX.RFLX_Types.Index'Base (I) - 1)));
               end loop;
               Put_Line
                 ("[broker] " & Client_Id & " PUBLISH topic="
                  & Topic & " QoS=" & QoS'Image
                  & " payload=""" & Payload_Str
                  & """ → " & Subscriber_Count'Image
                  & " subscriber(s)");
            end;
         when Mqtt_Core.Broker.Publish_Forwarded =>
            null;  --  per-subscriber forward — count summarised above
         when Mqtt_Core.Broker.Pingreq_Received =>
            null;  --  too noisy to log
         when Mqtt_Core.Broker.Client_Disconnected =>
            Put_Line ("[broker] DISCONNECT from " & Client_Id);
      end case;
   end On_Event;

   procedure Serve is new Mqtt_Core.Broker.Run (On_Event => On_Event);

   Port : Natural := 1883;
   L    : Mqtt_Core.Broker.Listener;
begin
   if Ada.Command_Line.Argument_Count >= 1 then
      Port := Natural'Value (Ada.Command_Line.Argument (1));
   end if;

   Mqtt_Core.Broker.Listen (L, "0.0.0.0", Port);
   Put_Line ("mqtt_broker_demo: listening on 0.0.0.0:" & Port'Image
             & " (max"
             & Natural'Image (Mqtt_Core.Broker.Max_Clients)
             & " clients)");

   begin
      Serve (L);
   exception
      when E : others =>
         Put_Line ("mqtt_broker_demo: terminated: "
                   & Ada.Exceptions.Exception_Information (E));
   end;
end Mqtt_Broker_Demo;
