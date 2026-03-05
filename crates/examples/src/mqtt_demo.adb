--  mqtt_demo — exercises the SPARK MQTT 3.1.1 client end-to-end.
--
--  Multi-stage demo against any compliant 3.1.1 broker on
--  127.0.0.1:1883:
--    1. CONNECT + CONNACK handshake
--    2. SUBSCRIBE to ada/test, await SUBACK
--    3. Three publish/receive round trips, including one near the
--       single-byte Remaining-Length cap
--    4. DISCONNECT and clean socket close
--
--  Run a broker first, e.g.:
--    docker run --rm -p 1883:1883 eclipse-mosquitto

with Ada.Text_IO;
with RFLX.RFLX_Types;
use type RFLX.RFLX_Types.Index;
with Mqtt_Core.Client;

procedure Mqtt_Demo is

   use Ada.Text_IO;

   --  Helpers to bridge Ada String and RFLX_Types.Bytes for ASCII.

   function To_Bytes (S : String) return RFLX.RFLX_Types.Bytes;
   function To_String
     (B : RFLX.RFLX_Types.Bytes; Last : RFLX.RFLX_Types.Length) return String;

   function To_Bytes (S : String) return RFLX.RFLX_Types.Bytes is
      Out_Bytes : RFLX.RFLX_Types.Bytes (1 .. S'Length);
      Dst       : RFLX.RFLX_Types.Index := Out_Bytes'First;
   begin
      for Src in S'Range loop
         Out_Bytes (Dst) :=
           RFLX.RFLX_Types.Byte (Character'Pos (S (Src)));
         exit when Src = S'Last;
         Dst := Dst + 1;
      end loop;
      return Out_Bytes;
   end To_Bytes;

   function To_String
     (B : RFLX.RFLX_Types.Bytes; Last : RFLX.RFLX_Types.Length) return String
   is
      Result : String (1 .. Natural (Last));
      Src    : RFLX.RFLX_Types.Index := B'First;
   begin
      for Dst in Result'Range loop
         Result (Dst) := Character'Val (Natural (B (Src)));
         exit when Dst = Result'Last;
         Src := Src + 1;
      end loop;
      return Result;
   end To_String;

   --  Send `Payload` then immediately consume the broker's echo of it
   --  (we are subscribed to the topic we publish on). Reports the
   --  topic + payload of the round trip and flags any mismatch.
   procedure Round_Trip
     (C       : in out Mqtt_Core.Client.Client;
      Topic   : String;
      Payload : String);

   procedure Round_Trip
     (C       : in out Mqtt_Core.Client.Client;
      Topic   : String;
      Payload : String)
   is
      Recv_Topic   : String (1 .. 128);
      Recv_T_Last  : Natural;
      Recv_Payload : RFLX.RFLX_Types.Bytes (1 .. 256);
      Recv_P_Last  : RFLX.RFLX_Types.Length;
   begin
      Mqtt_Core.Client.Publish (C, Topic, To_Bytes (Payload));
      Put_Line
        ("  -> published" & Integer'Image (Payload'Length)
         & "B to " & Topic);
      Mqtt_Core.Client.Receive_Publish
        (C, Recv_Topic, Recv_T_Last, Recv_Payload, Recv_P_Last);
      declare
         Got : constant String := To_String (Recv_Payload, Recv_P_Last);
      begin
         if Recv_Topic (Recv_Topic'First .. Recv_T_Last) /= Topic then
            Put_Line ("  !! topic mismatch: got "
                      & Recv_Topic (Recv_Topic'First .. Recv_T_Last));
         elsif Got /= Payload then
            Put_Line ("  !! payload mismatch:");
            Put_Line ("     sent: " & Payload);
            Put_Line ("     got:  " & Got);
         else
            Put_Line ("  <- echoed" & Integer'Image (Got'Length)
                      & "B ok");
         end if;
      end;
   end Round_Trip;

   --  Bigger payload to exercise the spec's single-byte
   --  Remaining-Length cap. Total wire frame for PUBLISH must satisfy
   --  2 + topic + payload <= 127, i.e. payload <= 117 with this topic.
   Big_Payload : constant String :=
     "abcdefghijklmnopqrstuvwxyz"
     & "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
     & "0123456789"
     & "abcdefghijklmnopqrstuvwxyz"
     & "ABCDEFGHIJKLMNOPQ";  --  total = 26+26+10+26+17 = 105 chars

   Topic  : constant String := "ada/test";
   Client : Mqtt_Core.Client.Client;

begin
   Put_Line ("mqtt_demo: connecting to localhost:1883...");
   Mqtt_Core.Client.Open
     (Client,
      Host          => "127.0.0.1",
      Port          => 1883,
      Client_Id     => "ada-mqtt-demo",
      Keep_Alive_S  => 60,
      Clean_Session => True);
   Put_Line ("mqtt_demo: connected.");

   Mqtt_Core.Client.Subscribe (Client, Topic);
   Put_Line ("mqtt_demo: subscribed to " & Topic);

   Put_Line ("mqtt_demo: round-trip 1 (small)");
   Round_Trip (Client, Topic, "Hello, MQTT!");

   Put_Line ("mqtt_demo: round-trip 2 (medium)");
   Round_Trip (Client, Topic, "second message - same buffer reused, no heap");

   Put_Line ("mqtt_demo: round-trip 3 (near RL cap)");
   Round_Trip (Client, Topic, Big_Payload);

   --  QoS 1 publish to the topic we're subscribed to. The broker
   --  will echo the PUBLISH back to us (as subscriber) AND send the
   --  PUBACK (as publisher) on the same socket; the FSM-driven
   --  Publish_Qos1 enqueues the PUBLISH for Receive_Publish to drain
   --  while it waits for the PUBACK. No data dropped, dispatch
   --  exhaustively verified at spec-compile time.
   Put_Line ("mqtt_demo: QoS 1 publish (FSM-driven, awaits PUBACK)");
   Mqtt_Core.Client.Publish_Qos1
     (Client, Topic,
      To_Bytes ("qos-1 hello, dispatch verified by RecordFlux"));
   Put_Line ("  -> publish acked");

   --  Drain the QoS 1 echo that was queued by Publish_Qos1 (it was
   --  forwarded on App_Pending while the FSM waited for PUBACK).
   Put_Line ("mqtt_demo: draining queued PUBLISH from Publish_Qos1");
   declare
      Recv_Topic   : String (1 .. 128);
      Recv_T_Last  : Natural;
      Recv_Payload : RFLX.RFLX_Types.Bytes (1 .. 256);
      Recv_P_Last  : RFLX.RFLX_Types.Length;
   begin
      Mqtt_Core.Client.Receive_Publish
        (Client, Recv_Topic, Recv_T_Last,
         Recv_Payload, Recv_P_Last);
      Put_Line
        ("  <- queued echo: """
         & To_String (Recv_Payload, Recv_P_Last) & """");
   end;

   Mqtt_Core.Client.Unsubscribe (Client, Topic);
   Put_Line ("mqtt_demo: unsubscribed from " & Topic);

   Mqtt_Core.Client.Close (Client);
   Put_Line ("mqtt_demo: disconnected. ok.");
end Mqtt_Demo;
