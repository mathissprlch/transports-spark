--  mqtt_demo — exercises the v0.2 SPARK MQTT 3.1.1 client end-to-end.
--
--  Connects to localhost:1883 (Mosquitto), subscribes to `ada/test`,
--  publishes a "Hello, MQTT!" payload on the same topic, then waits
--  for the broker to deliver it back. Disconnects cleanly.
--
--  Run a broker first, e.g.:
--    docker run --rm -p 1883:1883 eclipse-mosquitto
--    --or--
--    brew services start mosquitto

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

   Topic        : constant String := "ada/test";
   Hello        : constant String := "Hello, MQTT!";
   Topic_Buf    : String (1 .. 128);
   Topic_Last   : Natural;
   Payload_Buf  : RFLX.RFLX_Types.Bytes (1 .. 256);
   Payload_Last : RFLX.RFLX_Types.Length;
   Client       : Mqtt_Core.Client.Client;

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

   Mqtt_Core.Client.Publish (Client, Topic, To_Bytes (Hello));
   Put_Line ("mqtt_demo: published """ & Hello & """ to " & Topic);

   Mqtt_Core.Client.Receive_Publish
     (Client, Topic_Buf, Topic_Last, Payload_Buf, Payload_Last);
   Put_Line
     ("mqtt_demo: received topic="
      & Topic_Buf (Topic_Buf'First .. Topic_Last)
      & " payload=""" & To_String (Payload_Buf, Payload_Last) & """");

   Mqtt_Core.Client.Close (Client);
   Put_Line ("mqtt_demo: disconnected. ok.");
end Mqtt_Demo;
