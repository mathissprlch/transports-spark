--  mqtt_demo_tls -- MQTT 3.1.1 client over TLS 1.3.
--
--  Same logic as mqtt_demo, but the transport is our pure-Ada/SPARK
--  TLS 1.3. Build with -XTRANSPORT=tls.
--
--  Run a TLS-enabled Mosquitto first:
--    docker run --rm -d -p 8883:8883 --name mqtt-tls \
--      -v $PWD/../tls_core/tests/fixtures/interop/ec:/certs:ro \
--      -v $PWD/../../scripts/mosquitto-tls.conf:/mosquitto/config/mosquitto.conf:ro \
--      eclipse-mosquitto

with Ada.Text_IO;
with Ada.Directories;
with Ada.Streams.Stream_IO;

with RFLX.RFLX_Types;
use type RFLX.RFLX_Types.Index;
use type RFLX.RFLX_Types.Length;

with RFLX.Control_Packet;
with Mqtt_Core.Client;
with Mqtt_Core.Transport;
with Mqtt_Core.Wire;

procedure Mqtt_Demo_Tls is

   use Ada.Text_IO;

   Root_Path : constant String :=
     "../tls_core/tests/fixtures/interop/ec/root.der";

   function Load_File (Path : String) return RFLX.RFLX_Types.Bytes;
   function Load_File (Path : String) return RFLX.RFLX_Types.Bytes is
      use Ada.Streams;
      F    : Ada.Streams.Stream_IO.File_Type;
      Sz   : constant Natural :=
        Natural (Ada.Directories.Size (Path));
      Buf  : Stream_Element_Array (1 .. Stream_Element_Offset (Sz));
      Last : Stream_Element_Offset;
      Result : RFLX.RFLX_Types.Bytes (1 .. RFLX.RFLX_Types.Index (Sz));
   begin
      Ada.Streams.Stream_IO.Open (F, Ada.Streams.Stream_IO.In_File, Path);
      Ada.Streams.Read (Ada.Streams.Stream_IO.Stream (F).all, Buf, Last);
      Ada.Streams.Stream_IO.Close (F);
      for I in Result'Range loop
         Result (I) := RFLX.RFLX_Types.Byte (
           Buf (Stream_Element_Offset (I)));
      end loop;
      return Result;
   end Load_File;

   function To_Bytes (S : String) return RFLX.RFLX_Types.Bytes;
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

   Topic  : constant String := "ada/tls-test";
   Client : aliased Mqtt_Core.Client.Client;

   Buffer_Capacity : constant := 256;
   Buf      : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
   Inbound  : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
   Outgoing : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);

   Root_Der : constant RFLX.RFLX_Types.Bytes := Load_File (Root_Path);
   Port     : constant Natural := 8883;
begin
   Put_Line ("mqtt_demo_tls: connecting to localhost:" & Port'Image
             & " (TLS 1.3)...");
   Mqtt_Core.Client.Attach_Buffers (Client, Buf, Inbound, Outgoing);

   Mqtt_Core.Transport.Set_Trust_Anchor
     (Mqtt_Core.Client.Get_Transport (Client).all, Root_Der);

   Mqtt_Core.Client.Open
     (Client,
      Host          => "127.0.0.1",
      Port          => Port,
      Client_Id     => "ada-mqtt-tls",
      Keep_Alive_S  => 60,
      Clean_Session => True);
   Put_Line ("mqtt_demo_tls: connected.");

   declare
      use Mqtt_Core.Wire;
      Filters : constant Mqtt_Core.Client.Subscription_Filters (1 .. 1) :=
        (1 => Make_Subscription (Topic, RFLX.Control_Packet.QOS_0));
   begin
      Mqtt_Core.Client.Subscribe_Many (Client, Filters);
      Put_Line ("mqtt_demo_tls: subscribed to " & Topic);
   end;

   Mqtt_Core.Client.Publish (Client, Topic, To_Bytes ("hello over TLS"));
   Put_Line ("mqtt_demo_tls: published 14B");

   declare
      Recv_Topic   : String (1 .. 128);
      Recv_T_Last  : Natural;
      Recv_Payload : RFLX.RFLX_Types.Bytes (1 .. 256);
      Recv_P_Last  : RFLX.RFLX_Types.Length;
   begin
      Mqtt_Core.Client.Receive_Publish
        (Client, Recv_Topic, Recv_T_Last, Recv_Payload, Recv_P_Last);
      Put_Line ("mqtt_demo_tls: received: " &
        To_String (Recv_Payload, Recv_P_Last));
   end;

   Mqtt_Core.Client.Close (Client);
   Mqtt_Core.Client.Detach_Buffers (Client, Buf, Inbound, Outgoing);
   RFLX.RFLX_Types.Free (Buf);
   RFLX.RFLX_Types.Free (Inbound);
   RFLX.RFLX_Types.Free (Outgoing);
   Put_Line ("mqtt_demo_tls: disconnected. ok.");
end Mqtt_Demo_Tls;
