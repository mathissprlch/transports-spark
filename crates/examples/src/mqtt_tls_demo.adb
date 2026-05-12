--  mqtt_tls_demo — MQTT 3.1.1 over TLS 1.3 end-to-end.
--
--  Proves the full stack: SPARK TLS 1.3 handshake → encrypted
--  MQTT CONNECT/SUBSCRIBE/PUBLISH/DISCONNECT over our own
--  pure-Ada/SPARK crypto, no OpenSSL dependency on the client.
--
--  Usage:
--    TRANSPORT=tls alr -C crates/examples build
--    docker run --rm -p 8883:8883 \
--      -v $PWD/crates/tls_core/tests/fixtures/interop/ec:/certs:ro \
--      eclipse-mosquitto sh -c \
--        'printf "listener 8883\ncafile /certs/root.pem\n\
--    certfile /certs/leaf.pem\nkeyfile /certs/leaf.key\n\
--    allow_anonymous true\n" > /mosquitto/config/mosquitto.conf \
--      && mosquitto -c /mosquitto/config/mosquitto.conf'
--    ./bin/mqtt_tls_demo
--
--  Expected output:
--    mqtt_tls_demo: TLS handshake + MQTT CONNECT to localhost:8883
--    mqtt_tls_demo: connected over TLS
--    mqtt_tls_demo: published "hello over TLS" to ada/tls
--    mqtt_tls_demo: disconnected. ok.

with Ada.Text_IO;
with Ada.Streams.Stream_IO;
with RFLX.RFLX_Types;
use type RFLX.RFLX_Types.Index;
with Mqtt_Core.Client;

procedure Mqtt_Tls_Demo is

   use Ada.Text_IO;

   function To_Bytes (S : String) return RFLX.RFLX_Types.Bytes is
      R : RFLX.RFLX_Types.Bytes (1 .. S'Length);
      D : RFLX.RFLX_Types.Index := R'First;
   begin
      for I in S'Range loop
         R (D) := RFLX.RFLX_Types.Byte (Character'Pos (S (I)));
         exit when I = S'Last;
         D := D + 1;
      end loop;
      return R;
   end To_Bytes;

   function Load_Der (Path : String) return RFLX.RFLX_Types.Bytes is
      use Ada.Streams;
      F : Stream_IO.File_Type;
   begin
      Stream_IO.Open (F, Stream_IO.In_File, Path);
      declare
         N   : constant Stream_Element_Offset :=
           Stream_Element_Offset (Stream_IO.Size (F));
         Buf : Stream_Element_Array (1 .. N);
         Last : Stream_Element_Offset;
         Res : RFLX.RFLX_Types.Bytes (1 .. RFLX.RFLX_Types.Index (N));
      begin
         Stream_IO.Read (F, Buf, Last);
         Stream_IO.Close (F);
         for I in 1 .. RFLX.RFLX_Types.Index (Last) loop
            Res (I) := RFLX.RFLX_Types.Byte
              (Buf (Stream_Element_Offset (I)));
         end loop;
         return Res;
      end;
   exception
      when others =>
         if Stream_IO.Is_Open (F) then Stream_IO.Close (F); end if;
         Put_Line ("mqtt_tls_demo: cannot read " & Path);
         return RFLX.RFLX_Types.Bytes'(1 .. 0 => 0);
   end Load_Der;

   EC_Dir : constant String :=
     "crates/tls_core/tests/fixtures/interop/ec";

   Client : Mqtt_Core.Client.Client;

   Buf      : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. 256 => 0);
   Inbound  : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. 256 => 0);
   Outgoing : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. 256 => 0);

begin
   Put_Line ("mqtt_tls_demo: TLS handshake + MQTT CONNECT "
             & "to localhost:8883");

   Mqtt_Core.Client.Attach_Buffers (Client, Buf, Inbound, Outgoing);

   declare
      Trust : constant RFLX.RFLX_Types.Bytes :=
        Load_Der (EC_Dir & "/root.der");
   begin
      if Trust'Length = 0 then
         Put_Line ("mqtt_tls_demo: no trust anchor — aborting");
         return;
      end if;
      Mqtt_Core.Client.Configure_Tls_Client (Client, Trust);
   end;

   Mqtt_Core.Client.Open
     (Client,
      Host          => "127.0.0.1",
      Port          => 8883,
      Client_Id     => "ada-mqtt-tls",
      Keep_Alive_S  => 30,
      Clean_Session => True);
   Put_Line ("mqtt_tls_demo: connected over TLS");

   Mqtt_Core.Client.Publish
     (Client, "ada/tls", To_Bytes ("hello over TLS"));
   Put_Line ("mqtt_tls_demo: published ""hello over TLS"" to ada/tls");

   Mqtt_Core.Client.Close (Client);
   Put_Line ("mqtt_tls_demo: disconnected. ok.");

exception
   when others =>
      Put_Line ("mqtt_tls_demo: exception during TLS+MQTT handshake");
end Mqtt_Tls_Demo;
