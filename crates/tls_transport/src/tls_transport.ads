--  Tls_Transport — TLS 1.3 transport with the same API shape as
--  Http2_Core.Transport / Mqtt_Core.Transport (tcp variant).
--
--  Connect does TCP connect + TLS handshake; Send/Receive do
--  AEAD encrypt/decrypt transparently. The protocol layer above
--  (HTTP/2, MQTT, gRPC, HTTP/1.1) never sees TLS records.
--
--  Selected by -XTRANSPORT=tls in the per-crate .gpr file.
--  The per-crate transport_tls/ wrapper delegates to this crate
--  and adds protocol-specific config (ALPN, SNI).

with Tls_Core;
with Tls_Core.Aead_Channel;
with Tls_Core.Tls13_Driver;
with Tls_Core.Tcp_Transport;

package Tls_Transport
with SPARK_Mode => Off
is

   Max_Hostname : constant := 255;
   Max_Alpn     : constant := 255;
   Max_Trust    : constant := 8192;

   type Tls_Mode is (Cert_Ec, Psk_External, Psk_Resume);

   type Tls_Config is record
      Mode           : Tls_Mode := Cert_Ec;
      Hostname       : String (1 .. Max_Hostname) := (others => ' ');
      Hostname_Len   : Natural := 0;
      Alpn           : String (1 .. Max_Alpn) := (others => ' ');
      Alpn_Len       : Natural := 0;
      Trust_Der      : Tls_Core.Octet_Array (1 .. Max_Trust) :=
        (others => 0);
      Trust_Der_Len  : Natural := 0;
      Cert_Der       : Tls_Core.Octet_Array (1 .. 4096) := (others => 0);
      Cert_Der_Len   : Natural := 0;
      Key_Raw        : Tls_Core.Octet_Array (1 .. 32) := (others => 0);
      Key_Raw_Len    : Natural := 0;
   end record;

   type Channel is limited private;

   procedure Connect
     (Chan   : in out Channel;
      Host   : String;
      Port   : Natural;
      Config : Tls_Config);

   function Is_Open (Chan : Channel) return Boolean;

   procedure Send
     (Chan : in out Channel;
      Data : Tls_Core.Octet_Array)
   with Pre => Is_Open (Chan);

   procedure Receive
     (Chan    : in out Channel;
      Buffer  : out Tls_Core.Octet_Array;
      Last    : out Natural;
      Success : out Boolean)
   with Pre => Is_Open (Chan);

   procedure Close (Chan : in out Channel)
   with
     Pre  => Is_Open (Chan),
     Post => not Is_Open (Chan);

   type Listener is limited private;

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural);

   function Is_Listening (L : Listener) return Boolean;

   procedure Accept_One
     (L      : in out Listener;
      Chan   : in out Channel;
      Config : Tls_Config)
   with
     Pre  => Is_Listening (L),
     Post => Is_Open (Chan);

   procedure Stop (L : in out Listener)
   with
     Pre  => Is_Listening (L),
     Post => not Is_Listening (L);

   Connect_Error : exception;
   Send_Error    : exception;

private

   type Channel is limited record
      Tcp     : Tls_Core.Tcp_Transport.Channel;
      Driver  : Tls_Core.Tls13_Driver.Driver;
      App_In  : Tls_Core.Aead_Channel.Direction;
      App_Out : Tls_Core.Aead_Channel.Direction;
      Open    : Boolean := False;
   end record;

   type Listener is limited record
      Tcp       : Tls_Core.Tcp_Transport.Listener;
      Listening : Boolean := False;
   end record;

end Tls_Transport;
