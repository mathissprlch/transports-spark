--  Tls_Core.Tls13_Driver — spec-compliant TLS 1.3 handshake driver.
--
--  Distinct from Tls_Core.Handshake_Driver: this version emits
--  proper TLSPlaintext / TLSCiphertext records on the wire,
--  encrypts the handshake messages after ServerHello under the
--  handshake_traffic_secret, sends the mandatory
--  EncryptedExtensions message (RFC 8446 §4.3.1), and follows the
--  RFC 8446 §5.2 TLSInnerPlaintext content-type-byte convention.
--
--  Required for any external-reference-impl interop (openssl,
--  grpcurl, browsers) — those peers reject the simplified-record
--  shape Handshake_Driver emits.
--
--  This first slice supports the PSK_KE profile (RFC 8446 §7.1
--  mode 1) on the **server** side only. ECDHE / ECDHE+cert /
--  client-side join in subsequent phases.

with Tls_Core.Channel;
with Tls_Core.Handshake;
with Tls_Core.Transcript;

package Tls_Core.Tls13_Driver
with SPARK_Mode => Off
is

   type Role is (Client, Server);

   type State is
     (Awaiting_CH,        --  Server's initial state.
      Awaiting_Cf,        --  Server has sent SH+EE+SF; awaiting client Finished.
      Done,
      Failed);

   type Driver is private;

   --  Initialise as PSK_KE server. The PSK is the same byte string
   --  the peer (e.g. openssl s_client -psk) uses; Identity is the
   --  external PSK identity it advertises.
   procedure Init_Psk_Server
     (D            : out Driver;
      PSK          : Octet_Array;
      Psk_Identity : Octet_Array);

   --  Drive one flight. Caller hands in the bytes received over
   --  TCP since the last Step (one or more TLSPlaintext /
   --  TLSCiphertext records concatenated). Driver writes the
   --  outbound flight to Out_Buf — also a concatenation of records.
   procedure Step
     (D         : in out Driver;
      In_Bytes  : Octet_Array;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   with Pre =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 1024;

   function Current_State (D : Driver) return State;

   --  Open application-data Channel directions (after Done).
   --  Server: encrypts outbound with server_application_traffic_secret;
   --          decrypts inbound with client_application_traffic_secret.
   procedure Open_App_Directions
     (D       : Driver;
      Out_Dir : out Tls_Core.Channel.Direction;
      In_Dir  : out Tls_Core.Channel.Direction)
   with Pre => Current_State (D) = Done;

private

   subtype Psk_Bytes  is Octet_Array (1 .. 32);
   subtype Identity_Bytes is Octet_Array (1 .. 64);

   type Driver is record
      My_Role     : Role := Server;
      Cur_State   : State := Awaiting_CH;
      Hash_Ctx    : Tls_Core.Transcript.Accumulator;

      PSK         : Psk_Bytes := (others => 0);
      Identity    : Identity_Bytes := (others => 0);
      Identity_Len : Natural := 0;

      --  Channel directions for handshake encryption (post-SH).
      Hs_Out_Dir  : Tls_Core.Channel.Direction;
      Hs_In_Dir   : Tls_Core.Channel.Direction;

      --  Application-data secrets (filled at Done).
      App_Out_Sec : Tls_Core.Handshake.Traffic_Secrets;
      App_Set     : Boolean := False;
   end record;

   function Current_State (D : Driver) return State is (D.Cur_State);

end Tls_Core.Tls13_Driver;
