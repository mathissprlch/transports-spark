--  Tls_Core.Hello — encode / decode TLS 1.3 ClientHello and
--  ServerHello with the minimal extension set our handshake
--  driver negotiates.
--
--  Source: RFC 8446 §4.1.2 (ClientHello), §4.1.3 (ServerHello),
--          §4.2 (Extensions).
--
--  Wire format:
--      struct {
--          ProtocolVersion legacy_version = 0x0303;     -- u16
--          Random random;                                -- 32 bytes
--          opaque legacy_session_id<0..32>;              -- u8 len + N
--          CipherSuite cipher_suites<2..2^16-2>;         -- u16 len + N*2
--          opaque compression_methods<1..2^8-1>;         -- u8 len + N
--          Extension extensions<8..2^16-1>;              -- u16 len + N
--      } ClientHello;
--
--      struct {
--          ExtensionType extension_type;                 -- u16
--          opaque extension_data<0..2^16-1>;             -- u16 len + N
--      } Extension;
--
--  This module is the wire-format orchestration layer; gnatprove
--  proofs ride on the underlying primitive contracts.
--
--  We support exactly the negotiation surface the handshake
--  driver needs:
--      cipher_suite   = TLS_CHACHA20_POLY1305_SHA256   (0x1303)
--      named_group    = x25519                          (0x001D)
--      signature_alg  = ed25519                         (0x0807)
--      legacy_version = 0x0303 (TLS 1.2 marker)
--      negotiated_ver = 0x0304 (TLS 1.3, in supported_versions ext)
--
--  Other suites / groups / algorithms are out of scope for v0.5.

package Tls_Core.Hello
with SPARK_Mode => Off
is

   subtype Random_Bytes is Octet_Array (1 .. 32);
   subtype Session_Id is Octet_Array (1 .. 32);
   subtype Public_Key is Octet_Array (1 .. 32);

   --  ClientHello payload — the bytes after the Handshake header.
   type Client_Hello is record
      Random           : Random_Bytes;
      Session_Id_Len   : Natural;     --  0..32; 0 means absent
      Session_Id_Bytes : Session_Id;  --  meaningful only first Session_Id_Len bytes
      Key_Share        : Public_Key;  --  X25519 public key (always present in v0.5)
   end record;

   --  ServerHello payload — bytes after the Handshake header.
   type Server_Hello is record
      Random           : Random_Bytes;
      Session_Id_Len   : Natural;
      Session_Id_Bytes : Session_Id;
      Key_Share        : Public_Key;  --  Server's X25519 public key
   end record;

   --  Encode a ClientHello into Out_Buf. Returns the number of
   --  bytes written via Out_Last. Out_Buf'First must be 1.
   procedure Encode_Client_Hello
     (CH        : Client_Hello;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   with Pre =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 256;

   --  Encode a ServerHello into Out_Buf.
   procedure Encode_Server_Hello
     (SH        : Server_Hello;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   with Pre =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 256;

   --  Decode a ClientHello payload (the body after the 4-byte
   --  Handshake header has been stripped). Sets OK = False if the
   --  shape doesn't match what we negotiate.
   procedure Decode_Client_Hello
     (In_Bytes : Octet_Array;
      CH       : out Client_Hello;
      OK       : out Boolean);

   procedure Decode_Server_Hello
     (In_Bytes : Octet_Array;
      SH       : out Server_Hello;
      OK       : out Boolean);

end Tls_Core.Hello;
