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
with SPARK_Mode
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

   --  No functional Posts on Encode/Decode: byte-layout invariants
   --  (Out_Last in 0 .. Out_Buf'Last) are imperative; functional
   --  byte-by-byte content is exercised via RFC 8448 vectors at
   --  the handshake-driver level.

   --  Encode a ClientHello into Out_Buf. Returns the number of
   --  bytes written via Out_Last. Out_Buf'First must be 1.
   procedure Encode_Client_Hello
     (CH        : Client_Hello;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 256,
     Post =>
       Out_Last in 0 .. Out_Buf'Last;

   --  Encode a ServerHello into Out_Buf.
   procedure Encode_Server_Hello
     (SH        : Server_Hello;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 256,
     Post =>
       Out_Last in 0 .. Out_Buf'Last;

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

   ------------------------------------------------------------------
   --  RFC 8446 §4.2.11 PSK profile — separate encode/decode shape.
   --
   --  External-PSK ClientHello extensions (in encoded order):
   --     supported_versions      = [TLS 1.3]
   --     psk_key_exchange_modes  = [psk_ke (= 0)]
   --     pre_shared_key          = identity || binder    (MUST be last)
   --
   --  ServerHello extensions for PSK selection:
   --     supported_versions      = TLS 1.3
   --     pre_shared_key          = u16 selected_identity
   --
   --  We model exactly one identity / one binder — sufficient for
   --  openssl s_client -psk and the v0.5 single-PSK story.
   ------------------------------------------------------------------

   subtype Psk_Identity_Len is Positive range 1 .. 64;
   subtype Binder is Octet_Array (1 .. 32);

   --  Encode a CH with the PSK extension stack. Out_Bytes will hold
   --  the wire CH (no Handshake-header prefix). Truncated_Last is
   --  the index of the last byte of the truncated ClientHello —
   --  i.e. the last byte of the binders' length field, just before
   --  the binder bytes themselves. Use Out_Bytes (Out_Buf'First ..
   --  Truncated_Last) as the input to Tls_Core.Psk_Binder.Compute,
   --  then patch the resulting 32-byte binder into
   --  Out_Bytes (Truncated_Last + 1 .. Truncated_Last + 32).
   procedure Encode_Client_Hello_Psk
     (Random          : Random_Bytes;
      Identity        : Octet_Array;
      Out_Buf         : out Octet_Array;
      Out_Last        : out Natural;
      Truncated_Last  : out Natural)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 256
       and then Identity'Length in Psk_Identity_Len,
     Post =>
       Out_Last in 0 .. Out_Buf'Last;

   --  Decode the PSK ext from a received CH. Sets OK := False if
   --  the shape doesn't match (no PSK ext, multiple identities,
   --  binder length /= 32, etc.). Identity_First..Identity_Last and
   --  Binder_First..Binder_Last are absolute indices into In_Bytes
   --  naming the identity and binder slices. Truncated_Last is the
   --  last byte of the truncated CH (caller hashes
   --  In_Bytes(In_Bytes'First..Truncated_Last) for the binder
   --  recompute).
   procedure Decode_Client_Hello_Psk
     (In_Bytes        : Octet_Array;
      Random          : out Random_Bytes;
      Identity_First  : out Natural;
      Identity_Last   : out Natural;
      Binder_First    : out Natural;
      Binder_Last     : out Natural;
      Truncated_Last  : out Natural;
      OK              : out Boolean);

   --  Encode a ServerHello echoing selected_identity = 0 and the
   --  TLS 1.3 supported_versions.
   procedure Encode_Server_Hello_Psk
     (Random   : Random_Bytes;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 128,
     Post =>
       Out_Last in 0 .. Out_Buf'Last;

end Tls_Core.Hello;
