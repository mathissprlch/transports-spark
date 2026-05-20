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
--      cipher_suite   = one of TLS_CHACHA20_POLY1305_SHA256 (0x1303),
--                       TLS_AES_128_GCM_SHA256 (0x1301),
--                       TLS_AES_256_GCM_SHA384 (0x1302)
--                       — runtime-negotiated per RFC 8446 §4.1.3
--      named_group    = x25519                          (0x001D)
--      signature_alg  = ed25519                         (0x0807)
--      legacy_version = 0x0303 (TLS 1.2 marker)
--      negotiated_ver = 0x0304 (TLS 1.3, in supported_versions ext)
--
--  Other suites / groups / algorithms are out of scope for v0.5.

with Tls_Core.Suites;

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
   --  RFC 8446 §4.2.11 PSK profile (mode 3 — psk_dhe_ke).
   --
   --  External-PSK ClientHello extensions (in encoded order):
   --     supported_versions      = [TLS 1.3]
   --     supported_groups        = [x25519]
   --     key_share               = [{x25519, 32-byte u-coord}]
   --     psk_key_exchange_modes  = [psk_dhe_ke (= 1)]
   --     [cookie]                = optional, between modes and PSK ext
   --     pre_shared_key          = identity || binder    (MUST be last)
   --
   --  ServerHello extensions for PSK selection:
   --     supported_versions      = TLS 1.3
   --     key_share               = {x25519, 32-byte server u-coord}
   --     pre_shared_key          = u16 selected_identity
   --
   --  Mode 1 (psk_ke — PSK without DHE) is NOT advertised on the wire
   --  per docs/conventions.md §0a (production peers reject mode 1 by default;
   --  RFC 8446 §A.2 discourages it). The driver will reject any peer
   --  that advertises only mode 0.
   --
   --  We model exactly one identity / one binder, one named group
   --  (x25519) and one key_share entry — sufficient for the v0.5
   --  PSK + ECDHE story.
   ------------------------------------------------------------------

   --  PSK identity bytes — 1..1024 to accommodate session-resumption
   --  tickets from production peers (openssl 5.9.x emits ~190-byte
   --  tickets; gnutls/bssl can push beyond 256 B).  RFC 8446 §4.2.11
   --  caps PskIdentity opaque<1..2^16-1>; 1024 is our v0.5 envelope.
   subtype Psk_Identity_Len is Positive range 1 .. 1024;
   subtype Binder is Octet_Array (1 .. 32);

   --  Encode a CH with the PSK + DHE extension stack. Out_Bytes will
   --  hold the wire CH (no Handshake-header prefix). Truncated_Last
   --  is the index of the last byte of the truncated ClientHello —
   --  i.e. the last byte of the binders' length field, just before
   --  the binder bytes themselves. Use Out_Bytes (Out_Buf'First ..
   --  Truncated_Last) as the input to Tls_Core.Psk_Binder.Compute,
   --  then patch the resulting 32-byte binder into
   --  Out_Bytes (Truncated_Last + 1 .. Truncated_Last + 32).
   --
   --  Key_Share carries the client's X25519 public key (32-byte
   --  u-coordinate; RFC 7748 §6.1). The named group is fixed to
   --  x25519 (0x001D) for v0.5.
   --  Server_Name (RFC 6066 §3 / RFC 8446 §4.2.10) is included as
   --  a server_name extension when its length is non-zero; an empty
   --  array (length 0) means "omit the extension" (e.g. when the
   --  caller didn't set an SNI hostname).
   --
   --  Alpn_Offers (RFC 7301) is a pre-flattened ProtocolName list
   --  in the "u8 name_length || N name bytes" repeating layout.
   --  Caller is responsible for the flattening (see
   --  Tls_Core.Extensions.Append_Alpn_Name). Empty = omit ALPN
   --  extension.
   procedure Encode_Client_Hello_Psk
     (Random          : Random_Bytes;
      Identity        : Octet_Array;
      Key_Share       : Public_Key;
      Server_Name     : Octet_Array;
      Alpn_Offers     : Octet_Array;
      Out_Buf         : out Octet_Array;
      Out_Last        : out Natural;
      Truncated_Last  : out Natural)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 320
       and then Identity'Length in Psk_Identity_Len
       and then Server_Name'Length <= 255
       and then Alpn_Offers'Length in 0 | 2 .. 255,
     Post =>
       Out_Last in 0 .. Out_Buf'Last;

   --  HRR-aware variant: emit a CH with an additional cookie
   --  extension placed before the (mandatory-last) pre_shared_key.
   --  Cookie may be empty (length = 0) — in that case the layout is
   --  identical to Encode_Client_Hello_Psk. Used by the client's
   --  CH2 emission after consuming HRR per RFC 8446 §4.1.4.
   --
   --  Server_Name and Alpn_Offers as in Encode_Client_Hello_Psk.
   procedure Encode_Client_Hello_Psk_With_Cookie
     (Random          : Random_Bytes;
      Identity        : Octet_Array;
      Key_Share       : Public_Key;
      Cookie          : Octet_Array;
      Server_Name     : Octet_Array;
      Alpn_Offers     : Octet_Array;
      Out_Buf         : out Octet_Array;
      Out_Last        : out Natural;
      Truncated_Last  : out Natural)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 320
       and then Identity'Length in Psk_Identity_Len
       and then Cookie'Length <= 64
       and then Server_Name'Length <= 255
       and then Alpn_Offers'Length in 0 | 2 .. 255,
     Post =>
       Out_Last in 0 .. Out_Buf'Last;

   --  Decode the PSK + DHE ext stack from a received CH. Sets OK :=
   --  False if the shape doesn't match (no PSK ext, multiple
   --  identities, binder length /= 32, no key_share for x25519, no
   --  psk_dhe_ke mode, etc.). Identity_First..Identity_Last and
   --  Binder_First..Binder_Last are absolute indices into In_Bytes
   --  naming the identity and binder slices. Key_Share_First..
   --  Key_Share_Last name the 32-byte X25519 public key. Truncated_Last
   --  is the last byte of the truncated CH (caller hashes
   --  In_Bytes(In_Bytes'First..Truncated_Last) for the binder
   --  recompute). Suites_First..Suites_Last bracket the
   --  cipher_suites list bytes (RFC 8446 §4.1.2 — flat-packed u16
   --  codepoints) so the caller can run its own selection policy.
   procedure Decode_Client_Hello_Psk
     (In_Bytes          : Octet_Array;
      Random            : out Random_Bytes;
      Session_Id_First  : out Natural;
      Session_Id_Last   : out Natural;
      Suites_First      : out Natural;
      Suites_Last       : out Natural;
      Identity_First    : out Natural;
      Identity_Last     : out Natural;
      Binder_First      : out Natural;
      Binder_Last       : out Natural;
      Key_Share_First   : out Natural;
      Key_Share_Last    : out Natural;
      Truncated_Last    : out Natural;
      OK                : out Boolean);
   --  Session_Id_First..Session_Id_Last bracket the legacy_session_id
   --  bytes (RFC 8446 §4.1.2) — empty range when the client sent an
   --  empty session_id.  The server MUST echo this verbatim in its
   --  ServerHello (§4.1.3); openssl/mbedtls clients abort otherwise.

   --  Encode a ServerHello echoing selected_identity = 0 and the
   --  TLS 1.3 supported_versions. Selected_Suite is the cipher
   --  suite the server picked from the client's offered list (RFC
   --  8446 §4.1.3). Key_Share carries the server's X25519 public
   --  key (32-byte u-coordinate).
   procedure Encode_Server_Hello_Psk
     (Random         : Random_Bytes;
      Session_Id_Echo : Octet_Array;        --  RFC 8446 §4.1.3
      Selected_Suite : Tls_Core.Suites.U16;
      Key_Share      : Public_Key;
      Out_Buf        : out Octet_Array;
      Out_Last       : out Natural)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 192
       and then Session_Id_Echo'Length <= 32,
     Post =>
       Out_Last in 0 .. Out_Buf'Last;
   --  Session_Id_Echo MUST equal the legacy_session_id field from
   --  the received ClientHello (RFC 8446 §4.1.3).  Length 0 is
   --  legitimate (client sent empty); >32 is forbidden by the spec.

   --  Decode the server's X25519 public key from a received SH.
   --  In_Bytes is the SH body (after the 4-byte handshake header).
   --  OK = False if no key_share extension is present, or the group
   --  is not x25519, or the key_exchange length is not 32. Sets
   --  Key_Share_First..Key_Share_Last to absolute indices in
   --  In_Bytes naming the 32-byte X25519 public key bytes.
   procedure Decode_Server_Hello_Psk_Key_Share
     (In_Bytes        : Octet_Array;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      OK              : out Boolean);

   ------------------------------------------------------------------
   --  RFC 8446 §4.1.2 cert-mode ClientHello.
   --
   --  Extension stack emitted (in order):
   --     supported_versions      = [TLS 1.3]
   --     supported_groups        = [x25519]
   --     [server_name]           = optional, when Server_Name nonempty
   --     [ALPN]                  = optional, when Alpn_Offers nonempty
   --     key_share               = [{x25519, 32-byte u-coord}]
   --     signature_algorithms    = [ecdsa_secp256r1_sha256,
   --                                rsa_pss_rsae_sha256] (RFC 8446 §4.2.3)
   --
   --  No pre_shared_key, no psk_key_exchange_modes — distinguishes
   --  cert mode from PSK mode on the wire. Three v0.5 cipher suites
   --  are offered in §B.4 preference order, same as the PSK CH
   --  encoder; runtime selection happens server-side.
   ------------------------------------------------------------------
   procedure Encode_Client_Hello_Cert
     (Random          : Random_Bytes;
      Key_Share       : Public_Key;
      Server_Name     : Octet_Array;
      Alpn_Offers     : Octet_Array;
      Out_Buf         : out Octet_Array;
      Out_Last        : out Natural)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 320
       and then Server_Name'Length <= 255
       and then Alpn_Offers'Length in 0 | 2 .. 255,
     Post =>
       Out_Last in 0 .. Out_Buf'Last;

   --  Decode a received cert-mode ClientHello (after the 4-byte
   --  Handshake header has been stripped).  Sets OK = False if:
   --    * basic shape is malformed
   --    * no key_share for x25519
   --    * no signature_algorithms extension
   --
   --  Suites_First..Suites_Last bracket the cipher_suites list so
   --  the server can run its own selection policy. Sig_Algs_First..
   --  Sig_Algs_Last bracket the signature_algorithms list (u16 list
   --  body — the leading 2-byte length field is excluded). Key_Share_
   --  First..Key_Share_Last point at the 32-byte X25519 client public
   --  key.
   procedure Decode_Client_Hello_Cert
     (In_Bytes          : Octet_Array;
      Random            : out Random_Bytes;
      Session_Id_First  : out Natural;
      Session_Id_Last   : out Natural;
      Suites_First      : out Natural;
      Suites_Last       : out Natural;
      Sig_Algs_First    : out Natural;
      Sig_Algs_Last     : out Natural;
      Key_Share_First   : out Natural;
      Key_Share_Last    : out Natural;
      OK                : out Boolean);
   --  Session_Id_First..Session_Id_Last bracket the legacy_session_id
   --  bytes; see comment on Decode_Client_Hello_Psk.

   ------------------------------------------------------------------
   --  RFC 8446 §4.1.3 cert-mode ServerHello.
   --
   --  Identical to the PSK ServerHello except the pre_shared_key
   --  extension is absent. Extension list emitted (in order):
   --     supported_versions      = TLS 1.3
   --     key_share               = {x25519, 32-byte server u-coord}
   --
   --  Cert-mode SH carries no signal that a particular cert was
   --  selected — the certificate itself is communicated in the
   --  encrypted Certificate handshake message that follows
   --  EncryptedExtensions in the server flight (RFC 8446 §4.4.2).
   ------------------------------------------------------------------
   procedure Encode_Server_Hello_Cert
     (Random          : Random_Bytes;
      Session_Id_Echo : Octet_Array;        --  RFC 8446 §4.1.3
      Selected_Suite  : Tls_Core.Suites.U16;
      Key_Share       : Public_Key;
      Out_Buf         : out Octet_Array;
      Out_Last        : out Natural)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 192
       and then Session_Id_Echo'Length <= 32,
     Post =>
       Out_Last in 0 .. Out_Buf'Last;

end Tls_Core.Hello;
