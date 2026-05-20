--  Tls_Core.Hello_Retry — TLS 1.3 HelloRetryRequest support
--  (RFC 8446 §4.1.4 + §4.4.1 transcript-hash quirk).
--
--  HRR is structurally a ServerHello with the Random field set to
--  the well-known magic value SHA-256("HelloRetryRequest"), the
--  identity of which is fixed by §4.1.3.
--
--  The transcript-hash quirk: when the handshake includes an HRR,
--  the value of ClientHello1 in the transcript is replaced by a
--  synthetic message_hash handshake message:
--
--      [type=0xFE u8] [length=H_LEN u24] [Hash(ClientHello1)]
--
--  The transcript-hash input then becomes:
--      synthetic_msg || HRR || CH2 || SH || ...
--
--  This module is the SPARK-clean primitive layer; the handshake
--  driver dispatches into Build_Synthetic_Msg when it detects an
--  HRR (compares the SH's Random against Magic_Random).
--
--  HRR wire encode/decode and cookie helpers live here too. The
--  cookie is treated as an opaque byte string (RFC 8446 §4.2.2 —
--  "the contents of the cookie are not specified") that the server
--  emits in HRR and the client echoes back in CH2. Real production
--  servers HMAC the CH1 hash + a server-side secret; we use a
--  caller-supplied bytestring (test code constructs / verifies the
--  contents). Validation is constant-time bytewise compare.

with Interfaces;
with Tls_Core.Sha256;
with Tls_Core.Suites;

package Tls_Core.Hello_Retry
  with SPARK_Mode
is

   use type Interfaces.Unsigned_8;

   --  RFC 8446 §4.1.3 — fixed magic random value that flags an
   --  HRR. This is SHA-256 of the ASCII bytes "HelloRetryRequest".
   --  We hard-code the digest rather than recompute it because the
   --  RFC mandates the constant.
   Magic_Random : constant Octet_Array (1 .. 32) :=
     [16#CF#,
      16#21#,
      16#AD#,
      16#74#,
      16#E5#,
      16#9A#,
      16#61#,
      16#11#,
      16#BE#,
      16#1D#,
      16#8C#,
      16#02#,
      16#1E#,
      16#65#,
      16#B8#,
      16#91#,
      16#C2#,
      16#A2#,
      16#11#,
      16#16#,
      16#7A#,
      16#BB#,
      16#8C#,
      16#5E#,
      16#07#,
      16#9E#,
      16#09#,
      16#E2#,
      16#C8#,
      16#A8#,
      16#33#,
      16#9C#];

   --  Synthetic handshake type code for the message_hash record
   --  RFC 8446 §4.4.1 emits in place of ClientHello1.
   Synthetic_Type : constant Octet := 16#FE#;

   --  HRR cookie maximum size we accept. The RFC permits 2^16 - 1
   --  bytes; we cap at 64 because no production server we interop
   --  with uses bigger (OpenSSL: 32, mbedTLS: 32, BoringSSL: 32).
   Max_Cookie_Length : constant Natural := 64;

   subtype Cookie_Bytes is Octet_Array (1 .. Max_Cookie_Length);

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  HRR-random constant-time identity test.
   --
   --  Standard:    RFC 8446 §4.1.3 / §4.1.4 (HelloRetryRequest is
   --               structurally a ServerHello with random equal to
   --               SHA-256("HelloRetryRequest")).
   --  Spec mirror: miTLS src/tls/MiTLS.Handshake.Common.fst :
   --               isHelloRetryRequest (random comparison).
   --
   --  Functional:  Imperative Post — None. Returns True iff the
   --               32-byte slice equals Magic_Random byte-for-byte.
   --               Comparison is constant-time (fixed-length loop,
   --               no data-dependent branch).
   --  Proven at:   gnatprove --level=2 (5/5 checks proved, audit-clean).
   --------------------------------------------------------------------
   function Is_Hrr_Random (Random : Octet_Array) return Boolean
   with Pre => Random'Length = 32 and then Random'Last < Integer'Last;

   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  §4.4.1 synthetic message_hash builder.
   --
   --  Standard:    RFC 8446 §4.4.1 — when the handshake includes an
   --               HRR, ClientHello1 in the transcript is replaced by
   --                 [type=0xFE u8] [length=H_LEN u24] [Hash(CH1)]
   --               so that re-hashing on each side yields the same
   --               transcript hash without re-buffering CH1 bytes.
   --  Spec mirror: miTLS src/tls/MiTLS.HandshakeLog.fst :
   --               hash_ch1_into_msg (replaces CH1 with msg-hash
   --               record).
   --
   --  Functional:  Imperative Post — header bytes 1..4 match the
   --               §4.4.1 layout (0xFE, 0x000020) and bytes 5..36
   --               carry Ch1_Hash byte-for-byte.
   --  Proven at:   gnatprove --level=2 (31/31 checks proved,
   --               audit-clean).
   --------------------------------------------------------------------
   procedure Build_Synthetic_Msg_Sha256
     (Ch1_Hash : Tls_Core.Sha256.Digest; Out_Buf : out Octet_Array)
   with
     Pre  => Out_Buf'First = 1 and then Out_Buf'Length = 36,
     Post =>
       Out_Buf (1) = Synthetic_Type
       and then Out_Buf (2) = 0
       and then Out_Buf (3) = 0
       and then Out_Buf (4) = 32
       and then (for all I in 1 .. 32 => Out_Buf (4 + I) = Ch1_Hash (I));

   ----------------------------------------------------------------------
   --  HelloRetryRequest wire encode / decode
   --  (RFC 8446 §4.1.4 — same wire shape as ServerHello, with the
   --  fixed Magic_Random and the extensions key_share (group only),
   --  supported_versions, cookie). cipher_suite is echoed from CH.
   ----------------------------------------------------------------------

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  HelloRetryRequest wire encoder.
   --
   --  Standard:    RFC 8446 §4.1.4 — HRR uses ServerHello wire shape
   --               with magic random + extensions
   --               { supported_versions, key_share (group only),
   --                 cookie (optional) }.
   --  Spec mirror: miTLS src/tls/MiTLS.Handshake.Server.fst :
   --               serializeHelloRetryRequest.
   --
   --  Functional:  Imperative Post — Out_Last in 0 .. Out_Buf'Last.
   --               Bit-equality of the random field with Magic_Random
   --               is exercised at the test level (Hello_Retry_Unit
   --               scenario) rather than as a Post clause to keep
   --               the contract small.
   --  Proven at:   gnatprove --level=2 (34/34 checks proved,
   --               audit-clean).
   --------------------------------------------------------------------
   procedure Encode_Hrr
     (Selected_Suite : Tls_Core.Suites.U16;
      Selected_Group : Tls_Core.Suites.U16;
      Cookie         : Octet_Array;
      Out_Buf        : out Octet_Array;
      Out_Last       : out Natural)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 256
       and then Out_Buf'Last <= Integer'Last - 4
       and then Cookie'Length <= Max_Cookie_Length,
     Post => Out_Last in 0 .. Out_Buf'Last;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  HelloRetryRequest wire decoder.
   --
   --  Standard:    RFC 8446 §4.1.4 — inverse of Encode_Hrr. Sets OK
   --               False on shape mismatch (random not magic, missing
   --               key_share, malformed cookie length, etc.).
   --  Spec mirror: miTLS src/tls/MiTLS.Handshake.Client.fst :
   --               parseHelloRetryRequest.
   --
   --  Functional:  Imperative Post — Cookie_Length always lies in
   --               0 .. Max_Cookie_Length (zero if no cookie ext, or
   --               on any error path).
   --  Proven at:   gnatprove --level=2 (65/65 checks proved,
   --               audit-clean).
   --------------------------------------------------------------------
   procedure Decode_Hrr
     (In_Bytes       : Octet_Array;
      Cipher_Suite   : out Tls_Core.Suites.U16;
      Selected_Group : out Tls_Core.Suites.U16;
      Cookie         : out Cookie_Bytes;
      Cookie_Length  : out Natural;
      OK             : out Boolean)
   with
     Pre  => In_Bytes'Last < Integer'Last - 4,
     Post => Cookie_Length in 0 .. Max_Cookie_Length;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Cookie constant-time compare.
   --
   --  Standard:    RFC 8446 §4.2.2 — server validates the cookie
   --               echoed in CH2 to confirm CH1's authenticity.
   --               Constant-time compare avoids leaking cookie bytes
   --               via timing.
   --  Spec mirror: miTLS src/tls/MiTLS.Handshake.Server.fst :
   --               check_cookie_match.
   --
   --  Functional:  Returns True iff Have'Length = Want_Length and
   --               every byte matches. Loop runs Want_Length
   --               iterations regardless of early mismatch.
   --  Proven at:   gnatprove --level=2 (10/10 checks proved,
   --               audit-clean).
   --------------------------------------------------------------------
   function Cookies_Equal
     (Have : Octet_Array; Want : Cookie_Bytes; Want_Length : Natural)
      return Boolean
   with
     Pre =>
       Want_Length in 0 .. Max_Cookie_Length
       and then Have'Length <= Max_Cookie_Length
       and then (if Have'Length > 0 then Have'Last < Integer'Last);

end Tls_Core.Hello_Retry;
