--  Tls_Core.Cert_Verify — TLS 1.3 §4.4.2 + §4.4.3 wire support for
--  the Certificate and CertificateVerify handshake messages.
--
--  This module is the SPARK-clean *wire-format* layer; it produces
--  and consumes byte buffers. It does NOT perform certificate
--  chain validation or signature verification — those are the
--  caller's job (using Tls_Core.X509_Spki + Rsa_Pss / Ecdsa_P256).
--
--  Source: RFC 8446 §4.4.2 (Certificate), §4.4.3 (CertificateVerify).

with Interfaces;

package Tls_Core.Cert_Verify
with SPARK_Mode
is

   use type Interfaces.Unsigned_16;

   --  No functional Posts on the encoder/decoder operations: the
   --  byte-layout invariants (Out_Last = encoded length) are
   --  asserted imperatively below. Functional content is exercised
   --  via end-to-end TLS 1.3 handshakes in tls_core_tests.

   ---------------------------------------------------------------------
   --  Certificate (§4.4.2)
   --
   --      struct {
   --          opaque cert_data<1..2^24-1>;
   --          Extension extensions<0..2^16-1>;
   --      } CertificateEntry;
   --
   --      struct {
   --          opaque certificate_request_context<0..2^8-1>;
   --          CertificateEntry certificate_list<0..2^24-1>;
   --      } Certificate;
   --
   --  v0.5 issues only end-entity certs (no intermediate chain) and
   --  no CertificateRequest.context, so the encoder takes a single
   --  cert_data slice and emits the complete handshake-message body
   --  with empty request_context and empty extensions.
   ---------------------------------------------------------------------

   --  Encode the body of a Certificate handshake message containing
   --  a single end-entity certificate. Layout produced:
   --      00                                     (request_context len)
   --      cert_list_len_u24                       (3 bytes)
   --        cert_data_len_u24                     (3 bytes)
   --        cert_data                              (N bytes)
   --        00 00                                  (extensions len = 0)
   --
   --  Out_Last is set to the number of bytes written.
   procedure Encode_Body_Single
     (Cert_Data : Octet_Array;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   with
     Pre =>
       Cert_Data'Length in 1 .. 16#FFFFFF# - 5
       and then Cert_Data'Last < Integer'Last - 16#FFFFFF#
       and then Out_Buf'First = 1
       and then Out_Buf'Last < Integer'Last - 32
       and then Out_Buf'Length >= 1 + 3 + 3 + Cert_Data'Length + 2,
     Post =>
       Out_Last = 1 + 3 + 3 + Cert_Data'Length + 2;

   --  Decode the body of a Certificate handshake message containing
   --  exactly one end-entity certificate. Returns OK = False on any
   --  malformed structure, on more than one cert, or on a non-empty
   --  request_context (we don't post-handshake auth in v0.5).
   procedure Decode_Body_Single
     (Buf        : Octet_Array;
      OK         : out Boolean;
      Cert_First : out Natural;
      Cert_Last  : out Natural)
   with Pre => Buf'First = 1 and then Buf'Length <= 16#FFFFFF#;

   ---------------------------------------------------------------------
   --  CertificateVerify (§4.4.3)
   --
   --      struct {
   --          SignatureScheme algorithm;       --  u16
   --          opaque signature<0..2^16-1>;
   --      } CertificateVerify;
   --
   --  The signed content (per §4.4.3) is:
   --      64 * 0x20                             (64 spaces)
   --      "TLS 1.3, server CertificateVerify"   (33 bytes) or
   --      "TLS 1.3, client CertificateVerify"   (33 bytes)
   --      0x00                                  (1 byte separator)
   --      Transcript-Hash(Handshake-Context)    (HashLen bytes)
   ---------------------------------------------------------------------

   procedure Encode_Body
     (Sig_Scheme : Interfaces.Unsigned_16;
      Signature  : Octet_Array;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural)
   with
     Pre =>
       Signature'Length in 1 .. 65535
       and then Signature'Last < Integer'Last - 65535
       and then Out_Buf'First = 1
       and then Out_Buf'Last < Integer'Last - 32
       and then Out_Buf'Length >= 4 + Signature'Length,
     Post =>
       Out_Last = 4 + Signature'Length;

   procedure Decode_Body
     (Buf        : Octet_Array;
      OK         : out Boolean;
      Sig_Scheme : out Interfaces.Unsigned_16;
      Sig_First  : out Natural;
      Sig_Last   : out Natural)
   with Pre => Buf'First = 1 and then Buf'Length <= 65535;

   --  Build the "context-and-content" octets the CertVerify
   --  signature is computed over, per §4.4.3. Out_Buf must be sized
   --  to hold 64 + 33 + 1 + Transcript_Hash'Length bytes.
   --
   --  Side specifies the issuer perspective: when the server emits
   --  CertVerify, Side = Server; when the client does it (only for
   --  client auth, not in v0.5), Side = Client. The two literals
   --  differ in the word "server" vs "client" inside the prefix.
   type Cert_Verify_Side is (Server, Client);

   procedure Build_Signed_Content
     (Side            : Cert_Verify_Side;
      Transcript_Hash : Octet_Array;
      Out_Buf         : out Octet_Array;
      Out_Last        : out Natural)
   with
     Pre =>
       Transcript_Hash'Length in 1 .. 64
       and then Transcript_Hash'Last < Integer'Last - 64
       and then Out_Buf'First = 1
       and then Out_Buf'Last < Integer'Last - 256
       and then Out_Buf'Length >= 64 + 33 + 1 + Transcript_Hash'Length,
     Post =>
       Out_Last = 64 + 33 + 1 + Transcript_Hash'Length;

   ---------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  DER-encode an ECDSA Sig-Value SEQUENCE.
   --
   --  Standard:    RFC 5480 §2.2 / SEC 1 §C.5 (Ecdsa-Sig-Value).
   --  Wire layout:
   --      SEQUENCE {
   --          r  INTEGER,                  -- 32-byte big-endian, with
   --          s  INTEGER                   -- a leading 0x00 prepended
   --      }                                -- when the high bit is set,
   --                                       -- and any leading zero bytes
   --                                       -- of the input stripped.
   --
   --  Inputs R and S are the ECDSA-P256 32-byte big-endian scalar
   --  components produced by Tls_Core.Ecdsa_P256.Sign. Worst-case
   --  output is 72 bytes:
   --      0x30 len  0x02 0x21 (0x00 || 32B) 0x02 0x21 (0x00 || 32B)
   --
   --  Out_Last is the number of bytes written. Out_Buf must be at
   --  least 72 bytes long.
   ---------------------------------------------------------------------
   procedure Encode_Ecdsa_Sig_Der
     (R, S     : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   with
     Pre =>
       R'Length = 32
       and then S'Length = 32
       and then Out_Buf'First = 1
       and then Out_Buf'Length >= 72,
     Post =>
       Out_Last in 8 .. 72;

end Tls_Core.Cert_Verify;
