--  Tls_Core.Cert_Chain — body. Hand-written cert-chain walker.
--
--  Decomposes into:
--    Verify_Signed_TBS    — verify one cert's signature with parent's pub key
--    Parse_Ecdsa_Sig_Der  — pull (r, s) out of an ECDSA-Sig-Value SEQUENCE
--    Public_Key_From_Spki — wraps Tls_Core.X509_Spki.Decode +
--                           Decode_Rsa_Key as one shot
--
--  Termination: chain length is bounded by Max_Chain_Depth, trust
--  store by Max_Trust_Roots. Walker uses a counted FOR loop.

with Tls_Core.Bignum_2048;
with Tls_Core.Cert_Verify;
with Tls_Core.Ecdsa_P256;
with Tls_Core.Rsa_Pss;
with Tls_Core.X509_Spki;

package body Tls_Core.Cert_Chain
  with SPARK_Mode
is

   use type Tls_Core.Octet;
   use type Tls_Core.X509_Spki.Key_Kind;
   use type Tls_Core.Cert.Signature_Alg;

   ---------------------------------------------------------------------
   --  Decode a DER ECDSA signature SEQUENCE { r INTEGER, s INTEGER }
   --  into two 32-byte big-endian P-256 scalars (left-pad with zeros
   --  if the INTEGER body is shorter, strip a leading 0x00 sign byte
   --  if the body is 33 bytes).
   --
   --  Sets OK := False if the SEQUENCE / INTEGERs are malformed or
   --  one of the components doesn't fit in 32 bytes.
   ---------------------------------------------------------------------
   procedure Parse_Ecdsa_Sig_Der
     (Sig : Octet_Array;
      R   : out Tls_Core.Ecdsa_P256.Component;
      S   : out Tls_Core.Ecdsa_P256.Component;
      OK  : out Boolean)
   with
     Pre  =>
       Sig'First = 1
       and then Sig'Length in 8 .. 80
       and then Sig'Last < Integer'Last - 16,
     Post => True;

   procedure Parse_Ecdsa_Sig_Der
     (Sig : Octet_Array;
      R   : out Tls_Core.Ecdsa_P256.Component;
      S   : out Tls_Core.Ecdsa_P256.Component;
      OK  : out Boolean)
   is separate;

   ---------------------------------------------------------------------
   --  Verify_Signed_TBS — given a child cert's TBS bytes + its outer
   --  signature value + the signature algorithm enum, plus the parent
   --  cert's SPKI region, decide whether the child's signature is a
   --  valid signature by the parent's public key over the TBS.
   ---------------------------------------------------------------------
   procedure Verify_Signed_TBS
     (TBS_Bytes : Octet_Array;
      Sig_Bytes : Octet_Array;
      Sig_Alg   : Tls_Core.Cert.Signature_Alg;
      Spki_Buf  : Octet_Array;
      OK        : out Boolean)
   with
     Pre  =>
       TBS_Bytes'First = 1
       and then TBS_Bytes'Length in 1 .. 16384
       and then TBS_Bytes'Last < Integer'Last - 256
       and then Sig_Bytes'First = 1
       and then Sig_Bytes'Length in 1 .. 512
       and then Sig_Bytes'Last < Integer'Last - 256
       and then Spki_Buf'First = 1
       and then Spki_Buf'Length >= 16
       and then Spki_Buf'Last < Integer'Last - 16,
     Post => True;

   procedure Verify_Signed_TBS
     (TBS_Bytes : Octet_Array;
      Sig_Bytes : Octet_Array;
      Sig_Alg   : Tls_Core.Cert.Signature_Alg;
      Spki_Buf  : Octet_Array;
      OK        : out Boolean)
   is separate;

   ---------------------------------------------------------------------
   --  Validate_Chain
   ---------------------------------------------------------------------
   procedure Validate_Chain
     (All_Certs   : Octet_Array;
      Chain_In    : Chain;
      Trust       : Trust_Store;
      Result      : out Validation_Result;
      Leaf_Parsed : out Tls_Core.Cert.Parsed_Cert)
   is separate;

   ---------------------------------------------------------------------
   --  Verify_Cert_Verify — TLS 1.3 §4.4.3 CertificateVerify check.
   ---------------------------------------------------------------------
   procedure Verify_Cert_Verify
     (Leaf_Der       : Octet_Array;
      Leaf_Parsed    : Tls_Core.Cert.Parsed_Cert;
      Sig_Scheme     : Interfaces.Unsigned_16;
      Signed_Content : Octet_Array;
      Signature      : Octet_Array;
      OK             : out Boolean)
   is separate;

   ---------------------------------------------------------------------
   --  Authenticate_Server — pipeline glue.
   ---------------------------------------------------------------------
   procedure Authenticate_Server
     (All_Certs       : Octet_Array;
      Chain_In        : Chain;
      Trust           : Trust_Store;
      Hostname        : Octet_Array;
      Sig_Scheme      : Interfaces.Unsigned_16;
      Sig_Body        : Octet_Array;
      Transcript_Hash : Octet_Array;
      Result          : out Validation_Result)
   is separate;

end Tls_Core.Cert_Chain;
