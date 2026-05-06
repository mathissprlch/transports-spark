--  Tls_Core.X509_Spki — SPARK-clean DER parser for X.509
--  SubjectPublicKeyInfo (RFC 5280 §4.1.2.7) for the two
--  TLS-1.3-MUST-implement key types:
--
--    rsaEncryption         (OID 1.2.840.113549.1.1.1)
--    id-ecPublicKey        (OID 1.2.840.10045.2.1)
--      with parameters prime256v1 (1.2.840.10045.3.1.7)
--
--  The existing tls_core-x509 parser is Ed25519-only and lives in a
--  SPARK_Mode=>Off module that uses RFLX. This module is the
--  forward-going clean replacement: pure byte arithmetic on a
--  caller-supplied DER slice, no heap, no RFLX, no I/O.

package Tls_Core.X509_Spki
with SPARK_Mode
is

   type Key_Kind is (Unknown, Rsa, Ecdsa_P256);

   --  Spec functions — parser correctness as opaque ghosts. Callers
   --  that need to reason about the parse outcome funnel through
   --  Spec_Decode_OK / Spec_Decode_Kind. Pinned via pragma Assume
   --  in the body.
   function Spec_Decode_OK (Buf : Octet_Array) return Boolean
   with Ghost,
        Pre => Buf'First = 1 and then Buf'Length >= 2;

   function Spec_Decode_Kind (Buf : Octet_Array) return Key_Kind
   with Ghost,
        Pre => Buf'First = 1 and then Buf'Length >= 2;

   function Spec_Decode_Rsa_OK (Buf : Octet_Array) return Boolean
   with Ghost,
        Pre => Buf'First = 1 and then Buf'Length >= 2;

   --  Decode a SubjectPublicKeyInfo structure starting at Buf'First.
   --
   --  On success (OK = True), Kind says which key type was found,
   --  and the slice (Key_First .. Key_Last) inside Buf names the
   --  contents of the inner BIT STRING (= the bytes the BIT STRING
   --  contains *after* the unused-bits header byte). Caller then
   --  hands that slice to either the RSA module (which decodes the
   --  inner SEQUENCE { modulus, exponent }) or the ECDSA module
   --  (which expects the 65-byte 0x04||X||Y SEC1 encoding).
   procedure Decode
     (Buf       : Octet_Array;
      OK        : out Boolean;
      Kind      : out Key_Kind;
      Key_First : out Natural;
      Key_Last  : out Natural)
   with
     Pre  => Buf'First = 1
             and then Buf'Length >= 2
             and then Buf'Last < Integer'Last - 16,
     Post =>
       OK = Spec_Decode_OK (Buf)
       and then (if OK then Kind = Spec_Decode_Kind (Buf));

   --  For RSA SubjectPublicKey contents (the bytes inside the BIT
   --  STRING), parse the inner RSAPublicKey SEQUENCE and return the
   --  modulus and public exponent slices.
   --
   --     RSAPublicKey ::= SEQUENCE {
   --        modulus            INTEGER,
   --        publicExponent     INTEGER }
   procedure Decode_Rsa_Key
     (Buf       : Octet_Array;
      OK        : out Boolean;
      Mod_First : out Natural;
      Mod_Last  : out Natural;
      Exp_First : out Natural;
      Exp_Last  : out Natural)
   with
     Pre  => Buf'First = 1
             and then Buf'Length >= 2
             and then Buf'Last < Integer'Last - 16,
     Post => OK = Spec_Decode_Rsa_OK (Buf);

end Tls_Core.X509_Spki;
