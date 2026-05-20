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

   --  Decode a SubjectPublicKeyInfo structure starting at Buf'First.
   --
   --  On success (OK = True), Kind says which key type was found,
   --  and the slice (Key_First .. Key_Last) inside Buf names the
   --  contents of the inner BIT STRING (= the bytes the BIT STRING
   --  contains *after* the unused-bits header byte). Caller then
   --  hands that slice to either the RSA module (which decodes the
   --  inner SEQUENCE { modulus, exponent }) or the ECDSA module
   --  (which expects the 65-byte 0x04||X||Y SEC1 encoding).
   --
   --  Imperative Post: when OK is True the returned indices identify
   --  a non-empty slice strictly inside Buf and the returned Kind is
   --  one of the supported key types. When OK is False the caller
   --  must treat the index outputs as meaningless.
   procedure Decode
     (Buf       : Octet_Array;
      OK        : out Boolean;
      Kind      : out Key_Kind;
      Key_First : out Natural;
      Key_Last  : out Natural)
   with
     Pre  =>
       Buf'First = 1
       and then Buf'Length >= 2
       and then Buf'Last < Integer'Last - 16,
     Post =>
       (if OK
        then
          Kind in Rsa | Ecdsa_P256
          and then Key_First in Buf'Range
          and then Key_Last in Buf'Range
          and then Key_First <= Key_Last);

   --  For RSA SubjectPublicKey contents (the bytes inside the BIT
   --  STRING), parse the inner RSAPublicKey SEQUENCE and return the
   --  modulus and public exponent slices.
   --
   --     RSAPublicKey ::= SEQUENCE {
   --        modulus            INTEGER,
   --        publicExponent     INTEGER }
   --
   --  Imperative Post: when OK is True both INTEGER slices are
   --  non-empty and live inside Buf.
   procedure Decode_Rsa_Key
     (Buf       : Octet_Array;
      OK        : out Boolean;
      Mod_First : out Natural;
      Mod_Last  : out Natural;
      Exp_First : out Natural;
      Exp_Last  : out Natural)
   with
     Pre  =>
       Buf'First = 1
       and then Buf'Length >= 2
       and then Buf'Last < Integer'Last - 16,
     Post =>
       (if OK
        then
          Mod_First in Buf'Range
          and then Mod_Last in Buf'Range
          and then Mod_First <= Mod_Last
          and then Exp_First in Buf'Range
          and then Exp_Last in Buf'Range
          and then Exp_First <= Exp_Last);

end Tls_Core.X509_Spki;
