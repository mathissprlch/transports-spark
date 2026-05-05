--  Tls_Core.Ed25519 — Ed25519 signature verification (RFC 8032).
--
--  Source: RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA).
--
--  Ed25519 lives on the twisted Edwards curve
--      −x^2 + y^2 = 1 + d * x^2 * y^2     over GF(2^255 - 19)
--  with d = −121665/121666 (mod p).
--
--  Verification per §5.1.7:
--      Given (A, M, sig) with sig = R ‖ s (32 + 32 bytes):
--          k = SHA-512(R ‖ A ‖ M) reduced mod L
--          Accept iff [s]B = R + [k]A
--      where B is the curve's prime-order base point and
--      L = 2^252 + 27742317777372353535851937790883648493.
--
--  This module covers verification only; signing is not needed for
--  the TLS 1.3 server-cert path. Test vectors from RFC 8032 §7.1.
--
--  Same shape as Tls_Core.X25519 — a 16-limb 16-bit field
--  representation, but Edwards-form point operations + the curve
--  order arithmetic for reducing the SHA-512 hash mod L. Body sits
--  outside SPARK_Mode for the same reasons X25519 does: the field
--  arithmetic carry chains aren't a target for proof here; the
--  proof obligation is RFC-vector match.

with Tls_Core.Sha512;

package Tls_Core.Ed25519
with SPARK_Mode => Off
is

   subtype Bytes_32 is Octet_Array (1 .. 32);
   subtype Signature is Octet_Array (1 .. 64);

   --  Verify(public_key, message, signature). True iff valid.
   --
   --  RFC 8032 §5.1.7:
   --     R = sig[0..32), s = sig[32..64)
   --     A = decode(public_key)
   --     k = SHA-512(R ‖ public_key ‖ M) reduced mod L
   --     Accept iff [s]B = R + [k]A as encoded points.
   --  Abstract RFC 8032 §5.1.7 verify predicate.
   function Spec_Verify
     (Public_Key : Bytes_32;
      Message    : Octet_Array;
      Sig        : Signature)
      return Boolean
   with Ghost;

   function Verify
     (Public_Key : Bytes_32;
      Message    : Octet_Array;
      Sig        : Signature)
      return Boolean
   with Post =>
     Verify'Result = Spec_Verify (Public_Key, Message, Sig);

   --  RFC 8032 §5.1.6: derive the public key from a 32-byte seed.
   procedure Public_Of_Seed
     (Seed       : Bytes_32;
      Out_Public : out Bytes_32);

   --  RFC 8032 §5.1.6: produce a 64-byte signature over Message
   --  using the 32-byte seed (Ed25519 private key).
   procedure Sign
     (Seed    : Bytes_32;
      Message : Octet_Array;
      Out_Sig : out Signature);

   --  Diagnostic: encode the base point B. Should return the
   --  canonical encoding 0x5866666666...66 (32 bytes).
   procedure Debug_Encode_Base (Out_Bytes : out Bytes_32);

   --  Diagnostic: scalar-multiply the base point by `Scalar`
   --  and return the encoded result.
   procedure Debug_Scalar_Base
     (Scalar : Bytes_32;
      Out_Bytes : out Bytes_32);

   --  Diagnostic: decode then re-encode an encoded point.
   --  Should round-trip byte-exact for valid inputs.
   procedure Debug_Decode_Encode
     (In_Bytes  : Bytes_32;
      Out_Bytes : out Bytes_32;
      OK        : out Boolean);

end Tls_Core.Ed25519;
