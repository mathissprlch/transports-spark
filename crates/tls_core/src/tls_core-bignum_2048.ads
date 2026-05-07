--  Tls_Core.Bignum_2048 — fixed-size 2048-bit big-integer arithmetic
--  for RSA verification.
--
--  Scope: just enough to implement RSA-PSS / PKCS#1 verify against a
--  2048-bit modulus (the RSA size mandated by every modern profile —
--  TLS 1.3 RFC 8446 §4.2.3 / NIST SP 800-131A). The modulus, the
--  signature, and the public exponent are all exchanged as 256-byte
--  big-endian buffers; that is the X.509 / PKCS#1 (RFC 8017) wire
--  convention and matches `INTEGER` encoding inside RSA SubjectPublic
--  KeyInfo.
--
--  The on-the-wire representation is therefore `Bigint`, a 256-byte
--  big-endian octet array (MSB at index 1, LSB at index 256).
--  Internally the body works in 64 little-endian 32-bit limbs (limb 0
--  is LSB) — straightforward schoolbook arithmetic. Performance is
--  not a goal: an RSA verify involves at most a few thousand 2048x2048
--  multiplies and a like number of "subtract a shifted modulus" steps,
--  which is far below TLS's overall budget for cert verification.
--
--  No functional Posts: schoolbook 2048-bit arithmetic is checked
--  end-to-end via RSA-PSS RFC 8017 test vectors at the rsa_pss
--  layer.

package Tls_Core.Bignum_2048
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   Byte_Length : constant := 256;   --  2048 bits.

   subtype Bigint is Octet_Array (1 .. Byte_Length);
   --  Big-endian: Bigint (1) is the most significant byte,
   --  Bigint (256) is the least significant.

   Zero : constant Bigint := (others => 0);

   pragma Warnings (On, "array aggregate using () is an obsolescent syntax");

   --  A * B mod N. N must be non-zero. If N is zero the output is
   --  the zero Bigint.
   procedure Mod_Mul (A, B, N : Bigint; Out_R : out Bigint);

   --  Base^Exp mod N. N must be non-zero. Square-and-multiply,
   --  MSB-first scan over the bits of Exp. If N is zero the result is
   --  the zero Bigint.
   procedure Mod_Exp (Base, Exp, N : Bigint; Out_R : out Bigint);

   --  Constant-time equality: no early exit on mismatch. Useful for
   --  signature comparison if the caller wants to avoid leaking via
   --  byte-position timing.
   function Equal_CT (A, B : Bigint) return Boolean;

end Tls_Core.Bignum_2048;
