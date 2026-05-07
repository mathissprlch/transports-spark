--  Tls_Core.P256_Field — arithmetic over GF(p) where
--      p = 2^256 - 2^224 + 2^192 + 2^96 - 1
--  the NIST P-256 prime (FIPS 186-4 §D.1.2.3 / SEC 1 §2.4.2).
--
--  The wire representation is 32 bytes big-endian (RFC 8446 §4.2.8.2,
--  SEC 1 §2.3). Internally we work with eight 32-bit limbs in
--  little-endian order — limb 0 is the least significant 32 bits —
--  and a 64-bit accumulator for products.
--
--  Reduction follows FIPS 186-4 §D.1.4 / NIST SP 800-186: the
--  schoolbook product of two 8-limb operands yields a 16-limb
--  intermediate T15..T0; the nine sums S1..S9 are formed and
--  combined as
--      result = S1 + 2*S2 + 2*S3 + S4 + S5 - S6 - S7 - S8 - S9
--  followed by a small fixed-iteration conditional subtract of p
--  to land in [0, p).
--
--  Inversion uses Fermat: a^(p-2) mod p, computed by square-and-
--  multiply over the 256-bit exponent.

package Tls_Core.P256_Field
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   subtype Field is Octet_Array (1 .. 32);

   Zero : constant Field := (others => 0);
   One  : constant Field :=
     (1 .. 31 => 0, 32 => 1);  --  big-endian: LSB at byte 32

   pragma Warnings (On, "array aggregate using () is an obsolescent syntax");

   --  No functional Posts: GF(p) arithmetic is exercised end-to-end
   --  via the ECDSA-P256 test vectors at the ecdsa_p256 layer.

   procedure Add (A, B : Field; Out_C : out Field);

   procedure Sub (A, B : Field; Out_C : out Field);

   procedure Mul (A, B : Field; Out_C : out Field);

   procedure Square (A : Field; Out_C : out Field);

   --  Modular inverse via Fermat: a^(p-2) mod p. Defined for any
   --  Field; if A = 0 the result is 0 (degenerate).
   procedure Invert (A : Field; Out_C : out Field);

   --  Constant-time equality compare. No early exit on mismatch.
   function Equal_CT (A, B : Field) return Boolean;

end Tls_Core.P256_Field;
