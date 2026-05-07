--  Tls_Core.P256_Order — arithmetic over Z_n where
--      n = ffffffff 00000000 ffffffff ffffffff
--          bce6faad a7179e84 f3b9cac2 fc632551
--  is the order of the NIST P-256 generator (FIPS 186-4 §D.1.2.3).
--
--  Wire / byte representation matches Tls_Core.P256_Field: a Scalar
--  is 32 bytes big-endian. ECDSA r, s, e (digest as integer) and
--  per-signature k all live in Z_n; all the multiplicative inverses
--  in §6.4.2 are mod n, NOT mod p.
--
--  Internal representation: eight 32-bit limbs little-endian. Add
--  and Sub use a single conditional add/subtract of n. Mul folds a
--  16-limb schoolbook product through a bit-serial shift/subtract
--  reduction (correct but slow — fine for the per-verify cost).
--  Invert is Fermat: a^(n-2) mod n via square-and-multiply.

package Tls_Core.P256_Order
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   subtype Scalar is Octet_Array (1 .. 32);

   Zero : constant Scalar := (others => 0);
   One  : constant Scalar :=
     (1 .. 31 => 0, 32 => 1);

   pragma Warnings (On, "array aggregate using () is an obsolescent syntax");

   --  No functional Posts: Z_n arithmetic is exercised end-to-end
   --  via ECDSA-P256 RFC 6979 vectors at the ecdsa_p256 layer.

   procedure Add (A, B : Scalar; Out_C : out Scalar);

   procedure Sub (A, B : Scalar; Out_C : out Scalar);

   procedure Mul (A, B : Scalar; Out_C : out Scalar);

   --  Modular inverse via Fermat: a^(n-2) mod n. If A = 0 the
   --  result is 0 (degenerate; ECDSA rejects s = 0 before this).
   procedure Invert (A : Scalar; Out_C : out Scalar);

   --  Reduce a 32-byte big-endian value mod n (single step).
   --  Inputs already < n pass through unchanged.
   procedure Reduce (A : Scalar; Out_C : out Scalar);

   --  True iff X = 0.
   function Is_Zero (X : Scalar) return Boolean;

   --  True iff 0 < X < n (the "1 ≤ r,s ≤ n-1" gate from
   --  FIPS 186-4 §6.4.2).
   function In_Range (X : Scalar) return Boolean;

end Tls_Core.P256_Order;
