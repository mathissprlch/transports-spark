pragma Ada_2022;
with Ada.Numerics.Big_Numbers.Big_Integers;

--  §0e Montgomery number-theory layer (ghost). Provides the modular inverse
--  of 2**A modulo an odd N and the Montgomery cancellation identity, mirroring
--  the role of HACL\* Hacl.Spec.Montgomery.Lemmas.fst. HACL\* constructs the
--  inverse with a bit-lifting extended Euclid (eea_pow2_odd) because it also
--  needs the algorithmic constant mu; we only need the inverse to *exist* for
--  the (ghost) correctness proof, so we use the simpler 2**-1 = (N+1)/2 lifted
--  by power-of-product: (2**-1)**A is an inverse of 2**A. Everything is pure
--  Big_Integer arithmetic over literals -- never the §0e-opaque To_Big_Integer
--  -- so it composes with the Limb_Val value layer and ghost-eliminates from
--  the runtime / bare build.

package Tls_Core.Ghost_Bignum.Montgomery
  with SPARK_Mode, Ghost
is

   package BI renames Ada.Numerics.Big_Numbers.Big_Integers;
   use type BI.Big_Integer;

   --  2 ** A as a Big_Integer (bit-level radix for the inverse construction).
   function Pow2 (A : Natural) return BI.Big_Integer
   is (if A = 0 then 1 else Pow2 (A - 1) * 2)
   with Subprogram_Variant => (Decreases => A);

   --  General power B ** E over Big_Integer (square-and-multiply spec base).
   function Pow (B : BI.Big_Integer; E : Natural) return BI.Big_Integer
   is (if E = 0 then 1 else Pow (B, E - 1) * B)
   with Subprogram_Variant => (Decreases => E);

   procedure Lemma_Pow2_Pos (A : Natural)
   with Post => Pow2 (A) > 0, Subprogram_Variant => (Decreases => A);

   procedure Lemma_Pow2_Succ (A : Positive)
   with Post => Pow2 (A) = 2 * Pow2 (A - 1);

   --  2**A = Pow (2, A): the two radix definitions agree.
   procedure Lemma_Pow2_Is_Pow (A : Natural)
   with Post => Pow2 (A) = Pow (2, A), Subprogram_Variant => (Decreases => A);

   --  Exponents add: 2**(A+B) = 2**A * 2**B.
   procedure Lemma_Pow2_Add (A1, B1 : Natural)
   with
     Pre                => A1 <= Natural'Last - B1,
     Post               => Pow2 (A1 + B1) = Pow2 (A1) * Pow2 (B1),
     Subprogram_Variant => (Decreases => B1);

   --  Power of a power: (2**M)**K = 2**(M*K). Bridges a base-2**M radix
   --  (e.g. P32 with M=32) to the bit-level Pow2.
   procedure Lemma_Pow2_Pow_Mul (M, K : Natural)
   with
     Pre                => K = 0 or else M <= Natural'Last / K,
     Post               => Pow (Pow2 (M), K) = Pow2 (M * K),
     Subprogram_Variant => (Decreases => K);

   --  Pow (1, E) = 1.
   procedure Lemma_Pow_One (E : Natural)
   with Post => Pow (1, E) = 1, Subprogram_Variant => (Decreases => E);

   --  Power of a product distributes: (X*Y)**E = X**E * Y**E.
   procedure Lemma_Pow_Mul_Base (X, Y : BI.Big_Integer; E : Natural)
   with
     Post               => Pow (X * Y, E) = Pow (X, E) * Pow (Y, E),
     Subprogram_Variant => (Decreases => E);

   --  Pow is non-negative for a non-negative base.
   procedure Lemma_Pow_Nonneg (B : BI.Big_Integer; E : Natural)
   with
     Pre                => B >= 0,
     Post               => Pow (B, E) >= 0,
     Subprogram_Variant => (Decreases => E);

   --  Power respects congruence mod N: X ≡ Y ⇒ X**E ≡ Y**E (mod N).
   procedure Lemma_Pow_Cong
     (X, Y : BI.Big_Integer; E : Natural; N : BI.Big_Integer)
   with
     Pre                =>
       N > 0 and then X >= 0 and then Y >= 0 and then X mod N = Y mod N,
     Post               => Pow (X, E) mod N = Pow (Y, E) mod N,
     Subprogram_Variant => (Decreases => E);

   --  Modular inverse of 2**A modulo an odd N > 1: the unique D in [0, N)
   --  with (2**A) * D ≡ 1 (mod N). Exists because N is odd.
   function Mont_Inv (A : Positive; N : BI.Big_Integer) return BI.Big_Integer
   with
     Pre  => N > 1 and then N mod 2 = 1,
     Post =>
       Mont_Inv'Result >= 0
       and then Mont_Inv'Result < N
       and then (Pow2 (A) * Mont_Inv'Result) mod N = 1;

   --  Montgomery cancellation identity (HACL\* lemma_mont_id): given an
   --  inverse D of R modulo N, (a*R mod N) * D ≡ a (mod N).
   procedure Lemma_Mont_Id (N, R, D, A : BI.Big_Integer)
   with
     Pre  =>
       N > 0
       and then R >= 0
       and then D >= 0
       and then A >= 0
       and then (R * D) mod N = 1,
     Post => (((A * R) mod N) * D) mod N = A mod N;

end Tls_Core.Ghost_Bignum.Montgomery;
