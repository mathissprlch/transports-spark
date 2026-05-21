--  Tls_Core.Ghost_Bignum — a verified arbitrary-precision natural for use
--  as the *value type* of the crypto functional specs, replacing
--  Ada.Numerics.Big_Numbers.
--
--  Why this exists (CLAUDE.md §0e): SPARK's stdlib Big_Integers has an
--  opaque `To_Big_Integer` (body SPARK_Mode => Off), so the prover cannot
--  relate `To_Big_Integer (x + y)` to `To_Big_Integer (x) + To_Big_Integer
--  (y)` — every limb->value bridge bounces off it. The stdlib unit is also
--  absent from the light bare-metal runtimes. A natural carried in OUR own
--  type, whose `+` / `*` have real SPARK bodies and provable algebra, closes
--  the §0e wall AND removes the Big_Numbers dependency, so the bare build
--  carries the same functional proofs as hosted.
--
--  Representation (mirrors HACL* Hacl.Spec.Poly1305.Field32xN `felem5` /
--  `as_nat5`): a fixed-width little-endian limb array in "polynomial" form
--      Value (A) = sum  A (I) * 2**(26 * I)
--  Limbs are SIGNED integers (Long_Long_Integer), not a modular type, on
--  purpose: signed arithmetic is exact ℤ once overflow is ruled out, so
--  monotonicity (a <= b => a*c <= b*c) and `a + b >= a` are native theorems
--  — whereas a modular `+` can wrap silently, defeating those. Limbs are
--  capped at 26 bits so that a convolution column sum of up to Max_Limbs
--  products of two 26-bit limbs stays below Long_Long_Integer'Last:
--  160 * (2**26)**2 = 2**59.3 < 2**63. (felem_fits5 discipline.)
--
--  Entirely Ghost: never runs, no runtime cost, uses only Long_Long_Integer
--  (no 128-bit type, no Big_Numbers) so it compiles on every target.

package Tls_Core.Ghost_Bignum
  with SPARK_Mode, Ghost
is

   subtype LLI is Long_Long_Integer;

   Max_Limbs : constant := 160;          --  >= an RSA-2048 product in 26-bit limbs
   subtype Limb_Index is Natural range 0 .. Max_Limbs - 1;
   type Big_Nat is array (Limb_Index) of LLI;

   Zero : constant Big_Nat := [others => 0];

   --  Per-limb caps (felem_fits5 analogue). Add_Cap leaves room for a couple
   --  of additions; Mul_Cap (27 bits) is the multiply-input acceptance bound,
   --  wide enough to also accept the sum of two In_Cap (26-bit) limbs so the
   --  distributivity lemma can feed B + C into a multiply. Even at 2**27 a
   --  column sum of up to Max_Limbs products stays below 2**63:
   --  160 * (2**27)**2 = 2**61.3 < 2**63.
   Mul_Cap    : constant LLI := 2**27;
   In_Cap     : constant LLI := 2**26 - 1;   --  26-bit multiply inputs
   Two_Pow_54 : constant LLI := 2**54;        --  (2**27)**2
   --  A product limb is a column sum of up to Max_Limbs products of two
   --  Mul_Cap-bounded limbs: <= 160 * 2**54 = 2**61.32.
   Prod_Cap   : constant LLI := LLI (Max_Limbs) * Two_Pow_54;
   --  Add_Cap must hold a product limb (so A*B + A*C type-checks) yet keep
   --  the sum of two below 2**63: 2 * (2**62 - 1) = 2**63 - 2 <= LLI'Last.
   Add_Cap    : constant LLI := 2**62 - 1;
   Assoc_Cap  : constant LLI := 2**60;

   function In_Bounds (A : Big_Nat; Cap : LLI) return Boolean
   is (for all I in Limb_Index => A (I) in 0 .. Cap);

   ------------------------------------------------------------------
   --  Addition (HACL* `fadd5`): componentwise, no carry.
   ------------------------------------------------------------------

   function "+" (A, B : Big_Nat) return Big_Nat
   with
     Pre  => In_Bounds (A, Add_Cap) and then In_Bounds (B, Add_Cap),
     Post => (for all I in Limb_Index => "+"'Result (I) = A (I) + B (I));

   procedure Lemma_Add_Comm (A, B : Big_Nat)
   with
     Pre  => In_Bounds (A, Add_Cap) and then In_Bounds (B, Add_Cap),
     Post => A + B = B + A;

   procedure Lemma_Add_Zero_R (A : Big_Nat)
   with
     Pre  => In_Bounds (A, Add_Cap),
     Post => A + Zero = A;

   procedure Lemma_Add_Assoc (A, B, C : Big_Nat)
   with
     Pre  =>
       In_Bounds (A, Assoc_Cap) and then In_Bounds (B, Assoc_Cap)
       and then In_Bounds (C, Assoc_Cap),
     Post => (A + B) + C = A + (B + C);

   ------------------------------------------------------------------
   --  Multiplication (HACL* `mul_felem5` shape: schoolbook convolution).
   --  result (K) = sum_{i=0..K} A (I) * B (K - I)  (truncated at Max_Limbs).
   ------------------------------------------------------------------

   --  A single 26-bit limb, range-constrained so gnatprove's interval
   --  propagation bounds products (Mul_Limb * Mul_Limb in 0 .. 2**52)
   --  without any explicit nonlinear monotonicity lemma.
   subtype Mul_Limb is LLI range 0 .. Mul_Cap;

   --  Partial column sum  sum_{i=0..T} A (I) * B (K - I). Expression
   --  function so gnatprove can unfold the recurrence in the algebra proofs;
   --  the Mul_Limb subtype conversions give interval bounds for free.
   function Mul_Col (A, B : Big_Nat; K, T : Limb_Index) return LLI
   is (if T = 0
       then Mul_Limb (A (0)) * Mul_Limb (B (K))
       else Mul_Col (A, B, K, T - 1)
            + Mul_Limb (A (T)) * Mul_Limb (B (K - T)))
   with
     Pre                => In_Bounds (A, Mul_Cap) and then In_Bounds (B, Mul_Cap)
                           and then T <= K,
     Post               => Mul_Col'Result in 0 .. LLI (T + 1) * Two_Pow_54,
     Subprogram_Variant => (Decreases => T);

   function "*" (A, B : Big_Nat) return Big_Nat
   with
     Pre  => In_Bounds (A, Mul_Cap) and then In_Bounds (B, Mul_Cap),
     Post =>
       (for all K in Limb_Index => "*"'Result (K) = Mul_Col (A, B, K, K))
       and then In_Bounds ("*"'Result, Add_Cap);

   ------------------------------------------------------------------
   --  Multiplication algebra.
   ------------------------------------------------------------------

   --  Widen a limb bound (In_Bounds is monotone in the cap).
   procedure Lemma_Bounds_Mono (A : Big_Nat; Lo, Hi : LLI)
   with
     Global => null,
     Pre    => In_Bounds (A, Lo) and then Lo <= Hi,
     Post   => In_Bounds (A, Hi);

   --  Column-wise distributivity, proven by induction on T. BC is the
   --  precomputed limbwise sum of B and C (passed in so the contract needs
   --  no inline `+`, hence no cap-widening inside the contract):
   --    Mul_Col (A, BC, K, T) = Mul_Col (A, B, K, T) + Mul_Col (A, C, K, T)
   procedure Lemma_Mul_Col_Distrib (A, B, C, BC : Big_Nat; K, T : Limb_Index)
   with
     Pre                =>
       In_Bounds (A, Mul_Cap) and then In_Bounds (B, Mul_Cap)
       and then In_Bounds (C, Mul_Cap) and then In_Bounds (BC, Mul_Cap)
       and then (for all I in Limb_Index => BC (I) = B (I) + C (I))
       and then T <= K,
     Post               =>
       Mul_Col (A, BC, K, T)
       = Mul_Col (A, B, K, T) + Mul_Col (A, C, K, T),
     Subprogram_Variant => (Decreases => T);

   --  Left-distributivity of the full product: A * BC = A * B + A * C,
   --  where BC is the precomputed limbwise sum of B and C (param, so the
   --  contract needs no inline `+` and no cap-widening).
   procedure Lemma_Mul_Distrib (A, B, C, BC : Big_Nat)
   with
     Pre  =>
       In_Bounds (A, Mul_Cap) and then In_Bounds (B, Mul_Cap)
       and then In_Bounds (C, Mul_Cap) and then In_Bounds (BC, Mul_Cap)
       and then (for all I in Limb_Index => BC (I) = B (I) + C (I)),
     Post => A * BC = A * B + A * C;

end Tls_Core.Ghost_Bignum;
