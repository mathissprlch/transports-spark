--  Tls_Core.Ghost_Bignum — a verified arbitrary-precision natural for use
--  as the *value type* of the crypto functional specs, replacing
--  Ada.Numerics.Big_Numbers.
--
--  Why this exists (§0e of the proof conventions): SPARK's stdlib
--  Big_Integers has an
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

   ------------------------------------------------------------------
   --  Carry foundation (toward carry-normalisation and mod-prime).
   --  Mirrors HACL* `carry26`: split a limb into its low 26 bits and the
   --  carry-out, with x = Lo (x) + 2**26 * Hi (x). This is the building
   --  block of the value-preserving carry sweep.
   ------------------------------------------------------------------

   Limb_Base : constant LLI := 2**26;

   function Lo26 (X : LLI) return LLI
   is (X mod Limb_Base) with Pre => X >= 0;

   function Hi26 (X : LLI) return LLI
   is (X / Limb_Base) with Pre => X >= 0;

   --  Euclidean split: the low part is a valid 26-bit limb and the value
   --  decomposes exactly. (HACL* lemma_carry26 / the carry invariant.)
   procedure Lemma_Carry26 (X : LLI)
   with
     Pre  => X >= 0,
     Post => Lo26 (X) in 0 .. In_Cap
             and then X = Lo26 (X) + Limb_Base * Hi26 (X);

   --  Carry out of one Prod_Cap-bounded limb: Hi26 (X) <= 2**36.
   Hi_Cap : constant LLI := 2**36;

   procedure Lemma_Hi26_Bound (X : LLI)
   with
     Pre  => X in 0 .. Prod_Cap,
     Post => Hi26 (X) in 0 .. Hi_Cap;

   ------------------------------------------------------------------
   --  Scalar-free same-value relation (toward mod-prime / Feval5).
   --
   --  HACL* states value preservation over `as_nat5 : nat` (an unbounded
   --  F* integer). We never have an unbounded scalar (the §0e ban on
   --  Big_Integer is exactly why this type exists), and a 130-bit value
   --  overflows Long_Long_Integer. So same-value is expressed *relationally*
   --  via a base-2**26 carry chain instead of via a scalar:
   --
   --    A and B encode the same integer  <=>  there is a carry chain C with
   --      C (0) = 0,  C (Max_Limbs) = 0,  and for every limb I
   --        A (I) + C (I) = B (I) + 2**26 * C (I + 1).
   --
   --  This is exactly base-2**26 carry propagation, column by column; the
   --  full value is never formed, so the arithmetic stays inside LLI.
   ------------------------------------------------------------------

   --  Carry chain: one slot per limb plus the carry out of the top limb.
   type Carry_Array is array (Natural range 0 .. Max_Limbs) of LLI;

   function Carry_Bounded (C : Carry_Array) return Boolean
   is (for all J in C'Range => C (J) in 0 .. Hi_Cap);

   Zero_Carry : constant Carry_Array := [others => 0];

   function Val_Eq (A, B : Big_Nat; C : Carry_Array) return Boolean
   is (C (0) = 0
       and then C (Max_Limbs) = 0
       and then (for all I in Limb_Index =>
                   A (I) + C (I) = B (I) + Limb_Base * C (I + 1)))
   with
     Pre => In_Bounds (A, Add_Cap) and then In_Bounds (B, Add_Cap)
            and then Carry_Bounded (C);

   --  Reflexivity: the all-zero carry chain links A to itself.
   procedure Lemma_Val_Eq_Refl (A : Big_Nat)
   with
     Pre  => In_Bounds (A, Add_Cap),
     Post => Val_Eq (A, A, Zero_Carry);

   --  One base-2**26 carry step at position I: limb I keeps its low 26 bits;
   --  its high part moves into limb I+1. (HACL* carry26 inside the sweep.)
   function Step_Out (A : Big_Nat; I : Limb_Index) return Big_Nat
   is ([for J in Limb_Index =>
          (if J = I then Lo26 (A (I))
           elsif J = I + 1 then A (I + 1) + Hi26 (A (I))
           else A (J))])
   with
     Pre  => In_Bounds (A, Prod_Cap) and then I < Max_Limbs - 1,
     Post => In_Bounds (Step_Out'Result, Add_Cap);

   function Step_Carry (A : Big_Nat; I : Limb_Index) return Carry_Array
   is ([for J in 0 .. Max_Limbs =>
          (if J = I + 1 then Hi26 (A (I)) else 0)])
   with
     Pre  => In_Bounds (A, Prod_Cap) and then I < Max_Limbs - 1,
     Post => Carry_Bounded (Step_Carry'Result);

   --  The carry step is value-preserving: A and Step_Out (A, I) are linked
   --  by the single-entry carry chain Step_Carry (A, I).
   procedure Lemma_Carry_Step (A : Big_Nat; I : Limb_Index)
   with
     Pre  => In_Bounds (A, Prod_Cap) and then I < Max_Limbs - 1,
     Post => Val_Eq (A, Step_Out (A, I), Step_Carry (A, I));

   ------------------------------------------------------------------
   --  Prime constant and scalar multiply (toward the mod-prime fold).
   --
   --  Poly1305 reduces mod p = 2**130 - 5. In base 2**26 that is the
   --  five-limb value [2**26 - 5, 2**26 - 1, 2**26 - 1, 2**26 - 1,
   --  2**26 - 1] (matching HACL* subtract_p5: ml = 0x3fffffb,
   --  mh = 0x3ffffff). The mod-prime fold (carry out of limb 4 at weight
   --  2**130 folds back to limb 0 times 5, since 2**130 == 5 mod p) is
   --  tracked as exact value-equality with an explicit "+ k * P" term, so
   --  no separate abstract congruence relation is needed.
   ------------------------------------------------------------------

   P_Prime : constant Big_Nat :=
     [0 => In_Cap - 4, 1 | 2 | 3 | 4 => In_Cap, others => 0];

   --  Scalar multiply, limbwise, no carry (HACL* smul_felem5 shape). K is a
   --  fold carry (<= Hi_Cap) and A's limbs are reduced (<= In_Cap), so each
   --  product K * A (I) stays inside Long_Long_Integer.
   function Smul (K : LLI; A : Big_Nat) return Big_Nat
   is ([for I in Limb_Index => K * A (I)])
   with
     Pre  => K in 0 .. Hi_Cap and then In_Bounds (A, In_Cap),
     Post => (for all I in Limb_Index => Smul'Result (I) = K * A (I))
             and then In_Bounds (Smul'Result, Add_Cap);

end Tls_Core.Ghost_Bignum;
