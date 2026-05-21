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

   --  Convolution support: if A is zero from index Na on and B from index Nb
   --  on, the product A * B is zero from index Na + Nb - 1 on. (The product
   --  of two operands with highest set limbs Na-1 and Nb-1 has highest set
   --  limb (Na-1)+(Nb-1).) Needed so array-equality proofs over the product
   --  know its high limbs vanish. Proven by induction on T over Mul_Col.
   procedure Lemma_Mul_Col_Zero
     (A, B : Big_Nat; K, T, Na, Nb : Limb_Index)
   with
     Pre                =>
       In_Bounds (A, Mul_Cap) and then In_Bounds (B, Mul_Cap)
       and then T <= K
       and then Na >= 1 and then Nb >= 1
       and then Na + Nb - 1 <= K
       and then (for all I in Limb_Index => (if I >= Na then A (I) = 0))
       and then (for all I in Limb_Index => (if I >= Nb then B (I) = 0)),
     Post               => Mul_Col (A, B, K, T) = 0,
     Subprogram_Variant => (Decreases => T);

   --  AB is the precomputed product A * B (param, so the contract indexes a
   --  plain array rather than an operator result).
   procedure Lemma_Mul_Zero_High (A, B, AB : Big_Nat; Na, Nb : Limb_Index)
   with
     Pre  =>
       In_Bounds (A, Mul_Cap) and then In_Bounds (B, Mul_Cap)
       and then Na >= 1 and then Nb >= 1
       and then Na + Nb - 1 <= Max_Limbs - 1
       and then (for all I in Limb_Index => (if I >= Na then A (I) = 0))
       and then (for all I in Limb_Index => (if I >= Nb then B (I) = 0))
       and then AB = A * B,
     Post =>
       (for all K in Limb_Index =>
          (if K >= Na + Nb - 1 then AB (K) = 0));

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

   --  A convolution column of two five-limb (<= Mul_Cap) operands is a sum
   --  of at most nine products of two 2**27 limbs: <= 9 * 2**54. The carry
   --  out of such a column (and the cascade through a nine-limb sweep) then
   --  stays under Conv_Carry_Cap = 2**32 -- tight enough for Fold_High_9.
   Conv_Col_Cap   : constant LLI := LLI (9) * Two_Pow_54;
   Conv_Carry_Cap : constant LLI := 2**32;

   procedure Lemma_Hi26_Conv (X : LLI)
   with
     Pre  => X in 0 .. Conv_Col_Cap + Conv_Carry_Cap,
     Post => Hi26 (X) in 0 .. Conv_Carry_Cap;

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

   --  Uniqueness: two *reduced* values (limbs <= In_Cap < 2**26) that are
   --  value-equal are limb-equal. The base-2**26 representation is unique
   --  below the base, so the linking carry chain is forced to all zero. This
   --  is the foundation for canonical-form matching (e.g. proving the
   --  imperative reduced result equals the spec's reduced value).
   procedure Lemma_Val_Eq_Unique (A, B : Big_Nat; C : Carry_Array)
   with
     Pre  => In_Bounds (A, In_Cap) and then In_Bounds (B, In_Cap)
             and then Carry_Bounded (C)
             and then Val_Eq (A, B, C),
     Post => A = B;

   ------------------------------------------------------------------
   --  Signed-carry value-equality (a proper equivalence for COMPOSING
   --  reduction steps). Val_Eq's carry chain is non-negative, so it is
   --  directional and does not compose: chaining "A =val S" and "T =val S"
   --  to "A =val T" needs the difference of the two chains, which is signed.
   --  SVal_Eq is the same column relation with a signed carry chain, giving
   --  symmetry and transitivity. Operands stay <= Add_Cap and |carry| <=
   --  Hi_Cap so the column arithmetic still fits Long_Long_Integer
   --  (Add_Cap + 2**26 * Hi_Cap = 2**63 - 1).
   ------------------------------------------------------------------

   function SC_Bounded (C : Carry_Array) return Boolean
   is (for all J in C'Range => C (J) in -Hi_Cap .. Hi_Cap);

   function Neg_Carry (C : Carry_Array) return Carry_Array
   is ([for J in C'Range => -C (J)])
   with Pre => SC_Bounded (C), Post => SC_Bounded (Neg_Carry'Result);

   function Add_Carry (C1, C2 : Carry_Array) return Carry_Array
   is ([for J in C1'Range => C1 (J) + C2 (J)])
   with Pre => SC_Bounded (C1) and then SC_Bounded (C2);

   function SVal_Eq (A, B : Big_Nat; C : Carry_Array) return Boolean
   is (C (0) = 0
       and then C (Max_Limbs) = 0
       and then (for all I in Limb_Index =>
                   A (I) + C (I) = B (I) + Limb_Base * C (I + 1)))
   with
     Pre => In_Bounds (A, Add_Cap) and then In_Bounds (B, Add_Cap)
            and then SC_Bounded (C);

   --  Every Val_Eq is an SVal_Eq (a non-negative chain is signed-bounded).
   procedure Lemma_Val_To_SVal (A, B : Big_Nat; C : Carry_Array)
   with
     Pre  => In_Bounds (A, Add_Cap) and then In_Bounds (B, Add_Cap)
             and then Carry_Bounded (C) and then Val_Eq (A, B, C),
     Post => SVal_Eq (A, B, C);

   --  Symmetry: negate the carry chain.
   procedure Lemma_SVal_Sym (A, B : Big_Nat; C : Carry_Array)
   with
     Pre  => In_Bounds (A, Add_Cap) and then In_Bounds (B, Add_Cap)
             and then SC_Bounded (C) and then SVal_Eq (A, B, C),
     Post => SVal_Eq (B, A, Neg_Carry (C));

   --  Transitivity: add the carry chains. The caller must keep the summed
   --  chain within Hi_Cap (true for the small chains of a reduction).
   procedure Lemma_SVal_Trans (A, B, D : Big_Nat; C1, C2 : Carry_Array)
   with
     Pre  => In_Bounds (A, Add_Cap) and then In_Bounds (B, Add_Cap)
             and then In_Bounds (D, Add_Cap)
             and then SC_Bounded (C1) and then SC_Bounded (C2)
             and then SC_Bounded (Add_Carry (C1, C2))
             and then SVal_Eq (A, B, C1) and then SVal_Eq (B, D, C2),
     Post => SVal_Eq (A, D, Add_Carry (C1, C2));

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

   ------------------------------------------------------------------
   --  Exact carry sweep of a wide five-limb value (HACL*
   --  carry_wide_felem5, exact-value part — the prime fold is applied
   --  separately, see Smul / P_Prime above).
   --
   --  Input A holds five wide limbs (limbs 0..4 up to Prod_Cap, limbs 5+
   --  zero). The sweep propagates carries left-to-right; the carry out of
   --  limb 4 lands at limb 5 (weight 2**130), to be folded next. Output
   --  limbs 0..4 are reduced (< 2**26) and limb 5 holds that top carry.
   --  Sweep5_Out and the net carry chain Sweep5_Chain link A to the swept
   --  value by Val_Eq (exact same integer).
   ------------------------------------------------------------------

   --  The five sequential carries (Sw_Ci is the carry into limb i+1).
   function Sw_C0 (A : Big_Nat) return LLI is (Hi26 (A (0)))
   with Pre => In_Bounds (A, Prod_Cap), Post => Sw_C0'Result in 0 .. Hi_Cap;

   function Sw_C1 (A : Big_Nat) return LLI is (Hi26 (A (1) + Sw_C0 (A)))
   with Pre => In_Bounds (A, Prod_Cap), Post => Sw_C1'Result in 0 .. Hi_Cap;

   function Sw_C2 (A : Big_Nat) return LLI is (Hi26 (A (2) + Sw_C1 (A)))
   with Pre => In_Bounds (A, Prod_Cap), Post => Sw_C2'Result in 0 .. Hi_Cap;

   function Sw_C3 (A : Big_Nat) return LLI is (Hi26 (A (3) + Sw_C2 (A)))
   with Pre => In_Bounds (A, Prod_Cap), Post => Sw_C3'Result in 0 .. Hi_Cap;

   function Sw_C4 (A : Big_Nat) return LLI is (Hi26 (A (4) + Sw_C3 (A)))
   with Pre => In_Bounds (A, Prod_Cap), Post => Sw_C4'Result in 0 .. Hi_Cap;

   function Sweep5_Out (A : Big_Nat) return Big_Nat
   is ([0      => Lo26 (A (0)),
        1      => Lo26 (A (1) + Sw_C0 (A)),
        2      => Lo26 (A (2) + Sw_C1 (A)),
        3      => Lo26 (A (3) + Sw_C2 (A)),
        4      => Lo26 (A (4) + Sw_C3 (A)),
        5      => Sw_C4 (A),
        others => 0])
   with Pre => In_Bounds (A, Prod_Cap),
        Post => In_Bounds (Sweep5_Out'Result, Add_Cap);

   function Sweep5_Chain (A : Big_Nat) return Carry_Array
   is ([1      => Sw_C0 (A),
        2      => Sw_C1 (A),
        3      => Sw_C2 (A),
        4      => Sw_C3 (A),
        5      => Sw_C4 (A),
        others => 0])
   with Pre => In_Bounds (A, Prod_Cap),
        Post => Carry_Bounded (Sweep5_Chain'Result);

   --  The sweep is value-preserving: a five-limb wide A and its swept form
   --  encode the same integer (the carry out lives at limb 5).
   procedure Lemma_Sweep5 (A : Big_Nat)
   with
     Pre  => In_Bounds (A, Prod_Cap)
             and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                         A (I) = 0),
     Post => Val_Eq (A, Sweep5_Out (A), Sweep5_Chain (A));

   ------------------------------------------------------------------
   --  Exact carry sweep of a wide nine-limb value (the convolution of two
   --  five-limb numbers has columns 0..8). Same shape as Sweep5 but over
   --  nine limbs; the carry out of limb 8 lands at limb 9, ready to be
   --  folded back (positions 5..9 -> 0..4) by the mod-prime reduce.
   ------------------------------------------------------------------

   function Sw9_C0 (A : Big_Nat) return LLI is (Hi26 (A (0)))
   with Pre => In_Bounds (A, Prod_Cap), Post => Sw9_C0'Result in 0 .. Hi_Cap;

   function Sw9_C1 (A : Big_Nat) return LLI is (Hi26 (A (1) + Sw9_C0 (A)))
   with Pre => In_Bounds (A, Prod_Cap), Post => Sw9_C1'Result in 0 .. Hi_Cap;

   function Sw9_C2 (A : Big_Nat) return LLI is (Hi26 (A (2) + Sw9_C1 (A)))
   with Pre => In_Bounds (A, Prod_Cap), Post => Sw9_C2'Result in 0 .. Hi_Cap;

   function Sw9_C3 (A : Big_Nat) return LLI is (Hi26 (A (3) + Sw9_C2 (A)))
   with Pre => In_Bounds (A, Prod_Cap), Post => Sw9_C3'Result in 0 .. Hi_Cap;

   function Sw9_C4 (A : Big_Nat) return LLI is (Hi26 (A (4) + Sw9_C3 (A)))
   with Pre => In_Bounds (A, Prod_Cap), Post => Sw9_C4'Result in 0 .. Hi_Cap;

   function Sw9_C5 (A : Big_Nat) return LLI is (Hi26 (A (5) + Sw9_C4 (A)))
   with Pre => In_Bounds (A, Prod_Cap), Post => Sw9_C5'Result in 0 .. Hi_Cap;

   function Sw9_C6 (A : Big_Nat) return LLI is (Hi26 (A (6) + Sw9_C5 (A)))
   with Pre => In_Bounds (A, Prod_Cap), Post => Sw9_C6'Result in 0 .. Hi_Cap;

   function Sw9_C7 (A : Big_Nat) return LLI is (Hi26 (A (7) + Sw9_C6 (A)))
   with Pre => In_Bounds (A, Prod_Cap), Post => Sw9_C7'Result in 0 .. Hi_Cap;

   function Sw9_C8 (A : Big_Nat) return LLI is (Hi26 (A (8) + Sw9_C7 (A)))
   with Pre => In_Bounds (A, Prod_Cap), Post => Sw9_C8'Result in 0 .. Hi_Cap;

   function Sweep9_Out (A : Big_Nat) return Big_Nat
   is ([0      => Lo26 (A (0)),
        1      => Lo26 (A (1) + Sw9_C0 (A)),
        2      => Lo26 (A (2) + Sw9_C1 (A)),
        3      => Lo26 (A (3) + Sw9_C2 (A)),
        4      => Lo26 (A (4) + Sw9_C3 (A)),
        5      => Lo26 (A (5) + Sw9_C4 (A)),
        6      => Lo26 (A (6) + Sw9_C5 (A)),
        7      => Lo26 (A (7) + Sw9_C6 (A)),
        8      => Lo26 (A (8) + Sw9_C7 (A)),
        9      => Sw9_C8 (A),
        others => 0])
   with Pre => In_Bounds (A, Prod_Cap),
        Post => In_Bounds (Sweep9_Out'Result, Add_Cap)
                and then (for all I in Limb_Index range 0 .. 8 =>
                            Sweep9_Out'Result (I) in 0 .. In_Cap)
                and then (for all I in Limb_Index range 10 .. Max_Limbs - 1 =>
                            Sweep9_Out'Result (I) = 0);

   function Sweep9_Chain (A : Big_Nat) return Carry_Array
   is ([1      => Sw9_C0 (A),
        2      => Sw9_C1 (A),
        3      => Sw9_C2 (A),
        4      => Sw9_C3 (A),
        5      => Sw9_C4 (A),
        6      => Sw9_C5 (A),
        7      => Sw9_C6 (A),
        8      => Sw9_C7 (A),
        9      => Sw9_C8 (A),
        others => 0])
   with Pre => In_Bounds (A, Prod_Cap),
        Post => Carry_Bounded (Sweep9_Chain'Result);

   procedure Lemma_Sweep9 (A : Big_Nat)
   with
     Pre  => In_Bounds (A, Prod_Cap)
             and then (for all I in Limb_Index range 9 .. Max_Limbs - 1 =>
                         A (I) = 0),
     Post => Val_Eq (A, Sweep9_Out (A), Sweep9_Chain (A));

   --  For a convolution-sized input (columns <= Conv_Col_Cap) the sweep's
   --  carries -- including the top carry at limb 9 -- stay <= Conv_Carry_Cap
   --  (= Fold9_Top_Cap), so Sweep9_Out can be consumed by Fold_High_9.
   procedure Lemma_Sweep9_Conv (A : Big_Nat)
   with
     Pre  => In_Bounds (A, Conv_Col_Cap)
             and then (for all I in Limb_Index range 9 .. Max_Limbs - 1 =>
                         A (I) = 0),
     Post => Sweep9_Out (A) (9) in 0 .. Conv_Carry_Cap;

   ------------------------------------------------------------------
   --  Mod-prime fold (HACL* carry_wide_felem5 z1 = z1 + (z1 << 2)).
   --
   --  After the sweep, limb 5 holds the top carry c4 at weight 2**130.
   --  Since 2**130 = 5 + p, that carry folds back into limb 0 times 5,
   --  changing the value by exactly -c4 * p (i.e. nothing, mod p). We
   --  track this exactly: Fold_Out (B) is the reduced result, and
   --  Fold_Plus_P (B) = Fold_Out (B) + c4 * P_Prime is value-equal to the
   --  pre-fold B (Lemma_Fold). The "+ c4 * P_Prime" term is written inline
   --  with P_Prime's concrete limbs (p0 = In_Cap - 4, p1..p4 = In_Cap) so
   --  every product is a constant multiple of c4 (linear, no nonlinear VC).
   ------------------------------------------------------------------

   --  Top carry small enough that the folded limbs stay within Add_Cap.
   --  (A real Poly1305 sweep yields c4 <= ~2**32, well under this.)
   Fold_C_Cap : constant LLI := 2**35;

   --  The reduced fold result: c4 (limb 5) folded into limb 0 times 5.
   function Fold_Out (B : Big_Nat) return Big_Nat
   is ([0      => B (0) + 5 * B (5),
        1      => B (1),
        2      => B (2),
        3      => B (3),
        4      => B (4),
        others => 0])
   with
     Pre  => (for all I in Limb_Index range 0 .. 4 => B (I) in 0 .. In_Cap)
             and then B (5) in 0 .. Fold_C_Cap,
     Post => In_Bounds (Fold_Out'Result, Add_Cap);

   --  Fold_Out (B) plus c4 * P_Prime, written with P_Prime's concrete limbs.
   function Fold_Plus_P (B : Big_Nat) return Big_Nat
   is ([0      => B (0) + 5 * B (5) + B (5) * (In_Cap - 4),
        1      => B (1) + B (5) * In_Cap,
        2      => B (2) + B (5) * In_Cap,
        3      => B (3) + B (5) * In_Cap,
        4      => B (4) + B (5) * In_Cap,
        others => 0])
   with
     Pre  => (for all I in Limb_Index range 0 .. 4 => B (I) in 0 .. In_Cap)
             and then B (5) in 0 .. Fold_C_Cap,
     Post => In_Bounds (Fold_Plus_P'Result, Add_Cap);

   function Fold_Chain (C4 : LLI) return Carry_Array
   is ([1 | 2 | 3 | 4 | 5 => C4, others => 0])
   with Pre => C4 in 0 .. Fold_C_Cap, Post => Carry_Bounded (Fold_Chain'Result);

   --  Fold_Plus_P (B) = Fold_Out (B) + c4 * P_Prime encodes the same integer
   --  as the pre-fold B. So Fold_Out (B) = B - c4 * p, i.e. Fold_Out (B) is
   --  congruent to B mod p (it differs by the multiple c4 * p).
   procedure Lemma_Fold (B : Big_Nat)
   with
     Pre  => (for all I in Limb_Index range 0 .. 4 => B (I) in 0 .. In_Cap)
             and then B (5) in 0 .. Fold_C_Cap
             and then (for all I in Limb_Index range 6 .. Max_Limbs - 1 =>
                         B (I) = 0),
     Post => Val_Eq (Fold_Plus_P (B), B, Fold_Chain (B (5)));

   ------------------------------------------------------------------
   --  Final canonical reduce (HACL* subtract_p5).
   --
   --  Input B is fully reduced (limbs 0..4 <= In_Cap, 5+ = 0), so its value
   --  is < 2**130 and hence in [0, 2p). If it is >= p -- top four limbs all
   --  2**26-1 (= In_Cap) and limb 0 >= 2**26-5 (= In_Cap - 4) -- subtract p
   --  once. In that branch the subtraction is *exact limbwise* (no borrow),
   --  since limb 0 >= ml and limbs 1..4 equal mh, so Subtract_P5_Out (B) plus
   --  the conditional p equals B exactly (Val_Eq with the zero carry chain).
   --  The output is therefore congruent to B mod p and is itself < p.
   ------------------------------------------------------------------

   function Sub_Cond (B : Big_Nat) return Boolean
   is (B (4) = In_Cap and then B (3) = In_Cap and then B (2) = In_Cap
       and then B (1) = In_Cap and then B (0) >= In_Cap - 4);

   function Subtract_P5_Out (B : Big_Nat) return Big_Nat
   is (if Sub_Cond (B)
       then [0 => B (0) - (In_Cap - 4), others => 0]
       else B)
   with
     Pre  => (for all I in Limb_Index range 0 .. 4 => B (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                         B (I) = 0),
     Post => In_Bounds (Subtract_P5_Out'Result, In_Cap);

   function Sub_Sel_P (B : Big_Nat) return Big_Nat
   is (if Sub_Cond (B) then P_Prime else Zero)
   with Post => In_Bounds (Sub_Sel_P'Result, In_Cap);

   --  Subtract_P5_Out (B) + (cond ? p : 0) equals B exactly, so the output
   --  is congruent to B mod p (differs by the single multiple cond * p).
   procedure Lemma_Subtract_P5 (B : Big_Nat)
   with
     Pre  => (for all I in Limb_Index range 0 .. 4 => B (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                         B (I) = 0),
     Post => Val_Eq (Subtract_P5_Out (B) + Sub_Sel_P (B), B, Zero_Carry);

   ------------------------------------------------------------------
   --  Field rotation: r * 2**26 mod p (HACL* lemma_fmul5_pow26).
   --
   --  This is the first multiply brick. The field multiply expresses the
   --  product as a sum of single-limb scalings of *rotations* of r, where
   --  each rotation r * 2**(26*i) mod p keeps r's limbs reduced -- so the
   --  products stay inside Long_Long_Integer and the wide convolution is
   --  never formed. Rotation by one position is just a shift-up followed by
   --  the existing prime fold: shifting reduced r up one limb puts r4 at
   --  position 5 (weight 2**130), and folding it back (x5) gives
   --  (5*r4, r0, r1, r2, r3) == r * 2**26 mod p. Because r is reduced, the
   --  fold carry r4 <= In_Cap is small, so this is just Lemma_Fold applied
   --  to the shifted r -- no new overflow.
   ------------------------------------------------------------------

   --  r shifted up one 26-bit limb position: value = r * 2**26. Reduced r
   --  in, so limbs 0..4 stay reduced and r4 lands (reduced) at limb 5.
   function Shift1 (R : Big_Nat) return Big_Nat
   is ([0      => 0,
        1      => R (0),
        2      => R (1),
        3      => R (2),
        4      => R (3),
        5      => R (4),
        others => 0])
   with
     Pre  => (for all I in Limb_Index range 0 .. 4 => R (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                         R (I) = 0),
     Post => (for all I in Limb_Index range 0 .. 4 => Shift1'Result (I) in 0 .. In_Cap)
             and then Shift1'Result (5) in 0 .. Fold_C_Cap
             and then (for all I in Limb_Index range 6 .. Max_Limbs - 1 =>
                         Shift1'Result (I) = 0);

   --  Fold_Out (Shift1 (R)) = (5*r4, r0, r1, r2, r3) = rotate-by-one of r,
   --  and it is congruent to Shift1 (R) = r * 2**26 mod p (Lemma_Fold).
   procedure Lemma_Rotate1 (R : Big_Nat)
   with
     Pre  => (for all I in Limb_Index range 0 .. 4 => R (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                         R (I) = 0),
     Post =>
       Val_Eq
         (Fold_Plus_P (Shift1 (R)), Shift1 (R), Fold_Chain (Shift1 (R) (5)));

   ------------------------------------------------------------------
   --  General high-limb fold (HACL* carry_wide_felem5 fold step).
   --
   --  Folds the four high positions 5..8 of a *reduced* value down into
   --  positions 0..3 (each times 5, since 2**(26*(m+5)) = 2**130 * 2**(26m)
   --  == 5 * 2**(26m) mod p). Because the inputs are reduced (limbs <=
   --  In_Cap), every product limb*P stays <= ~In_Cap**2 < 2**54 and the
   --  carry chain entries stay <= 4*In_Cap < Hi_Cap -- nothing overflows.
   --
   --  This one brick subsumes the field rotations (rotate_i (R) =
   --  Fold_High_Out (Shift_i (R)), the unused high positions being zero)
   --  and the reduce step of the field multiply (fold the reduced wide
   --  product back to five limbs).
   ------------------------------------------------------------------

   function Fold_High_Out (B : Big_Nat) return Big_Nat
   is ([0      => B (0) + 5 * B (5),
        1      => B (1) + 5 * B (6),
        2      => B (2) + 5 * B (7),
        3      => B (3) + 5 * B (8),
        4      => B (4),
        others => 0])
   with
     Pre  => (for all I in Limb_Index range 0 .. 8 => B (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 9 .. Max_Limbs - 1 =>
                         B (I) = 0),
     Post => In_Bounds (Fold_High_Out'Result, Add_Cap);

   --  Fold_High_Out (B) plus the four prime multiples (one per folded
   --  position), written with P_Prime's concrete limbs so every product is
   --  a constant multiple of a reduced limb (linear, no nonlinear VC).
   function Fold_High_Plus_P (B : Big_Nat) return Big_Nat
   is ([0      => B (0) + 5 * B (5) + B (5) * (In_Cap - 4),
        1      => B (1) + 5 * B (6) + B (5) * In_Cap + B (6) * (In_Cap - 4),
        2      =>
          B (2) + 5 * B (7)
          + B (5) * In_Cap + B (6) * In_Cap + B (7) * (In_Cap - 4),
        3      =>
          B (3) + 5 * B (8)
          + B (5) * In_Cap + B (6) * In_Cap + B (7) * In_Cap
          + B (8) * (In_Cap - 4),
        4      =>
          B (4)
          + B (5) * In_Cap + B (6) * In_Cap + B (7) * In_Cap + B (8) * In_Cap,
        5      => B (6) * In_Cap + B (7) * In_Cap + B (8) * In_Cap,
        6      => B (7) * In_Cap + B (8) * In_Cap,
        7      => B (8) * In_Cap,
        others => 0])
   with
     Pre  => (for all I in Limb_Index range 0 .. 8 => B (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 9 .. Max_Limbs - 1 =>
                         B (I) = 0),
     Post => In_Bounds (Fold_High_Plus_P'Result, Add_Cap);

   function Fold_High_Chain (B : Big_Nat) return Carry_Array
   is ([0      => 0,
        1      => B (5),
        2      => B (5) + B (6),
        3      => B (5) + B (6) + B (7),
        4      => B (5) + B (6) + B (7) + B (8),
        5      => B (5) + B (6) + B (7) + B (8),
        6      => B (6) + B (7) + B (8),
        7      => B (7) + B (8),
        8      => B (8),
        others => 0])
   with
     Pre  => (for all I in Limb_Index range 5 .. 8 => B (I) in 0 .. In_Cap),
     Post => Carry_Bounded (Fold_High_Chain'Result);

   --  Fold_High_Plus_P (B) = Fold_High_Out (B) + (sum of the four folded
   --  positions times the matching shift of p) is value-equal to B, so
   --  Fold_High_Out (B) is congruent to B mod p.
   procedure Lemma_Fold_High (B : Big_Nat)
   with
     Pre  => (for all I in Limb_Index range 0 .. 8 => B (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 9 .. Max_Limbs - 1 =>
                         B (I) = 0),
     Post => Val_Eq (Fold_High_Plus_P (B), B, Fold_High_Chain (B));

   ------------------------------------------------------------------
   --  Field rotations by 2, 3, 4 positions (HACL* lemma_fmul5_pow52 /
   --  pow78 / pow104). Each is just Fold_High applied to r shifted up by
   --  the matching number of limbs: the wrapped top limbs land in the high
   --  positions (all <= In_Cap because r is reduced) and Fold_High folds
   --  them back x5. rotate_i (R) = Fold_High_Out (Shift_i (R)).
   ------------------------------------------------------------------

   function Shift2 (R : Big_Nat) return Big_Nat
   is ([0 | 1  => 0,
        2      => R (0),
        3      => R (1),
        4      => R (2),
        5      => R (3),
        6      => R (4),
        others => 0])
   with
     Pre  => (for all I in Limb_Index range 0 .. 4 => R (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                         R (I) = 0),
     Post => (for all I in Limb_Index range 0 .. 8 => Shift2'Result (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 9 .. Max_Limbs - 1 =>
                         Shift2'Result (I) = 0);

   function Shift3 (R : Big_Nat) return Big_Nat
   is ([0 | 1 | 2 => 0,
        3          => R (0),
        4          => R (1),
        5          => R (2),
        6          => R (3),
        7          => R (4),
        others     => 0])
   with
     Pre  => (for all I in Limb_Index range 0 .. 4 => R (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                         R (I) = 0),
     Post => (for all I in Limb_Index range 0 .. 8 => Shift3'Result (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 9 .. Max_Limbs - 1 =>
                         Shift3'Result (I) = 0);

   function Shift4 (R : Big_Nat) return Big_Nat
   is ([0 | 1 | 2 | 3 => 0,
        4              => R (0),
        5              => R (1),
        6              => R (2),
        7              => R (3),
        8              => R (4),
        others         => 0])
   with
     Pre  => (for all I in Limb_Index range 0 .. 4 => R (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                         R (I) = 0),
     Post => (for all I in Limb_Index range 0 .. 8 => Shift4'Result (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 9 .. Max_Limbs - 1 =>
                         Shift4'Result (I) = 0);

   procedure Lemma_Rotate2 (R : Big_Nat)
   with
     Pre  => (for all I in Limb_Index range 0 .. 4 => R (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                         R (I) = 0),
     Post =>
       Val_Eq
         (Fold_High_Plus_P (Shift2 (R)), Shift2 (R), Fold_High_Chain (Shift2 (R)));

   procedure Lemma_Rotate3 (R : Big_Nat)
   with
     Pre  => (for all I in Limb_Index range 0 .. 4 => R (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                         R (I) = 0),
     Post =>
       Val_Eq
         (Fold_High_Plus_P (Shift3 (R)), Shift3 (R), Fold_High_Chain (Shift3 (R)));

   procedure Lemma_Rotate4 (R : Big_Nat)
   with
     Pre  => (for all I in Limb_Index range 0 .. 4 => R (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                         R (I) = 0),
     Post =>
       Val_Eq
         (Fold_High_Plus_P (Shift4 (R)), Shift4 (R), Fold_High_Chain (Shift4 (R)));

   ------------------------------------------------------------------
   --  Bridge: the high-fold multiple in convolution form.
   --
   --  Fold_High_Plus_P (B) = Fold_High_Out (B) + p * High4 (B), where
   --  High4 (B) = (B5, B6, B7, B8) collects the four folded positions.
   --  This recasts the proven Lemma_Fold_High into the "+ Mul (P_Prime, Q)"
   --  shape used by the congruence relation Cong_P_W, so congruence is
   --  preserved by add (via Lemma_Mul_Distrib on p) and by scalar multiply.
   ------------------------------------------------------------------

   function High4 (B : Big_Nat) return Big_Nat
   is ([0      => B (5),
        1      => B (6),
        2      => B (7),
        3      => B (8),
        others => 0])
   with
     Pre  => (for all I in Limb_Index range 5 .. 8 => B (I) in 0 .. In_Cap),
     Post => In_Bounds (High4'Result, In_Cap)
             and then (for all I in Limb_Index range 4 .. Max_Limbs - 1 =>
                         High4'Result (I) = 0);

   procedure Lemma_Fold_High_Mul_Form (B : Big_Nat)
   with
     Pre  => (for all I in Limb_Index range 0 .. 8 => B (I) in 0 .. In_Cap)
             and then (for all I in Limb_Index range 9 .. Max_Limbs - 1 =>
                         B (I) = 0),
     Post => Fold_High_Plus_P (B) = Fold_High_Out (B) + P_Prime * High4 (B);

   ------------------------------------------------------------------
   --  Five-position high fold (5..9 -> 0..4, x5). Used on the swept
   --  convolution, whose carry out of column 8 lands at limb 9. Limbs 5..8
   --  are reduced (<= In_Cap); limb 9 is the small top carry (<= Fold9_Top_
   --  Cap) so the chain entry B5+..+B9 stays within Hi_Cap. Same shape as
   --  Fold_High with one more folded position.
   ------------------------------------------------------------------

   Fold9_Top_Cap : constant LLI := 2**32;

   function Fold_High_9_Out (B : Big_Nat) return Big_Nat
   is ([0      => B (0) + 5 * B (5),
        1      => B (1) + 5 * B (6),
        2      => B (2) + 5 * B (7),
        3      => B (3) + 5 * B (8),
        4      => B (4) + 5 * B (9),
        others => 0])
   with
     Pre  => (for all I in Limb_Index range 0 .. 8 => B (I) in 0 .. In_Cap)
             and then B (9) in 0 .. Fold9_Top_Cap
             and then (for all I in Limb_Index range 10 .. Max_Limbs - 1 =>
                         B (I) = 0),
     Post => In_Bounds (Fold_High_9_Out'Result, Add_Cap);

   function Fold_High_9_Plus_P (B : Big_Nat) return Big_Nat
   is ([0      => B (0) + 5 * B (5) + B (5) * (In_Cap - 4),
        1      => B (1) + 5 * B (6) + B (5) * In_Cap + B (6) * (In_Cap - 4),
        2      =>
          B (2) + 5 * B (7)
          + B (5) * In_Cap + B (6) * In_Cap + B (7) * (In_Cap - 4),
        3      =>
          B (3) + 5 * B (8)
          + B (5) * In_Cap + B (6) * In_Cap + B (7) * In_Cap
          + B (8) * (In_Cap - 4),
        4      =>
          B (4) + 5 * B (9)
          + B (5) * In_Cap + B (6) * In_Cap + B (7) * In_Cap + B (8) * In_Cap
          + B (9) * (In_Cap - 4),
        5      =>
          B (6) * In_Cap + B (7) * In_Cap + B (8) * In_Cap + B (9) * In_Cap,
        6      => B (7) * In_Cap + B (8) * In_Cap + B (9) * In_Cap,
        7      => B (8) * In_Cap + B (9) * In_Cap,
        8      => B (9) * In_Cap,
        others => 0])
   with
     Pre  => (for all I in Limb_Index range 0 .. 8 => B (I) in 0 .. In_Cap)
             and then B (9) in 0 .. Fold9_Top_Cap
             and then (for all I in Limb_Index range 10 .. Max_Limbs - 1 =>
                         B (I) = 0),
     Post => In_Bounds (Fold_High_9_Plus_P'Result, Add_Cap);

   function Fold_High_9_Chain (B : Big_Nat) return Carry_Array
   is ([0      => 0,
        1      => B (5),
        2      => B (5) + B (6),
        3      => B (5) + B (6) + B (7),
        4      => B (5) + B (6) + B (7) + B (8),
        5      => B (5) + B (6) + B (7) + B (8) + B (9),
        6      => B (6) + B (7) + B (8) + B (9),
        7      => B (7) + B (8) + B (9),
        8      => B (8) + B (9),
        9      => B (9),
        others => 0])
   with
     Pre  => (for all I in Limb_Index range 5 .. 8 => B (I) in 0 .. In_Cap)
             and then B (9) in 0 .. Fold9_Top_Cap,
     Post => Carry_Bounded (Fold_High_9_Chain'Result);

   procedure Lemma_Fold_High_9 (B : Big_Nat)
   with
     Pre  => (for all I in Limb_Index range 0 .. 8 => B (I) in 0 .. In_Cap)
             and then B (9) in 0 .. Fold9_Top_Cap
             and then (for all I in Limb_Index range 10 .. Max_Limbs - 1 =>
                         B (I) = 0),
     Post => Val_Eq (Fold_High_9_Plus_P (B), B, Fold_High_9_Chain (B));

   ------------------------------------------------------------------
   --  First reduction round of a convolution, composed end-to-end. S and C1
   --  are the swept value Sweep9_Out (Conv) and its chain (passed in so the
   --  contract can discharge Fold_High_9's input bounds without re-deriving
   --  the runtime conv-tight top-carry bound). The convolution is then
   --  value-equal (SVal_Eq) to Fold_High_9_Plus_P (S) -- i.e. congruent mod p
   --  to the folded five-limb form Fold_High_9_Out (S), since the difference
   --  is the prime multiples. Composes Sweep9 (exact) with Fold_High_9
   --  (mod p) via the SVal_Eq lift / symmetry / transitivity lemmas.
   ------------------------------------------------------------------

   procedure Lemma_Reduce_Conv_Round1 (Conv, S : Big_Nat; C1 : Carry_Array)
   with
     Pre  => In_Bounds (Conv, Conv_Col_Cap)
             and then (for all I in Limb_Index range 9 .. Max_Limbs - 1 =>
                         Conv (I) = 0)
             and then S = Sweep9_Out (Conv)
             and then C1 = Sweep9_Chain (Conv)
             and then S (9) in 0 .. Fold9_Top_Cap,
     Post =>
       SVal_Eq
         (Conv,
          Fold_High_9_Plus_P (S),
          Add_Carry (C1, Neg_Carry (Fold_High_9_Chain (S))));

end Tls_Core.Ghost_Bignum;
