pragma Ada_2022;
with Ada.Numerics.Big_Numbers.Big_Integers;

--  §0e value layer (codomain for the Mul bridge / convolution faithfulness).
--
--  Limb_Val maps a (signed) limb to its Big_Integer value by UNIT recursion
--  (base 0, step +/-1), so the §0e-opaque To_Big_Integer is never touched. The
--  whole algebra (additivity, multiplicativity, and downstream Val on Big_Nat)
--  is proved over this ingress. Big_Integer is the only scalar unbounded int
--  SPARK has, so it is the codomain -- but this unit is entirely Ghost, and
--  Tls_Core.Ghost_Bignum itself stays Big_Numbers-free, so Big_Integer never
--  reaches the runtime / bare-metal build domain (it ghost-eliminates; the
--  bare build excludes this child).
package Tls_Core.Ghost_Bignum.Value
  with SPARK_Mode, Ghost
is

   package BI renames Ada.Numerics.Big_Numbers.Big_Integers;
   use type BI.Big_Integer;

   --  Domain cap for the ingress. Comfortably above every value we feed in
   --  (Wide_Cap = 2**80 carries, Prod_Cap ~ 2**61 limbs, and the largest
   --  intermediate Limb_Base * carry ~ 2**106), and well below LLI'Last = 2**127
   --  so abs in the variant never overflows.
   Val_Cap : constant LLI := 2**110;
   subtype Val_Int is LLI range -Val_Cap .. Val_Cap;

   --  Non-opaque limb -> Big_Integer ingress: builds the value by unit
   --  recursion (base 0, step +/-1), NEVER via the opaque To_Big_Integer.
   function Limb_Val (X : Val_Int) return BI.Big_Integer
   is (if X = 0 then 0
       elsif X > 0 then Limb_Val (X - 1) + 1
       else Limb_Val (X + 1) - 1)
   with Subprogram_Variant => (Decreases => abs X);

   --  One-step shifts: unconditional (hold for all signs by a single unfold).
   --  These dissolve the crossing-zero case explosion in additivity.
   procedure Lemma_Limb_Val_Succ (X : Val_Int)
   with
     Pre  => X < Val_Cap,
     Post => Limb_Val (X + 1) = Limb_Val (X) + 1;

   procedure Lemma_Limb_Val_Pred (X : Val_Int)
   with
     Pre  => X > -Val_Cap,
     Post => Limb_Val (X - 1) = Limb_Val (X) - 1;

   --  PILLAR 1 -- additivity: Limb_Val (X + Y) = Limb_Val (X) + Limb_Val (Y).
   procedure Lemma_Limb_Val_Add (X, Y : Val_Int)
   with
     Pre                => X + Y in Val_Int,
     Post               => Limb_Val (X + Y) = Limb_Val (X) + Limb_Val (Y),
     Subprogram_Variant => (Decreases => abs Y);

   --  Negation: Limb_Val (-X) = -Limb_Val (X) (from additivity at X + (-X) = 0).
   procedure Lemma_Limb_Val_Neg (X : Val_Int)
   with Post => Limb_Val (-X) = -Limb_Val (X);

   --  Asymmetric multiplicand caps so the product (<= 2**109) is a decidable
   --  interval -- fits Val_Int AND a 128-bit machine int with no nonlinear
   --  overflow reasoning. Covers every use: limb*limb (each <= Mul_Cap = 2**27)
   --  and Limb_Base * carry (2**26 * Wide_Cap = 2**106). Order the factors so
   --  the larger one is Y.
   Mul_Cap_X : constant := 2**28;
   Mul_Cap_Y : constant := 2**81;
   subtype Mul_X_Int is LLI range -Mul_Cap_X .. Mul_Cap_X;
   subtype Mul_Y_Int is LLI range -Mul_Cap_Y .. Mul_Cap_Y;

   --  PILLAR 2 -- multiplicativity: Limb_Val (X * Y) = Limb_Val (X) * Limb_Val (Y).
   --  Follows from additivity by induction on Y. This is the master key: the
   --  Big_Nat convolution homomorphism Val (A*B) = Val (A) * Val (B) reduces to
   --  this together with additivity.
   procedure Lemma_Limb_Val_Mul (X : Mul_X_Int; Y : Mul_Y_Int)
   with
     Post               => Limb_Val (X * Y) = Limb_Val (X) * Limb_Val (Y),
     Subprogram_Variant => (Decreases => abs Y);

   ------------------------------------------------------------------
   --  Big_Nat value: Horner evaluation in base Base = Limb_Val (Limb_Base).
   --  Val (A) = sum_k Limb_Val (A (k)) * Base**k. Base is OUR ingress of the
   --  limb radix 2**26 -- never To_Big_Integer.
   ------------------------------------------------------------------

   Base : constant BI.Big_Integer := Limb_Val (Limb_Base);

   function Val_From (A : Big_Nat; I : Limb_Index) return BI.Big_Integer
   is (if I = Max_Limbs - 1 then Limb_Val (A (I))
       else Limb_Val (A (I)) + Base * Val_From (A, I + 1))
   with
     Pre                => In_Bounds (A, Val_Cap),
     Subprogram_Variant => (Decreases => Max_Limbs - 1 - I);

   function Val (A : Big_Nat) return BI.Big_Integer is (Val_From (A, 0))
   with Pre => In_Bounds (A, Val_Cap);

   --  Congruence: equal Big_Nats have equal Val (forces the substitution that
   --  eager unfolding of the recursive Val_From otherwise hides from the SMT).
   procedure Lemma_Val_From_Cong (X, Y : Big_Nat; I : Limb_Index)
   with
     Pre                =>
       In_Bounds (X, Val_Cap) and then In_Bounds (Y, Val_Cap) and then X = Y,
     Post               => Val_From (X, I) = Val_From (Y, I),
     Subprogram_Variant => (Decreases => Max_Limbs - 1 - I);

   procedure Lemma_Val_Cong (X, Y : Big_Nat)
   with
     Pre  => In_Bounds (X, Val_Cap) and then In_Bounds (Y, Val_Cap)
             and then X = Y,
     Post => Val (X) = Val (Y);

   ------------------------------------------------------------------
   --  Master lift: a wide signed value-equality (SVal_Wide) is a Val-equality.
   --  Telescopes the column relation; the pillars collapse each column. This
   --  lifts ALL the existing SVal_Wide / SVal_Eq congruence machinery into the
   --  value layer in one shot.
   ------------------------------------------------------------------

   --  Partial-Horner invariant: A and B differ by exactly the carry into I.
   procedure Lemma_Val_Tele (A, B : Big_Nat; C : Carry_Array; I : Limb_Index)
   with
     Pre                =>
       In_Bounds (A, Add_Cap) and then In_Bounds (B, Add_Cap)
       and then SC_Wide (C) and then SVal_Wide (A, B, C),
     Post               =>
       Val_From (A, I) + Limb_Val (C (I)) = Val_From (B, I),
     Subprogram_Variant => (Decreases => Max_Limbs - 1 - I);

   procedure Lemma_SVal_To_Val (A, B : Big_Nat; C : Carry_Array)
   with
     Pre  =>
       In_Bounds (A, Add_Cap) and then In_Bounds (B, Add_Cap)
       and then SC_Wide (C) and then SVal_Wide (A, B, C),
     Post => Val (A) = Val (B);

   ------------------------------------------------------------------
   --  Value homomorphisms feeding the convolution faithfulness theorem.
   ------------------------------------------------------------------

   --  A tail of zero limbs contributes nothing to the Horner value.
   procedure Lemma_Val_From_Zero_High (A : Big_Nat; N, I : Limb_Index)
   with
     Pre                =>
       In_Bounds (A, Val_Cap)
       and then (for all K in Limb_Index range N .. Max_Limbs - 1 => A (K) = 0)
       and then I >= N,
     Post               => Val_From (A, I) = 0,
     Subprogram_Variant => (Decreases => Max_Limbs - 1 - I);

   --  Scalar homomorphism: Val (Smul (S, A)) = Limb_Val (S) * Val (A).
   procedure Lemma_Val_From_Smul (S : LLI; A : Big_Nat; I : Limb_Index)
   with
     Pre                => S in 0 .. Smul_Cap and then In_Bounds (A, In_Cap),
     Post               =>
       Val_From (Smul (S, A), I) = Limb_Val (S) * Val_From (A, I),
     Subprogram_Variant => (Decreases => Max_Limbs - 1 - I);

   procedure Lemma_Val_Smul (S : LLI; A : Big_Nat)
   with
     Pre  => S in 0 .. Smul_Cap and then In_Bounds (A, In_Cap),
     Post => Val (Smul (S, A)) = Limb_Val (S) * Val (A);

   --  Additive homomorphism: Val (A + B) = Val (A) + Val (B).
   procedure Lemma_Val_From_Add (A, B : Big_Nat; I : Limb_Index)
   with
     Pre                => In_Bounds (A, Add_Cap) and then In_Bounds (B, Add_Cap),
     Post               =>
       Val_From (A + B, I) = Val_From (A, I) + Val_From (B, I),
     Subprogram_Variant => (Decreases => Max_Limbs - 1 - I);

   procedure Lemma_Val_Add (A, B : Big_Nat)
   with
     Pre  => In_Bounds (A, Add_Cap) and then In_Bounds (B, Add_Cap),
     Post => Val (A + B) = Val (A) + Val (B);

   ------------------------------------------------------------------
   --  Column-value: the Limb_Val of an impl convolution column is the sum of
   --  the limb-value products (additivity + multiplicativity, per term).
   ------------------------------------------------------------------

   function Col_Val (A, B : Big_Nat; K, T : Limb_Index) return BI.Big_Integer
   is (if T = 0 then Limb_Val (A (0)) * Limb_Val (B (K))
       else Col_Val (A, B, K, T - 1)
            + Limb_Val (A (T)) * Limb_Val (B (K - T)))
   with
     Pre                => In_Bounds (A, Mul_Cap) and then In_Bounds (B, Mul_Cap)
                           and then T <= K,
     Subprogram_Variant => (Decreases => T);

   procedure Lemma_Col_Val (A, B : Big_Nat; K, T : Limb_Index)
   with
     Pre                => In_Bounds (A, Mul_Cap) and then In_Bounds (B, Mul_Cap)
                           and then T <= K,
     Post               => Limb_Val (Mul_Col (A, B, K, T)) = Col_Val (A, B, K, T),
     Subprogram_Variant => (Decreases => T);

   ------------------------------------------------------------------
   --  Shift homomorphism: Val (X shifted up by N limbs) = Base**N * Val (X).
   ------------------------------------------------------------------

   --  Shift up by one limb: limb 0 -> 0, limb K -> X (K-1).
   function Shift1g (X : Big_Nat) return Big_Nat
   is ([for K in Limb_Index => (if K = 0 then 0 else X (K - 1))]);

   --  Suffix identity: the shifted array's Horner from I+1 equals X's from I
   --  (X's top limb, shifted out of range, must be zero).
   procedure Lemma_Shift1_Suffix (X : Big_Nat; I : Limb_Index)
   with
     Pre                =>
       In_Bounds (X, Val_Cap) and then X (Max_Limbs - 1) = 0
       and then I <= Max_Limbs - 2,
     Post               => Val_From (Shift1g (X), I + 1) = Val_From (X, I),
     Subprogram_Variant => (Decreases => Max_Limbs - 2 - I);

   procedure Lemma_Val_Shift1 (X : Big_Nat)
   with
     Pre  => In_Bounds (X, Val_Cap) and then X (Max_Limbs - 1) = 0,
     Post => Val (Shift1g (X)) = Base * Val (X);

   --  Base**N, defined recursively so the recurrence unfolds (no reliance on
   --  Big_Integers "**" axioms).
   function Base_Pow (N : Limb_Index) return BI.Big_Integer
   is (if N = 0 then 1 else Base * Base_Pow (N - 1))
   with Subprogram_Variant => (Decreases => N);

   --  Shift up by N limb positions: limb K -> (K >= N ? X (K-N) : 0).
   function Shift_By (B : Big_Nat; N : Limb_Index) return Big_Nat
   is ([for K in Limb_Index => (if K >= N then B (K - N) else 0)]);

   --  Shift homomorphism: Val (Shift_By (B, N)) = Base_Pow (N) * Val (B).
   --  Requires B's top N limbs zero (nothing is shifted out of range).
   procedure Lemma_Val_Shift_By (B : Big_Nat; N : Limb_Index)
   with
     Pre                =>
       In_Bounds (B, Val_Cap)
       and then (for all K in Limb_Index range Max_Limbs - N .. Max_Limbs - 1 =>
                   B (K) = 0),
     Post               => Val (Shift_By (B, N)) = Base_Pow (N) * Val (B),
     Subprogram_Variant => (Decreases => N);

   ------------------------------------------------------------------
   --  Single-limb multiply: A * Unit_Limb (v, m) = Smul (v, Shift_By (A, m)).
   --  Each convolution column collapses to a SINGLE term (Unit_Limb has one
   --  nonzero limb), which is the device that turns the 2D Cauchy product into
   --  a single row-induction.
   ------------------------------------------------------------------

   function Unit_Limb (V : LLI; M : Limb_Index) return Big_Nat
   is ([for K in Limb_Index => (if K = M then V else 0)]);

   --  The convolution column against a unit limb keeps only the i = K - M term.
   procedure Lemma_Mul_Unit_Col (A : Big_Nat; V : LLI; M, K, T : Limb_Index)
   with
     Pre                =>
       In_Bounds (A, Mul_Cap) and then V in 0 .. Mul_Cap and then T <= K,
     Post               =>
       Mul_Col (A, Unit_Limb (V, M), K, T)
       = (if M <= K and then K - M <= T then A (K - M) * V else 0),
     Subprogram_Variant => (Decreases => T);

   procedure Lemma_Mul_Unit (A : Big_Nat; V : LLI; M : Limb_Index)
   with
     Pre  => In_Bounds (A, In_Cap) and then V in 0 .. Mul_Cap,
     Post => A * Unit_Limb (V, M) = Smul (V, Shift_By (A, M));

   ------------------------------------------------------------------
   --  Convolution faithfulness Val (A * B) = Val (A) * Val (B), by peeling B
   --  one limb at a time (single induction; each step a single-limb multiply).
   ------------------------------------------------------------------

   subtype Lo_Count is Natural range 0 .. Max_Limbs;

   --  Low part of B: limbs 0 .. M-1 kept, the rest zeroed.
   function B_Lo (B : Big_Nat; M : Lo_Count) return Big_Nat
   is ([for K in Limb_Index => (if K < M then B (K) else 0)]);

   --  Congruence of "*" in the second operand (column level, then full).
   procedure Lemma_Mul_Col_Cong (A, X, Y : Big_Nat; K, T : Limb_Index)
   with
     Pre                =>
       In_Bounds (A, Mul_Cap) and then In_Bounds (X, Mul_Cap)
       and then In_Bounds (Y, Mul_Cap) and then X = Y and then T <= K,
     Post               => Mul_Col (A, X, K, T) = Mul_Col (A, Y, K, T),
     Subprogram_Variant => (Decreases => T);

   procedure Lemma_Mul_Cong_R (A, X, Y : Big_Nat)
   with
     Pre  => In_Bounds (A, Mul_Cap) and then In_Bounds (X, Mul_Cap)
             and then In_Bounds (Y, Mul_Cap) and then X = Y,
     Post => A * X = A * Y;

   procedure Lemma_Mul_Zero_Col (A : Big_Nat; K, T : Limb_Index)
   with
     Pre                => In_Bounds (A, Mul_Cap) and then T <= K,
     Post               => Mul_Col (A, Zero, K, T) = 0,
     Subprogram_Variant => (Decreases => T);

   procedure Lemma_Mul_Zero_R (A : Big_Nat)
   with Pre => In_Bounds (A, Mul_Cap), Post => A * Zero = Zero;

   --  Val (Unit_Limb (v, m)) = Limb_Val (v) * Base_Pow (m).
   procedure Lemma_Val_Unit (V : LLI; M : Limb_Index)
   with
     Pre  => V in 0 .. In_Cap,
     Post => Val (Unit_Limb (V, M)) = Limb_Val (V) * Base_Pow (M);

   --  One-limb extension of the low part.
   procedure Lemma_Val_Lo_Step (B : Big_Nat; M : Limb_Index)
   with
     Pre  => In_Bounds (B, In_Cap),
     Post => Val (B_Lo (B, M + 1))
             = Val (B_Lo (B, M)) + Limb_Val (B (M)) * Base_Pow (M);

   procedure Lemma_Val_Mul_Acc (A, B : Big_Nat; Na, Nb, M : Lo_Count)
   with
     Pre                =>
       In_Bounds (A, In_Cap) and then In_Bounds (B, In_Cap)
       and then (for all K in Limb_Index range Na .. Max_Limbs - 1 => A (K) = 0)
       and then (for all K in Limb_Index range Nb .. Max_Limbs - 1 => B (K) = 0)
       and then Na + Nb <= Max_Limbs and then M <= Nb,
     Post               =>
       Val (A * B_Lo (B, M)) = Val (A) * Val (B_Lo (B, M)),
     Subprogram_Variant => (Decreases => M);

   procedure Lemma_Val_Mul (A, B : Big_Nat; Na, Nb : Lo_Count)
   with
     Pre  =>
       In_Bounds (A, In_Cap) and then In_Bounds (B, In_Cap)
       and then (for all K in Limb_Index range Na .. Max_Limbs - 1 => A (K) = 0)
       and then (for all K in Limb_Index range Nb .. Max_Limbs - 1 => B (K) = 0)
       and then Na + Nb <= Max_Limbs,
     Post => Val (A * B) = Val (A) * Val (B);

   --  The value of the prime p = 2**130 - 5 in our base: Base_Pow (5) = 2**130.
   --  The five-limb P_Prime telescopes to Base**5 - 5.
   procedure Lemma_Val_P_Prime
   with Post => Val (P_Prime) = Base_Pow (5) - 5;

   --  P_Prime * R has value p * Val (R): convolution faithfulness applied to
   --  the prime. The value of the product is a multiple of the prime p, the
   --  fact the field-multiply fold (2**130 == 5 mod p) ultimately discharges.
   procedure Lemma_Val_P_Mul (R : Big_Nat)
   with
     Pre  => In_Bounds (R, In_Cap)
             and then (for all K in Limb_Index range 5 .. Max_Limbs - 1 =>
                         R (K) = 0),
     Post => Val (P_Prime * R) = (Base_Pow (5) - 5) * Val (R);

   ------------------------------------------------------------------
   --  Reduction-step lifts (toward the Field_Mul bridge, Route A): turn the
   --  exact carry-chain value equalities the reduce steps already prove into
   --  Val equalities. Composed with Lemma_Val_To_SVal / Lemma_SVal_To_Wide.
   ------------------------------------------------------------------

   --  A non-negative carry-chain value equality is a Val equality.
   procedure Lemma_ValEq_To_Val (A, B : Big_Nat; C : Carry_Array)
   with
     Pre  => In_Bounds (A, Add_Cap) and then In_Bounds (B, Add_Cap)
             and then Carry_Bounded (C) and then Val_Eq (A, B, C),
     Post => Val (A) = Val (B);

   ------------------------------------------------------------------
   --  Value bounds on reduced Big_Nats (toward "reduced & not Sub_Cond =>
   --  0 <= Val < p", the magnitude half of mod-p uniqueness in the value layer).
   ------------------------------------------------------------------

   --  Limb_Val is non-negative and monotone on the non-negative domain.
   procedure Lemma_Limb_Val_Nonneg (X : Val_Int)
   with
     Pre                => X >= 0,
     Post               => Limb_Val (X) >= 0,
     Subprogram_Variant => (Decreases => X);

   procedure Lemma_Limb_Val_Mono (X, Y : Val_Int)
   with
     Pre                => 0 <= X and then X <= Y,
     Post               => Limb_Val (X) <= Limb_Val (Y),
     Subprogram_Variant => (Decreases => Y - X);

   --  Reduced (limbs <= In_Cap, zero from 5) Big_Nat: each Horner suffix is
   --  in [0, Base_Pow (5-K) - 1]. At K=0 this bounds Val (X) by Base_Pow (5)-1.
   procedure Lemma_Val_From_Reduced_Ub (X : Big_Nat; K : Lo_Count)
   with
     Pre                =>
       In_Bounds (X, In_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => X (I) = 0)
       and then K <= 5,
     Post               =>
       Val_From (X, K) >= 0
       and then Val_From (X, K) <= Base_Pow (5 - K) - 1,
     Subprogram_Variant => (Decreases => 5 - K);

end Tls_Core.Ghost_Bignum.Value;
