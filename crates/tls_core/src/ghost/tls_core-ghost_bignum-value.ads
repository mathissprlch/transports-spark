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
   is (if X = 0
       then 0
       elsif X > 0
       then Limb_Val (X - 1) + 1
       else Limb_Val (X + 1) - 1)
   with Subprogram_Variant => (Decreases => abs X);

   --  One-step shifts: unconditional (hold for all signs by a single unfold).
   --  These dissolve the crossing-zero case explosion in additivity.
   procedure Lemma_Limb_Val_Succ (X : Val_Int)
   with Pre => X < Val_Cap, Post => Limb_Val (X + 1) = Limb_Val (X) + 1;

   procedure Lemma_Limb_Val_Pred (X : Val_Int)
   with Pre => X > -Val_Cap, Post => Limb_Val (X - 1) = Limb_Val (X) - 1;

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
   is (if I = Max_Limbs - 1
       then Limb_Val (A (I))
       else Limb_Val (A (I)) + Base * Val_From (A, I + 1))
   with
     Pre                => In_Bounds (A, Val_Cap),
     Subprogram_Variant => (Decreases => Max_Limbs - 1 - I);

   function Val (A : Big_Nat) return BI.Big_Integer
   is (Val_From (A, 0))
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
     Pre  =>
       In_Bounds (X, Val_Cap) and then In_Bounds (Y, Val_Cap) and then X = Y,
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
       In_Bounds (A, Add_Cap)
       and then In_Bounds (B, Add_Cap)
       and then SC_Wide (C)
       and then SVal_Wide (A, B, C),
     Post               =>
       Val_From (A, I) + Limb_Val (C (I)) = Val_From (B, I),
     Subprogram_Variant => (Decreases => Max_Limbs - 1 - I);

   procedure Lemma_SVal_To_Val (A, B : Big_Nat; C : Carry_Array)
   with
     Pre  =>
       In_Bounds (A, Add_Cap)
       and then In_Bounds (B, Add_Cap)
       and then SC_Wide (C)
       and then SVal_Wide (A, B, C),
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
     Pre                =>
       In_Bounds (A, Add_Cap) and then In_Bounds (B, Add_Cap),
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
   is (if T = 0
       then Limb_Val (A (0)) * Limb_Val (B (K))
       else Col_Val (A, B, K, T - 1) + Limb_Val (A (T)) * Limb_Val (B (K - T)))
   with
     Pre                =>
       In_Bounds (A, Mul_Cap) and then In_Bounds (B, Mul_Cap) and then T <= K,
     Subprogram_Variant => (Decreases => T);

   procedure Lemma_Col_Val (A, B : Big_Nat; K, T : Limb_Index)
   with
     Pre                =>
       In_Bounds (A, Mul_Cap) and then In_Bounds (B, Mul_Cap) and then T <= K,
     Post               =>
       Limb_Val (Mul_Col (A, B, K, T)) = Col_Val (A, B, K, T),
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
       In_Bounds (X, Val_Cap)
       and then X (Max_Limbs - 1) = 0
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
       and then (for all K in
                   Limb_Index range Max_Limbs - N .. Max_Limbs - 1 =>
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
       In_Bounds (A, Mul_Cap)
       and then In_Bounds (X, Mul_Cap)
       and then In_Bounds (Y, Mul_Cap)
       and then X = Y
       and then T <= K,
     Post               => Mul_Col (A, X, K, T) = Mul_Col (A, Y, K, T),
     Subprogram_Variant => (Decreases => T);

   procedure Lemma_Mul_Cong_R (A, X, Y : Big_Nat)
   with
     Pre  =>
       In_Bounds (A, Mul_Cap)
       and then In_Bounds (X, Mul_Cap)
       and then In_Bounds (Y, Mul_Cap)
       and then X = Y,
     Post => A * X = A * Y;

   --  Congruence of "*" in the FIRST operand (column level, then full).
   procedure Lemma_Mul_Col_Cong_L (A, A2, B : Big_Nat; K, T : Limb_Index)
   with
     Pre                =>
       In_Bounds (A, Mul_Cap)
       and then In_Bounds (A2, Mul_Cap)
       and then In_Bounds (B, Mul_Cap)
       and then A = A2
       and then T <= K,
     Post               => Mul_Col (A, B, K, T) = Mul_Col (A2, B, K, T),
     Subprogram_Variant => (Decreases => T);

   --  Full congruence of "*" in both operands.
   procedure Lemma_Mul_Cong_LR (A, A2, B, B2 : Big_Nat)
   with
     Pre  =>
       In_Bounds (A, Mul_Cap)
       and then In_Bounds (A2, Mul_Cap)
       and then In_Bounds (B, Mul_Cap)
       and then In_Bounds (B2, Mul_Cap)
       and then A = A2
       and then B = B2,
     Post => A * B = A2 * B2;

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
     Post =>
       Val (B_Lo (B, M + 1))
       = Val (B_Lo (B, M)) + Limb_Val (B (M)) * Base_Pow (M);

   procedure Lemma_Val_Mul_Acc (A, B : Big_Nat; Na, Nb, M : Lo_Count)
   with
     Pre                =>
       In_Bounds (A, In_Cap)
       and then In_Bounds (B, In_Cap)
       and then (for all K in Limb_Index range Na .. Max_Limbs - 1 =>
                   A (K) = 0)
       and then (for all K in Limb_Index range Nb .. Max_Limbs - 1 =>
                   B (K) = 0)
       and then Na + Nb <= Max_Limbs
       and then M <= Nb,
     Post               => Val (A * B_Lo (B, M)) = Val (A) * Val (B_Lo (B, M)),
     Subprogram_Variant => (Decreases => M);

   procedure Lemma_Val_Mul (A, B : Big_Nat; Na, Nb : Lo_Count)
   with
     Pre  =>
       In_Bounds (A, In_Cap)
       and then In_Bounds (B, In_Cap)
       and then (for all K in Limb_Index range Na .. Max_Limbs - 1 =>
                   A (K) = 0)
       and then (for all K in Limb_Index range Nb .. Max_Limbs - 1 =>
                   B (K) = 0)
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
     Pre  =>
       In_Bounds (R, In_Cap)
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
     Pre  =>
       In_Bounds (A, Add_Cap)
       and then In_Bounds (B, Add_Cap)
       and then Carry_Bounded (C)
       and then Val_Eq (A, B, C),
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
       Val_From (X, K) >= 0 and then Val_From (X, K) <= Base_Pow (5 - K) - 1,
     Subprogram_Variant => (Decreases => 5 - K);

   --  Value bound certificate (Val-domain): a value below Base_Pow (5) sweeps
   --  with no carry out of limb 4. Lemma_Sweep5 makes the swept low limbs
   --  (0 .. 4, value < Base_Pow (5)) plus the carry limb 5 encode Val (X); if
   --  Val (X) < Base_Pow (5) the carry term must vanish. The Val-domain analogue
   --  of Lemma_Reduced_No_Carry for non-reduced inputs -- the gating fact the
   --  Mac freeze needs after Carry; Carry (value < 2**130).
   procedure Lemma_Val_Lt_No_Carry (X : Big_Nat)
   with
     Pre  =>
       In_Bounds (X, Prod_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => X (I) = 0)
       and then Val (X) < Base_Pow (5),
     Post => Sweep5_Out (X) (5) = 0;

   --  Magnitude after one carry-fold: a value whose sweep carries out at most
   --  once is below 2 * Base_Pow (5) (= low5 + carry * Base_Pow (5), low5 <
   --  Base_Pow (5), carry <= 1). Bounds the accumulator between the Mac's two
   --  Carry folds so the second fold lands it below Base_Pow (5).
   procedure Lemma_Val_Carry_Bound (X : Big_Nat)
   with
     Pre  =>
       In_Bounds (X, Prod_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => X (I) = 0)
       and then Sweep5_Out (X) (5) <= 1,
     Post => Val (X) < 2 * Base_Pow (5);

   --  Same bound for a twice-carried sweep (carry <= 2, the impl accumulator's
   --  bound via Lemma_Sweep5_Acc_Carry): Val (X) < 3 * Base_Pow (5).
   procedure Lemma_Val_Carry_Bound_2 (X : Big_Nat)
   with
     Pre  =>
       In_Bounds (X, Prod_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => X (I) = 0)
       and then Sweep5_Out (X) (5) <= 2,
     Post => Val (X) < 3 * Base_Pow (5);

   --  Tight Carry_Model magnitude: one carry-fold lands the value at most 5 per
   --  swept-out unit above Base_Pow (5). Val (Carry_Model (B)) = swept-low5
   --  (< Base_Pow (5)) + 5 * K0, so <= Base_Pow (5) - 1 + 5 * K0. This is the
   --  bound that makes the Mac's two Carry folds reach < Base_Pow (5) (the loose
   --  Val < 2 * Base_Pow (5) is not enough -- the Sub_Cond fixed-point window).
   procedure Lemma_Carry_Model_Val_Tight (B : Big_Nat)
   with
     Pre  =>
       In_Bounds (B, Mul_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => B (I) = 0)
       and then Sweep5_Out (B) (5) <= 2,
     Post =>
       Val (Carry_Model (B))
       <= Base_Pow (5) - 1 + 5 * Limb_Val (Sweep5_Out (B) (5));

   --  Second of the Mac's two Carry folds: a value already within Base_Pow (5)
   --  + 9 (Val, the post-first-Carry state) with sweep-carry <= 2 lands
   --  strictly below Base_Pow (5) after another fold, so its sweep has no carry
   --  out. (K0 = 2 is infeasible -- it would force Val (X) >= 2*Base_Pow(5)-10.)
   procedure Lemma_Single_Carry_To_Zero (X : Big_Nat)
   with
     Pre  =>
       In_Bounds (X, Mul_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => X (I) = 0)
       and then Sweep5_Out (X) (5) <= 2
       and then Val (X) <= Base_Pow (5) + 9,
     Post => Sweep5_Out (Carry_Model (X)) (5) = 0;

   --  The value-level core of Lemma_Single_Carry_To_Zero: the second Carry fold
   --  of a value within Base_Pow (5) + 9 lands strictly below Base_Pow (5).
   --  Stated on Val (not Sweep5_Out) so it transfers across the Carry routine's
   --  value-equality postcondition -- the Mac needs the bound on the *real*
   --  accumulator limbs, then recovers Sweep5_Out (5) = 0 via Lemma_Val_Lt_No_Carry.
   procedure Lemma_Carry_Model_Val_Lt (X : Big_Nat)
   with
     Pre  =>
       In_Bounds (X, Mul_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => X (I) = 0)
       and then Sweep5_Out (X) (5) <= 2
       and then Val (X) <= Base_Pow (5) + 9,
     Post => Val (Carry_Model (X)) < Base_Pow (5);

   --  Big_Integer multiply-monotonicity (isolated so the SMT solver sees the
   --  nonlinear fact in a tiny context).
   procedure Lemma_BI_Mul_Mono (C, A, B : BI.Big_Integer)
   with Pre => C >= 0 and then A <= B, Post => C * A <= C * B;

   --  Converse of the upper bound: a Horner suffix at its maximum forces every
   --  limb in the suffix to be In_Cap (uniqueness of the max representation).
   procedure Lemma_Val_From_Max_Forces (X : Big_Nat; K : Lo_Count)
   with
     Pre                =>
       In_Bounds (X, In_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => X (I) = 0)
       and then K <= 5
       and then Val_From (X, K) = Base_Pow (5 - K) - 1,
     Post               =>
       (for all J in Limb_Index range K .. 4 => X (J) = In_Cap),
     Subprogram_Variant => (Decreases => 5 - K);

   --  Base is at least 6 (= Limb_Val (2**26)); used in the < p margin.
   procedure Lemma_Base_Ge_6
   with Post => Base >= 6;

   --  Magnitude half of mod-p uniqueness: a canonical Big_Nat (reduced AND
   --  not Sub_Cond, i.e. < p) has 0 <= Val (X) < p = Base_Pow (5) - 5.
   procedure Lemma_Val_Lt_P (X : Big_Nat)
   with
     Pre  =>
       In_Bounds (X, In_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => X (I) = 0)
       and then not Sub_Cond (X),
     Post => Val (X) >= 0 and then Val (X) < Base_Pow (5) - 5;

   ------------------------------------------------------------------
   --  Val-injectivity on reduced Big_Nats (uniqueness of the base-Base
   --  representation). The other half of mod-p uniqueness in the value layer.
   ------------------------------------------------------------------

   --  Limb_Val is injective on the non-negative domain.
   procedure Lemma_Limb_Val_Inj (X, Y : Val_Int)
   with
     Pre  => X >= 0 and then Y >= 0 and then Limb_Val (X) = Limb_Val (Y),
     Post => X = Y;

   procedure Lemma_Val_From_Inj (X, Y : Big_Nat; K : Lo_Count)
   with
     Pre                =>
       In_Bounds (X, In_Cap)
       and then In_Bounds (Y, In_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => X (I) = 0)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => Y (I) = 0)
       and then K <= 5
       and then Val_From (X, K) = Val_From (Y, K),
     Post               =>
       (for all J in Limb_Index range K .. 4 => X (J) = Y (J)),
     Subprogram_Variant => (Decreases => 5 - K);

   procedure Lemma_Val_Inj_Reduced (X, Y : Big_Nat)
   with
     Pre  =>
       In_Bounds (X, In_Cap)
       and then In_Bounds (Y, In_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => X (I) = 0)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => Y (I) = 0)
       and then Val (X) = Val (Y),
     Post => X = Y;

   ------------------------------------------------------------------
   --  Mod-p uniqueness capstone: canonical residues are unique. This is what
   --  the Field_Mul bridge consumes -- it turns the value-level congruences the
   --  reduction lifts produce into limb equalities.
   ------------------------------------------------------------------

   --  Base_Pow (N) >= 1 (so p = Base_Pow (5) - 5 > 0).
   procedure Lemma_Base_Pow_Ge_1 (N : Limb_Index)
   with Post => Base_Pow (N) >= 1, Subprogram_Variant => (Decreases => N);

   --  Two canonical Big_Nats whose values differ by a multiple of p (the
   --  concrete "+ Ka*p / + Kb*p" form the reduction folds produce) are equal.
   procedure Lemma_Val_Canonical_Eq (X, Y : Big_Nat; Ka, Kb : BI.Big_Integer)
   with
     Pre  =>
       In_Bounds (X, In_Cap)
       and then In_Bounds (Y, In_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => X (I) = 0)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => Y (I) = 0)
       and then not Sub_Cond (X)
       and then not Sub_Cond (Y)
       and then Ka >= 0
       and then Kb >= 0
       and then Val (X) + Ka * (Base_Pow (5) - 5)
                = Val (Y) + Kb * (Base_Pow (5) - 5),
     Post => X = Y;

   --  Value of a per-limb combine B(I) = GWc(I) + Kc*GPr(I):
   --  Val (B) = Val (GWc) + Limb_Val (Kc) * Val (GPr). (The Lemma_Mul_Cong_Prime
   --  combined operand, lifted to the value layer.)
   procedure Lemma_Val_B_From (GWc, GPr, B : Big_Nat; Kc : LLI; I : Limb_Index)
   with
     Pre                =>
       In_Bounds (GWc, Conv_Col_Cap)
       and then In_Bounds (GPr, Conv_Col_Cap)
       and then In_Bounds (B, Add_Cap)
       and then Kc in 0 .. 5
       and then (for all J in Limb_Index => B (J) = GWc (J) + Kc * GPr (J)),
     Post               =>
       Val_From (B, I) = Val_From (GWc, I) + Limb_Val (Kc) * Val_From (GPr, I),
     Subprogram_Variant => (Decreases => Max_Limbs - 1 - I);

   procedure Lemma_Val_B_Combine (GWc, GPr, B : Big_Nat; Kc : LLI)
   with
     Pre  =>
       In_Bounds (GWc, Conv_Col_Cap)
       and then In_Bounds (GPr, Conv_Col_Cap)
       and then In_Bounds (B, Add_Cap)
       and then Kc in 0 .. 5
       and then (for all J in Limb_Index => B (J) = GWc (J) + Kc * GPr (J)),
     Post => Val (B) = Val (GWc) + Limb_Val (Kc) * Val (GPr);

   --  Val of a non-negatively-bounded Big_Nat is non-negative.
   procedure Lemma_Val_From_Nonneg (X : Big_Nat; I : Limb_Index)
   with
     Pre                => In_Bounds (X, Val_Cap),
     Post               => Val_From (X, I) >= 0,
     Subprogram_Variant => (Decreases => Max_Limbs - 1 - I);

   --  Field_Mul preserves value mod p: Val (Field_Mul (A, R)) + Kg*p = Val (A*R),
   --  Kg >= 0. The reduction chain (Sweep9 exact, Fold_High_9 / Carry_Model /
   --  Canonical each subtract a p-multiple) carried to the value layer, for an
   --  accumulator-sized A (limbs < Mul_Cap) and reduced R.
   procedure Lemma_Field_Mul_Reduce_Cong
     (A, R : Big_Nat; Kg : out BI.Big_Integer)
   with
     Pre  =>
       In_Bounds (A, Mul_Cap)
       and then In_Bounds (R, In_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => A (I) = 0)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                   R (I) = 0),
     Post =>
       Kg >= 0
       and then Val (Field_Mul (A, R)) + Kg * (Base_Pow (5) - 5) = Val (A * R);

   --  The §0e Mul-bridge keystone: the field product of the prime by any reduced
   --  R is Zero (P_Prime == 0 mod p). Discharges the Kc*(P_Prime*R) residual the
   --  SVal multiply-congruence leaves; mirrors Lemma_Canonical_P_Prime for mul.
   procedure Lemma_Field_Mul_P_Zero (R : Big_Nat)
   with
     Pre  =>
       In_Bounds (R, In_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                   R (I) = 0),
     Post => Field_Mul (P_Prime, R) = Zero;

   --  Column bound for a reduced-by-reduced product: A, B In_Cap and zero from
   --  5 give A*B columns under Conv_Col_Cap (each of <=5 terms is < Two_Pow_54).
   --  Isolated so the nonlinear column bound proves in a small context.
   procedure Lemma_Mul_Conv_Bound (A, B, AB : Big_Nat)
   with
     Pre  =>
       In_Bounds (A, In_Cap)
       and then In_Bounds (B, In_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => A (I) = 0)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => B (I) = 0)
       and then AB = A * B,
     Post =>
       In_Bounds (AB, Conv_Col_Cap)
       and then (for all K in Limb_Index range 9 .. Max_Limbs - 1 =>
                   AB (K) = 0);

   --  The #166 Mul bridge: the field product is invariant under canonicalising
   --  its accumulator-sized left operand -- Field_Mul (Acc, R) reduces the same
   --  residue as Field_Mul (Canonical (Acc), R). Proof: the congruence
   --  Acc == Canonical (Acc) + Kc*P_Prime (Lemma_Canonical_Cong) is lifted
   --  through the convolution (Lemma_Mul_Cong_Prime) and the value layer
   --  (Lemma_Val_B_Combine + Lemma_Val_P_Mul) so the two products differ by a
   --  multiple of p; two reductions (Lemma_Field_Mul_Reduce_Cong) plus
   --  field-element uniqueness (Lemma_Val_Canonical_Eq) collapse them.
   --  This is the per-op bridge the Poly1305 Mac accumulator needs (its limbs
   --  are Mul_Cap-bounded by the impl Carry Post, not yet canonical).
   procedure Lemma_Field_Mul_Bridge (Acc, R : Big_Nat)
   with
     Pre  =>
       In_Bounds (Acc, Mul_Cap)
       and then In_Bounds (R, In_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                   Acc (I) = 0)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                   R (I) = 0),
     Post => Field_Mul (Acc, R) = Field_Mul (Canonical (Acc), R);

   --  Corollary: a canonical Big_Nat whose value is a multiple of p is Zero.
   procedure Lemma_Val_Canonical_Zero (X : Big_Nat; Ka : BI.Big_Integer)
   with
     Pre  =>
       In_Bounds (X, In_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 => X (I) = 0)
       and then not Sub_Cond (X)
       and then Ka >= 0
       and then Val (X) = Ka * (Base_Pow (5) - 5),
     Post => X = Zero;

   ------------------------------------------------------------------
   --  Canonical preserves value mod p (the reduction-chain lift). Field_Mul,
   --  Field_Add, and the impl-op outputs all end in Canonical (...); this turns
   --  their value congruences into the "+ Kf*p" form Lemma_Val_Canonical_Eq
   --  consumes. Built by lifting the SVal_Eq witnesses that Normalize and
   --  Lemma_Reduce_Canonical already expose.
   ------------------------------------------------------------------

   --  Signed-chain value equality is a Val equality (the SVal_Eq analogue of
   --  Lemma_ValEq_To_Val).
   procedure Lemma_SValEq_To_Val (A, B : Big_Nat; C : Carry_Array)
   with
     Pre  =>
       In_Bounds (A, Add_Cap)
       and then In_Bounds (B, Add_Cap)
       and then SC_Bounded (C)
       and then SVal_Eq (A, B, C),
     Post => Val (A) = Val (B);

   --  Val (B) = Val (Canonical (B)) + Kf * p, Kf >= 0.
   procedure Lemma_Canonical_Val_Cong (B : Big_Nat; Kf : out BI.Big_Integer)
   with
     Pre  =>
       In_Bounds (B, Mul_Cap)
       and then (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                   B (I) = 0),
     Post =>
       Kf >= 0
       and then Val (B) = Val (Canonical (B)) + Kf * (Base_Pow (5) - 5);

   --  The Sweep9 carry sweep is value-exact (lift of Lemma_Sweep9). First
   --  reduction step of Field_Mul (Conv = A*R) in the value layer.
   procedure Lemma_Val_Sweep9 (Conv : Big_Nat)
   with
     Pre  =>
       In_Bounds (Conv, Conv_Col_Cap)
       and then (for all I in Limb_Index range 9 .. Max_Limbs - 1 =>
                   Conv (I) = 0),
     Post => Val (Conv) = Val (Sweep9_Out (Conv));

   --  The 9-fold "plus prime" form splits into the folded output plus the
   --  prime-multiple part (limbwise Big_Nat identity).
   procedure Lemma_FH9_Split (B : Big_Nat)
   with
     Pre  =>
       (for all I in Limb_Index range 0 .. 8 => B (I) in 0 .. In_Cap)
       and then B (9) in 0 .. Fold9_Top_Cap
       and then (for all I in Limb_Index range 10 .. Max_Limbs - 1 =>
                   B (I) = 0),
     Post =>
       Fold_High_9_Plus_P (B)
       = Fold_High_9_Out (B) + Fold_High_9_PrimePart (B);

   --  The 9-fold step (the 2**130==5 prime fold) is value-preserving mod p:
   --  Val (Fold_High_9_Out (S)) + p * Val (High5 (S)) = Val (S).
   procedure Lemma_Val_FH9_Out (S : Big_Nat)
   with
     Pre  =>
       (for all I in Limb_Index range 0 .. 8 => S (I) in 0 .. In_Cap)
       and then S (9) in 0 .. Fold9_Top_Cap
       and then (for all I in Limb_Index range 10 .. Max_Limbs - 1 =>
                   S (I) = 0),
     Post =>
       Val (Fold_High_9_Out (S)) + (Base_Pow (5) - 5) * Val (High5 (S))
       = Val (S);

   ------------------------------------------------------------------
   --  Fold_High_9 prime-multiple part is a multiple of p. Fold_High_9_PrimePart
   --  (B) is the convolution P_Prime * High5 (B); B (9) can exceed Mul_Cap so
   --  Val_Mul does not apply, but the Smul row decomposition does (each scalar
   --  B (5+j) <= Fold9_Top_Cap <= Smul_Cap), giving Val = p * Val (High5 (B)).
   ------------------------------------------------------------------

   --  The five high limbs B (5 .. 9) as a five-limb value.
   function High5 (B : Big_Nat) return Big_Nat
   is ([0      => B (5),
        1      => B (6),
        2      => B (7),
        3      => B (8),
        4      => B (9),
        others => 0]);

   --  Big_Integer ring reassociations (isolated so the SMT solver applies the
   --  nonlinear comm/assoc in a tiny context).
   procedure Lemma_BI_Reassoc (X, Y, Z : BI.Big_Integer)
   with Post => X * (Y * Z) = Y * (X * Z);

   procedure Lemma_BI_Assoc (X, Y, Z : BI.Big_Integer)
   with Post => X * (Y * Z) = (X * Y) * Z;

   --  Factor a common multiplier out of a five-term sum.
   procedure Lemma_BI_Factor5 (A, B, C, D, E, P : BI.Big_Integer)
   with
     Post => A * P + B * P + C * P + D * P + E * P = P * (A + B + C + D + E);

   --  Right-operand congruence: X = Y => P*X = P*Y.
   procedure Lemma_BI_MulR_Cong (P, X, Y : BI.Big_Integer)
   with Pre => X = Y, Post => P * X = P * Y;

   --  Field-value factoring: P*VR - P*VH - LK*P - Kf*P = (VR-VH-LK-Kf)*P.
   procedure Lemma_BI_FieldKa (VR, VH, LK, Kf, P : BI.Big_Integer)
   with Post => P * VR - P * VH - LK * P - Kf * P = (VR - VH - LK - Kf) * P;

   --  Three-term factoring: P*VH + LK*P + Kf*P = (VH+LK+Kf)*P.
   procedure Lemma_BI_Factor3 (VH, LK, Kf, P : BI.Big_Integer)
   with Post => P * VH + LK * P + Kf * P = (VH + LK + Kf) * P;

   --  Two-term factoring: P*VR - Kg*P = (VR-Kg)*P.
   procedure Lemma_BI_Factor2 (VR, Kg, P : BI.Big_Integer)
   with Post => P * VR - Kg * P = (VR - Kg) * P;

   --  Fold the carry multiple into one p-coefficient:
   --  Kg2*P + Kc_v*(P*Vr) = (Kg2 + Kc_v*Vr)*P.
   procedure Lemma_BI_FactorMul (Kc_v, Vr, Kg2, P : BI.Big_Integer)
   with Post => Kg2 * P + Kc_v * (P * Vr) = (Kg2 + Kc_v * Vr) * P;

   --  Nested Horner (base Base) to Base_Pow-weighted flat, five terms (isolated
   --  abstract-value context so the SMT solver does the degree-4 ring identity).
   procedure Lemma_Nested5_To_Flat (A0, A1, A2, A3, A4 : BI.Big_Integer)
   with
     Post =>
       A0 + Base * (A1 + Base * (A2 + Base * (A3 + Base * A4)))
       = A0
         * Base_Pow (0)
         + A1 * Base_Pow (1)
         + A2 * Base_Pow (2)
         + A3 * Base_Pow (3)
         + A4 * Base_Pow (4);

   --  Val (High5 (B)) in explicit Base_Pow-weighted form (isolated so the SMT
   --  solver sees the nested-Base -> Base_Pow flatten in a small context).
   procedure Lemma_Val_High5_Flat (B : Big_Nat)
   with
     Pre  =>
       (for all I in Limb_Index range 5 .. 8 => B (I) in 0 .. In_Cap)
       and then B (9) in 0 .. Fold9_Top_Cap,
     Post =>
       Val (High5 (B))
       = Limb_Val (B (5))
         * Base_Pow (0)
         + Limb_Val (B (6)) * Base_Pow (1)
         + Limb_Val (B (7)) * Base_Pow (2)
         + Limb_Val (B (8)) * Base_Pow (3)
         + Limb_Val (B (9)) * Base_Pow (4);

   --  One PrimePart term, fully evaluated (isolated so its nonlinear chain is a
   --  small VC): Val (Smul (S, Shift_By (P_Prime, J))) = Limb_Val (S)*Base_Pow(J)*p.
   procedure Lemma_Val_PrimeTerm (S : LLI; J : Limb_Index)
   with
     Pre  => S in 0 .. Fold9_Top_Cap and then J <= 4,
     Post =>
       Val (Smul (S, Shift_By (P_Prime, J)))
       = Limb_Val (S) * Base_Pow (J) * (Base_Pow (5) - 5);

   --  PrimePart as the sum of single-limb scalings of shifted P_Prime.
   procedure Lemma_PrimePart_Decomp (B : Big_Nat)
   with
     Pre  =>
       (for all I in Limb_Index range 5 .. 8 => B (I) in 0 .. In_Cap)
       and then B (9) in 0 .. Fold9_Top_Cap,
     Post =>
       Fold_High_9_PrimePart (B)
       = Smul (B (5), Shift_By (P_Prime, 0))
         + Smul (B (6), Shift_By (P_Prime, 1))
         + Smul (B (7), Shift_By (P_Prime, 2))
         + Smul (B (8), Shift_By (P_Prime, 3))
         + Smul (B (9), Shift_By (P_Prime, 4));

   procedure Lemma_Val_PrimePart (B : Big_Nat)
   with
     Pre  =>
       (for all I in Limb_Index range 5 .. 8 => B (I) in 0 .. In_Cap)
       and then B (9) in 0 .. Fold9_Top_Cap,
     Post =>
       Val (Fold_High_9_PrimePart (B)) = (Base_Pow (5) - 5) * Val (High5 (B));

end Tls_Core.Ghost_Bignum.Value;
