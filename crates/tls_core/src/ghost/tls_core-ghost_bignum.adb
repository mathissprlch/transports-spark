package body Tls_Core.Ghost_Bignum
  with SPARK_Mode
is

   function "+" (A, B : Big_Nat) return Big_Nat is
      R : Big_Nat := Zero;
   begin
      for I in Limb_Index loop
         R (I) := A (I) + B (I);
         pragma Loop_Invariant
           (for all J in Limb_Index'First .. I => R (J) = A (J) + B (J));
      end loop;
      return R;
   end "+";

   procedure Lemma_Add_Comm (A, B : Big_Nat) is null;

   procedure Lemma_Add_Zero_R (A : Big_Nat) is null;

   procedure Lemma_Add_Assoc (A, B, C : Big_Nat) is null;

   procedure Lemma_Bounds_Mono (A : Big_Nat; Lo, Hi : LLI) is null;

   procedure Lemma_Mul_Col_Distrib (A, B, C, BC : Big_Nat; K, T : Limb_Index) is
   begin
      if T /= 0 then
         Lemma_Mul_Col_Distrib (A, B, C, BC, K, T - 1);
      end if;
      --  Per-term distributivity at column position K-T; the rest follows
      --  from the inductive hypothesis and the Mul_Col recurrence.
      pragma Assert
        (Mul_Limb (A (T)) * Mul_Limb (BC (K - T))
         = Mul_Limb (A (T)) * Mul_Limb (B (K - T))
           + Mul_Limb (A (T)) * Mul_Limb (C (K - T)));
   end Lemma_Mul_Col_Distrib;

   procedure Lemma_Mul_Distrib (A, B, C, BC : Big_Nat) is
      L  : constant Big_Nat := A * BC;
      R1 : constant Big_Nat := A * B;
      R2 : constant Big_Nat := A * C;
   begin
      for K in Limb_Index loop
         Lemma_Mul_Col_Distrib (A, B, C, BC, K, K);
         pragma Loop_Invariant
           (for all J in 0 .. K => L (J) = R1 (J) + R2 (J));
      end loop;
   end Lemma_Mul_Distrib;

   procedure Lemma_Mul_Col_Zero
     (A, B : Big_Nat; K, T, Na, Nb : Limb_Index) is
   begin
      if T = 0 then
         --  Mul_Col = A(0)*B(K); K >= Na+Nb-1 >= Nb (Na>=1), so B(K) = 0.
         pragma Assert (B (K) = 0);
      else
         Lemma_Mul_Col_Zero (A, B, K, T - 1, Na, Nb);
         --  Term A(T)*B(K-T): T>=Na => A(T)=0; else K-T>=Nb => B(K-T)=0.
         pragma Assert (if T >= Na then A (T) = 0 else B (K - T) = 0);
      end if;
   end Lemma_Mul_Col_Zero;

   procedure Lemma_Mul_Zero_High (A, B, AB : Big_Nat; Na, Nb : Limb_Index) is
   begin
      for K in Limb_Index loop
         if K >= Na + Nb - 1 then
            Lemma_Mul_Col_Zero (A, B, K, K, Na, Nb);
         end if;
         pragma Loop_Invariant
           (for all J in 0 .. K =>
              (if J >= Na + Nb - 1 then AB (J) = 0));
      end loop;
   end Lemma_Mul_Zero_High;

   procedure Lemma_Mul5_Cols (A, B, AB : Big_Nat) is
   begin
      Lemma_Mul_Zero_High (A, B, AB, 5, 5);
      --  AB (k) = Mul_Col (A, B, k, k) (from AB = A * B and the "*" Post);
      --  unfold the Mul_Col recurrence one column at a time so it flattens to
      --  the explicit convolution sum. Mul_Limb keeps every product bounded.

      pragma Assert (Mul_Col (A, B, 1, 1)
        = Mul_Col (A, B, 1, 0) + Mul_Limb (A (1)) * Mul_Limb (B (0)));

      pragma Assert (Mul_Col (A, B, 2, 1)
        = Mul_Col (A, B, 2, 0) + Mul_Limb (A (1)) * Mul_Limb (B (1)));
      pragma Assert (Mul_Col (A, B, 2, 2)
        = Mul_Col (A, B, 2, 1) + Mul_Limb (A (2)) * Mul_Limb (B (0)));

      pragma Assert (Mul_Col (A, B, 3, 1)
        = Mul_Col (A, B, 3, 0) + Mul_Limb (A (1)) * Mul_Limb (B (2)));
      pragma Assert (Mul_Col (A, B, 3, 2)
        = Mul_Col (A, B, 3, 1) + Mul_Limb (A (2)) * Mul_Limb (B (1)));
      pragma Assert (Mul_Col (A, B, 3, 3)
        = Mul_Col (A, B, 3, 2) + Mul_Limb (A (3)) * Mul_Limb (B (0)));

      pragma Assert (Mul_Col (A, B, 4, 1)
        = Mul_Col (A, B, 4, 0) + Mul_Limb (A (1)) * Mul_Limb (B (3)));
      pragma Assert (Mul_Col (A, B, 4, 2)
        = Mul_Col (A, B, 4, 1) + Mul_Limb (A (2)) * Mul_Limb (B (2)));
      pragma Assert (Mul_Col (A, B, 4, 3)
        = Mul_Col (A, B, 4, 2) + Mul_Limb (A (3)) * Mul_Limb (B (1)));
      pragma Assert (Mul_Col (A, B, 4, 4)
        = Mul_Col (A, B, 4, 3) + Mul_Limb (A (4)) * Mul_Limb (B (0)));

      pragma Assert (Mul_Col (A, B, 5, 1)
        = Mul_Col (A, B, 5, 0) + Mul_Limb (A (1)) * Mul_Limb (B (4)));
      pragma Assert (Mul_Col (A, B, 5, 2)
        = Mul_Col (A, B, 5, 1) + Mul_Limb (A (2)) * Mul_Limb (B (3)));
      pragma Assert (Mul_Col (A, B, 5, 3)
        = Mul_Col (A, B, 5, 2) + Mul_Limb (A (3)) * Mul_Limb (B (2)));
      pragma Assert (Mul_Col (A, B, 5, 4)
        = Mul_Col (A, B, 5, 3) + Mul_Limb (A (4)) * Mul_Limb (B (1)));
      pragma Assert (Mul_Col (A, B, 5, 5)
        = Mul_Col (A, B, 5, 4) + Mul_Limb (A (5)) * Mul_Limb (B (0)));

      pragma Assert (Mul_Col (A, B, 6, 2)
        = Mul_Col (A, B, 6, 1) + Mul_Limb (A (2)) * Mul_Limb (B (4)));
      pragma Assert (Mul_Col (A, B, 6, 3)
        = Mul_Col (A, B, 6, 2) + Mul_Limb (A (3)) * Mul_Limb (B (3)));
      pragma Assert (Mul_Col (A, B, 6, 4)
        = Mul_Col (A, B, 6, 3) + Mul_Limb (A (4)) * Mul_Limb (B (2)));
      pragma Assert (Mul_Col (A, B, 6, 5)
        = Mul_Col (A, B, 6, 4) + Mul_Limb (A (5)) * Mul_Limb (B (1)));
      pragma Assert (Mul_Col (A, B, 6, 6)
        = Mul_Col (A, B, 6, 5) + Mul_Limb (A (6)) * Mul_Limb (B (0)));

      pragma Assert (Mul_Col (A, B, 7, 1)
        = Mul_Col (A, B, 7, 0) + Mul_Limb (A (1)) * Mul_Limb (B (6)));
      pragma Assert (Mul_Col (A, B, 7, 2)
        = Mul_Col (A, B, 7, 1) + Mul_Limb (A (2)) * Mul_Limb (B (5)));
      pragma Assert (Mul_Col (A, B, 7, 3)
        = Mul_Col (A, B, 7, 2) + Mul_Limb (A (3)) * Mul_Limb (B (4)));
      pragma Assert (Mul_Col (A, B, 7, 4)
        = Mul_Col (A, B, 7, 3) + Mul_Limb (A (4)) * Mul_Limb (B (3)));
      pragma Assert (Mul_Col (A, B, 7, 5)
        = Mul_Col (A, B, 7, 4) + Mul_Limb (A (5)) * Mul_Limb (B (2)));
      pragma Assert (Mul_Col (A, B, 7, 6)
        = Mul_Col (A, B, 7, 5) + Mul_Limb (A (6)) * Mul_Limb (B (1)));
      pragma Assert (Mul_Col (A, B, 7, 7)
        = Mul_Col (A, B, 7, 6) + Mul_Limb (A (7)) * Mul_Limb (B (0)));

      pragma Assert (Mul_Col (A, B, 8, 1)
        = Mul_Col (A, B, 8, 0) + Mul_Limb (A (1)) * Mul_Limb (B (7)));
      pragma Assert (Mul_Col (A, B, 8, 2)
        = Mul_Col (A, B, 8, 1) + Mul_Limb (A (2)) * Mul_Limb (B (6)));
      pragma Assert (Mul_Col (A, B, 8, 3)
        = Mul_Col (A, B, 8, 2) + Mul_Limb (A (3)) * Mul_Limb (B (5)));
      pragma Assert (Mul_Col (A, B, 8, 4)
        = Mul_Col (A, B, 8, 3) + Mul_Limb (A (4)) * Mul_Limb (B (4)));
      pragma Assert (Mul_Col (A, B, 8, 5)
        = Mul_Col (A, B, 8, 4) + Mul_Limb (A (5)) * Mul_Limb (B (3)));
      pragma Assert (Mul_Col (A, B, 8, 6)
        = Mul_Col (A, B, 8, 5) + Mul_Limb (A (6)) * Mul_Limb (B (2)));
      pragma Assert (Mul_Col (A, B, 8, 7)
        = Mul_Col (A, B, 8, 6) + Mul_Limb (A (7)) * Mul_Limb (B (1)));
      pragma Assert (Mul_Col (A, B, 8, 8)
        = Mul_Col (A, B, 8, 7) + Mul_Limb (A (8)) * Mul_Limb (B (0)));
   end Lemma_Mul5_Cols;

   procedure Lemma_Carry26 (X : LLI) is null;

   procedure Lemma_Hi26_Bound (X : LLI) is null;

   procedure Lemma_Hi26_Conv (X : LLI) is null;

   procedure Lemma_Val_Eq_Refl (A : Big_Nat) is null;

   procedure Lemma_Val_Eq_Unique (A, B : Big_Nat; C : Carry_Array) is
   begin
      for I in Limb_Index loop
         --  C (I) = 0 holds: from Val_Eq for I = 0, from the prior iteration
         --  invariant otherwise. The column gives A(I)-B(I) = Limb_Base*C(I+1)
         --  with |A(I)-B(I)| <= In_Cap < Limb_Base, forcing C(I+1) = 0.
         pragma Assert (C (I) = 0);
         pragma Assert (A (I) + C (I) = B (I) + Limb_Base * C (I + 1));
         pragma Assert (Limb_Base * C (I + 1) = A (I) - B (I));
         pragma Assert (C (I + 1) = 0);
         pragma Assert (A (I) = B (I));
         pragma Loop_Invariant (C (I + 1) = 0);
         pragma Loop_Invariant (for all J in 0 .. I => A (J) = B (J));
      end loop;
   end Lemma_Val_Eq_Unique;

   procedure Lemma_Val_To_SVal (A, B : Big_Nat; C : Carry_Array) is null;

   procedure Lemma_SVal_Sym (A, B : Big_Nat; C : Carry_Array) is null;

   procedure Lemma_SVal_Trans (A, B, D : Big_Nat; C1, C2 : Carry_Array) is
   begin
      pragma Assert
        (for all I in Limb_Index =>
           A (I) + (C1 (I) + C2 (I))
           = D (I) + Limb_Base * (C1 (I + 1) + C2 (I + 1)));
   end Lemma_SVal_Trans;

   procedure Lemma_SVal_Add_Const (X, Y, M : Big_Nat; C : Carry_Array) is
   begin
      pragma Assert
        (for all I in Limb_Index =>
           (X (I) + M (I)) + C (I)
           = (Y (I) + M (I)) + Limb_Base * C (I + 1));
   end Lemma_SVal_Add_Const;

   procedure Lemma_Carry_Step (A : Big_Nat; I : Limb_Index) is
   begin
      Lemma_Carry26 (A (I));
   end Lemma_Carry_Step;

   procedure Lemma_Sweep5 (A : Big_Nat) is
   begin
      Lemma_Carry26 (A (0));
      Lemma_Carry26 (A (1) + Sw_C0 (A));
      Lemma_Carry26 (A (2) + Sw_C1 (A));
      Lemma_Carry26 (A (3) + Sw_C2 (A));
      Lemma_Carry26 (A (4) + Sw_C3 (A));
   end Lemma_Sweep5;

   procedure Lemma_Sweep5_Tight (A : Big_Nat) is null;

   procedure Lemma_Sweep5_Tight_Carry (A : Big_Nat) is null;

   procedure Lemma_Sweep5_Chain_Tight (A : Big_Nat) is
   begin
      Lemma_Hi26_Conv (A (0));
      Lemma_Hi26_Conv (A (1) + Sw_C0 (A));
      Lemma_Hi26_Conv (A (2) + Sw_C1 (A));
      Lemma_Hi26_Conv (A (3) + Sw_C2 (A));
      Lemma_Hi26_Conv (A (4) + Sw_C3 (A));
   end Lemma_Sweep5_Chain_Tight;

   procedure Lemma_Sweep5_Acc_Carry (B : Big_Nat) is
   begin
      --  Each limb <= Mul_Cap = 2**27, each carry-in <= 2, so every column is
      --  < 2**28 and Hi26 (= /2**26) of it is <= 2. Chain the five carries.
      Lemma_Bounds_Mono (B, Mul_Cap, Prod_Cap);
      pragma Assert (Sw_C0 (B) <= 2);
      pragma Assert (Sw_C1 (B) <= 2);
      pragma Assert (Sw_C2 (B) <= 2);
      pragma Assert (Sw_C3 (B) <= 2);
      pragma Assert (Sw_C4 (B) <= 2);
   end Lemma_Sweep5_Acc_Carry;

   procedure Lemma_Sweep9 (A : Big_Nat) is
   begin
      Lemma_Carry26 (A (0));
      Lemma_Carry26 (A (1) + Sw9_C0 (A));
      Lemma_Carry26 (A (2) + Sw9_C1 (A));
      Lemma_Carry26 (A (3) + Sw9_C2 (A));
      Lemma_Carry26 (A (4) + Sw9_C3 (A));
      Lemma_Carry26 (A (5) + Sw9_C4 (A));
      Lemma_Carry26 (A (6) + Sw9_C5 (A));
      Lemma_Carry26 (A (7) + Sw9_C6 (A));
      Lemma_Carry26 (A (8) + Sw9_C7 (A));
   end Lemma_Sweep9;

   procedure Lemma_Sweep9_Conv (A : Big_Nat) is
   begin
      Lemma_Hi26_Conv (A (0));
      Lemma_Hi26_Conv (A (1) + Sw9_C0 (A));
      Lemma_Hi26_Conv (A (2) + Sw9_C1 (A));
      Lemma_Hi26_Conv (A (3) + Sw9_C2 (A));
      Lemma_Hi26_Conv (A (4) + Sw9_C3 (A));
      Lemma_Hi26_Conv (A (5) + Sw9_C4 (A));
      Lemma_Hi26_Conv (A (6) + Sw9_C5 (A));
      Lemma_Hi26_Conv (A (7) + Sw9_C6 (A));
      Lemma_Hi26_Conv (A (8) + Sw9_C7 (A));
   end Lemma_Sweep9_Conv;

   procedure Lemma_Sweep9_Cols (A : Big_Nat) is null;

   procedure Lemma_Sweep9_Chain_Tight (A : Big_Nat) is
   begin
      Lemma_Hi26_Conv (A (0));
      Lemma_Hi26_Conv (A (1) + Sw9_C0 (A));
      Lemma_Hi26_Conv (A (2) + Sw9_C1 (A));
      Lemma_Hi26_Conv (A (3) + Sw9_C2 (A));
      Lemma_Hi26_Conv (A (4) + Sw9_C3 (A));
      Lemma_Hi26_Conv (A (5) + Sw9_C4 (A));
      Lemma_Hi26_Conv (A (6) + Sw9_C5 (A));
      Lemma_Hi26_Conv (A (7) + Sw9_C6 (A));
      Lemma_Hi26_Conv (A (8) + Sw9_C7 (A));
   end Lemma_Sweep9_Chain_Tight;

   procedure Lemma_Fold (B : Big_Nat) is null;

   procedure Lemma_Fold_Plus_P_Eq (B : Big_Nat) is
      M : constant Big_Nat := Smul (B (5), P_Prime);
   begin
      --  Smul (B (5), P_Prime) is exactly Fold_Plus_P's inline prime terms.
      pragma Assert (M (0) = B (5) * (In_Cap - 4));
      pragma Assert
        (for all I in Limb_Index range 1 .. 4 => M (I) = B (5) * In_Cap);
      pragma Assert
        (for all I in Limb_Index range 5 .. Max_Limbs - 1 => M (I) = 0);
      pragma Assert
        (for all I in Limb_Index =>
           Fold_Out (B) (I) + M (I) = Fold_Plus_P (B) (I));
   end Lemma_Fold_Plus_P_Eq;

   procedure Lemma_Subtract_P5 (B : Big_Nat) is null;

   procedure Lemma_Reduced_No_Carry (X : Big_Nat) is
   begin
      Lemma_Bounds_Mono (X, In_Cap, Prod_Cap);
      --  Each limb <= In_Cap < 2**26, every carry-in is 0, so every Hi26 is 0
      --  and Lo26 is the identity: the sweep reproduces X with no carry out.
      pragma Assert (Sw_C0 (X) = 0);
      pragma Assert (Sw_C1 (X) = 0);
      pragma Assert (Sw_C2 (X) = 0);
      pragma Assert (Sw_C3 (X) = 0);
      pragma Assert (Sw_C4 (X) = 0);
      pragma Assert
        (for all I in Limb_Index => Sweep5_Out (X) (I) = X (I));
   end Lemma_Reduced_No_Carry;

   procedure Lemma_Sweep5_Ripple (X : Big_Nat) is
   begin
      pragma Assert (In_Bounds (X, Mul_Cap));
      Lemma_Bounds_Mono (X, Mul_Cap, Prod_Cap);
      --  X(0) < 2**27 and each carry-in <= 1, so every Sw_Ci is 0 or 1.
      pragma Assert (Sw_C0 (X) <= 1);
      pragma Assert (Sw_C1 (X) <= 1);
      pragma Assert (Sw_C2 (X) <= 1);
      pragma Assert (Sw_C3 (X) <= 1);
      pragma Assert (Sw_C4 (X) <= 1);
      --  A surviving carry forces the limb to In_Cap and the prior carry to 1
      --  (X(i) + Sw_C{i-1} = 2**26 is the only way Hi26 = 1 when both are
      --  bounded), so the swept limb is Lo26 (In_Cap + 1) = Lo26 (2**26) = 0.
      pragma Assert
        (if Sw_C1 (X) = 1 then X (1) = In_Cap and then Sw_C0 (X) = 1);
      pragma Assert
        (if Sw_C2 (X) = 1 then X (2) = In_Cap and then Sw_C1 (X) = 1);
      pragma Assert
        (if Sw_C3 (X) = 1 then X (3) = In_Cap and then Sw_C2 (X) = 1);
      pragma Assert
        (if Sw_C4 (X) = 1 then X (4) = In_Cap and then Sw_C3 (X) = 1);
      pragma Assert
        (if Sw_C4 (X) = 1
         then Sweep5_Out (X) (4) = 0 and then Sweep5_Out (X) (3) = 0
              and then Sweep5_Out (X) (2) = 0 and then Sweep5_Out (X) (1) = 0);
   end Lemma_Sweep5_Ripple;

   procedure Lemma_Sweep5_Low_Only (X : Big_Nat) is
   begin
      pragma Assert (In_Bounds (X, Mul_Cap));
      Lemma_Bounds_Mono (X, Mul_Cap, Prod_Cap);
      --  limb0 < 2**27 => Sw_C0 <= 1; limbs 1..4 = 0 so each later carry-in
      --  is Hi26 (0 + previous carry) = Hi26 (<= 1) = 0.
      pragma Assert (Sw_C0 (X) <= 1);
      pragma Assert (Sw_C1 (X) = 0);
      pragma Assert (Sw_C2 (X) = 0);
      pragma Assert (Sw_C3 (X) = 0);
      pragma Assert (Sw_C4 (X) = 0);
   end Lemma_Sweep5_Low_Only;

   procedure Lemma_Reduce_Canonical (B : Big_Nat) is
      S   : constant Big_Nat := Sweep5_Out (B);
      Sum : constant Big_Nat := Subtract_P5_Out (S) + Sub_Sel_P (S);
   begin
      --  B =val S (the sweep is exact); S = Subtract_P5_Out (S) + Sub_Sel_P (S)
      --  limbwise (the subtract is exact). Lift both to SVal_Eq and compose:
      --  B =val[Sweep5_Chain] S =val[0] Sum, so B =val[Sweep5_Chain] Sum.
      Lemma_Bounds_Mono (B, Prod_Cap, Add_Cap);
      Lemma_Sweep5 (B);
      Lemma_Val_To_SVal (B, S, Sweep5_Chain (B));
      Lemma_Subtract_P5 (S);
      Lemma_Val_To_SVal (Sum, S, Zero_Carry);
      Lemma_SVal_Sym (Sum, S, Zero_Carry);
      Lemma_SVal_Trans (B, S, Sum, Sweep5_Chain (B), Neg_Carry (Zero_Carry));
      pragma Assert
        (Add_Carry (Sweep5_Chain (B), Neg_Carry (Zero_Carry)) = Sweep5_Chain (B));
   end Lemma_Reduce_Canonical;

   function Normalize (B : Big_Nat) return Big_Nat is
      S1, R1, S2, R2, S3 : Big_Nat;
   begin
      Lemma_Bounds_Mono (B, Mul_Cap, Prod_Cap);
      Lemma_Sweep5_Acc_Carry (B);          --  Sweep5_Out (B) (5) <= 2
      S1 := Sweep5_Out (B);
      R1 := Fold_Out (S1);                 --  Pre: S1 (5) <= Fold_C_Cap (ok)

      --  R1 = first fold round: limb0 <= In_Cap + 10 (= S1(0)+5*S1(5),
      --  S1(5) <= 2), limbs 1..4 <= In_Cap, zero from 5. So R1 is Mul_Cap-
      --  bounded and feeds the second round.
      pragma Assert (R1 (0) <= In_Cap + 10);
      pragma Assert
        (for all I in Limb_Index range 1 .. 4 => R1 (I) in 0 .. In_Cap);
      pragma Assert
        (for all I in Limb_Index range 5 .. Max_Limbs - 1 => R1 (I) = 0);
      pragma Assert (In_Bounds (R1, Mul_Cap));

      Lemma_Sweep5_Acc_Carry (R1);         --  Sweep5_Out (R1) (5) <= 2
      S2 := Sweep5_Out (R1);
      R2 := Fold_Out (S2);                 --  Pre: S2 (5) <= Fold_C_Cap (ok)

      if S2 (5) >= 1 then
         --  Carry survived: by the ripple lemma the swept limbs 1..4 are 0,
         --  so R2 collapses to [<= In_Cap + 10, 0, 0, 0, 0] and its sweep
         --  has no carry out (value < 2**130).
         Lemma_Sweep5_Ripple (R1);
         pragma Assert (for all I in Limb_Index range 1 .. 4 => S2 (I) = 0);
         pragma Assert (R2 (0) <= In_Cap + 10);
         pragma Assert
           (for all I in Limb_Index range 1 .. Max_Limbs - 1 => R2 (I) = 0);
         Lemma_Sweep5_Low_Only (R2);
      else
         --  No carry: R2 = S2 is already reduced (limbs <= In_Cap).
         pragma Assert
           (for all I in Limb_Index range 0 .. 4 => R2 (I) in 0 .. In_Cap);
         pragma Assert
           (for all I in Limb_Index range 5 .. Max_Limbs - 1 => R2 (I) = 0);
         pragma Assert (In_Bounds (R2, In_Cap));
         Lemma_Reduced_No_Carry (R2);
      end if;

      --  Both branches: Sweep5_Out (R2) (5) = 0, so the third sweep S3 is a
      --  fully reduced five-limb value (< 2**130).
      pragma Assert (Sweep5_Out (R2) (5) = 0);
      S3 := Sweep5_Out (R2);
      pragma Assert
        (for all I in Limb_Index range 0 .. 4 => S3 (I) in 0 .. In_Cap);
      pragma Assert
        (for all I in Limb_Index range 5 .. Max_Limbs - 1 => S3 (I) = 0);
      pragma Assert (In_Bounds (S3, In_Cap));
      Lemma_Reduced_No_Carry (S3);         --  Sweep5_Out (S3) (5) = 0
      return S3;
   end Normalize;

   procedure Lemma_Rotate1 (R : Big_Nat) is
   begin
      Lemma_Fold (Shift1 (R));
   end Lemma_Rotate1;

   procedure Lemma_Fold_High (B : Big_Nat) is null;

   procedure Lemma_Rotate2 (R : Big_Nat) is
   begin
      Lemma_Fold_High (Shift2 (R));
   end Lemma_Rotate2;

   procedure Lemma_Rotate3 (R : Big_Nat) is
   begin
      Lemma_Fold_High (Shift3 (R));
   end Lemma_Rotate3;

   procedure Lemma_Rotate4 (R : Big_Nat) is
   begin
      Lemma_Fold_High (Shift4 (R));
   end Lemma_Rotate4;

   procedure Lemma_Fold_High_Mul_Form (B : Big_Nat) is
      H : constant Big_Nat := High4 (B);
      M : constant Big_Nat := P_Prime * H;
   begin
      --  High product limbs vanish: P_Prime is zero from index 5, H from
      --  index 4, so M is zero from index 8 on.
      Lemma_Mul_Zero_High (P_Prime, H, M, 5, 4);
      --  Zero facts so the deep convolution unfolds drop their high terms.
      pragma Assert (P_Prime (5) = 0);
      pragma Assert (H (4) = 0 and then H (5) = 0);
      --  Low columns by unfolding the convolution (M (K) = Mul_Col from the
      --  "*" postcondition); P_Prime = (In_Cap-4, In_Cap, In_Cap, In_Cap,
      --  In_Cap) and H = (B5, B6, B7, B8).
      pragma Assert (M (0) = (In_Cap - 4) * B (5));
      pragma Assert (M (1) = (In_Cap - 4) * B (6) + In_Cap * B (5));
      pragma Assert
        (M (2) = (In_Cap - 4) * B (7) + In_Cap * B (6) + In_Cap * B (5));
      pragma Assert
        (M (3) =
           (In_Cap - 4) * B (8) + In_Cap * B (7) + In_Cap * B (6)
           + In_Cap * B (5));
      pragma Assert
        (M (4) =
           In_Cap * B (8) + In_Cap * B (7) + In_Cap * B (6) + In_Cap * B (5));
      pragma Assert
        (Mul_Col (P_Prime, H, 5, 4)
         = In_Cap * B (8) + In_Cap * B (7) + In_Cap * B (6));
      pragma Assert (M (5) = In_Cap * B (8) + In_Cap * B (7) + In_Cap * B (6));
      pragma Assert (M (6) = In_Cap * B (8) + In_Cap * B (7));
      pragma Assert (M (7) = In_Cap * B (8));
   end Lemma_Fold_High_Mul_Form;

   procedure Lemma_Fold_High_9 (B : Big_Nat) is null;

   procedure Lemma_Reduce_Conv_Round1 (Conv, S : Big_Nat; C1 : Carry_Array) is
      C2 : constant Carry_Array := Fold_High_9_Chain (S);
   begin
      Lemma_Sweep9 (Conv);                                --  Val_Eq(Conv,S,C1)
      Lemma_Val_To_SVal (Conv, S, C1);                    --  SVal_Eq(Conv,S,C1)
      Lemma_Fold_High_9 (S);                              --  Val_Eq(P9(S),S,C2)
      Lemma_Val_To_SVal (Fold_High_9_Plus_P (S), S, C2);  --  SVal_Eq(P9(S),S,C2)
      Lemma_SVal_Sym (Fold_High_9_Plus_P (S), S, C2);     --  SVal_Eq(S,P9(S),-C2)
      pragma Assert (SC_Bounded (Add_Carry (C1, Neg_Carry (C2))));
      Lemma_SVal_Trans
        (Conv, S, Fold_High_9_Plus_P (S), C1, Neg_Carry (C2));
   end Lemma_Reduce_Conv_Round1;

   procedure Lemma_Reduce_Round2 (R1, T : Big_Nat; D1 : Carry_Array) is
      D2 : constant Carry_Array := Fold_Chain (T (5));
   begin
      Lemma_Sweep5 (R1);                          --  Val_Eq(R1, T, D1)
      Lemma_Val_To_SVal (R1, T, D1);              --  SVal_Eq(R1, T, D1)
      Lemma_Fold (T);                             --  Val_Eq(Fold_Plus_P(T),T,D2)
      Lemma_Val_To_SVal (Fold_Plus_P (T), T, D2); --  SVal_Eq(Fold_Plus_P(T),T,D2)
      Lemma_SVal_Sym (Fold_Plus_P (T), T, D2);    --  SVal_Eq(T,Fold_Plus_P(T),-D2)
      pragma Assert (SC_Bounded (Add_Carry (D1, Neg_Carry (D2))));
      Lemma_SVal_Trans (R1, T, Fold_Plus_P (T), D1, Neg_Carry (D2));
   end Lemma_Reduce_Round2;

   procedure Lemma_Mul_Reduce
     (Conv, S, R1, T : Big_Nat; C1, D1 : Carry_Array)
   is
      C2  : constant Carry_Array := Fold_High_9_Chain (S);
      D2  : constant Carry_Array := Fold_Chain (T (5));
      M1  : constant Big_Nat := Fold_High_9_PrimePart (S);
      Ch1 : constant Carry_Array := Add_Carry (C1, Neg_Carry (C2));
      Ch2 : constant Carry_Array := Add_Carry (D1, Neg_Carry (D2));
   begin
      --  Conv-tight chain bounds so the combined chain stays within Hi_Cap.
      Lemma_Sweep9_Conv (Conv);          --  S (9) and the C2 entries are tight
      Lemma_Sweep9_Chain_Tight (Conv);   --  C1 entries <= Conv_Carry_Cap
      Lemma_Sweep5_Chain_Tight (R1);     --  D1 entries <= Conv_Carry_Cap
      Lemma_Reduce_Conv_Round1 (Conv, S, C1);
      --  SVal_Eq (Conv, Fold_High_9_Plus_P (S), Ch1)
      Lemma_Reduce_Round2 (R1, T, D1);
      --  SVal_Eq (R1, Fold_Plus_P (T), Ch2)
      pragma Assert (Fold_High_9_Out (S) + M1 = Fold_High_9_Plus_P (S));
      Lemma_SVal_Add_Const (R1, Fold_Plus_P (T), M1, Ch2);
      --  SVal_Eq (Fold_High_9_Plus_P (S), Fold_Plus_P (T) + M1, Ch2)
      --  Component bounds so the combined chain stays within Hi_Cap:
      --  C1, D1 conv-tight; C2 <= 4*In_Cap+Fold9_Top_Cap; D2 <= Fold_C_Cap.
      pragma Assert
        (for all J in Carry_Array'Range => C1 (J) in 0 .. Conv_Carry_Cap);
      pragma Assert
        (for all J in Carry_Array'Range => D1 (J) in 0 .. Conv_Carry_Cap);
      pragma Assert
        (for all J in Carry_Array'Range =>
           C2 (J) in 0 .. 4 * In_Cap + Fold9_Top_Cap);
      pragma Assert
        (for all J in Carry_Array'Range => D2 (J) in 0 .. Fold_C_Cap);
      pragma Assert
        (for all J in Carry_Array'Range => Ch1 (J) = C1 (J) - C2 (J));
      pragma Assert
        (for all J in Carry_Array'Range => Ch2 (J) = D1 (J) - D2 (J));
      pragma Assert (SC_Bounded (Add_Carry (Ch1, Ch2)));
      Lemma_SVal_Trans
        (Conv, Fold_High_9_Plus_P (S), Fold_Plus_P (T) + M1, Ch1, Ch2);
   end Lemma_Mul_Reduce;

   procedure Lemma_Two_Round_Cong
     (B, S1, R1, S2 : Big_Nat; CA, CB : Carry_Array)
   is
      M_A : constant Big_Nat := Smul (S1 (5), P_Prime);
      ChA : constant Carry_Array :=
        Add_Carry (CA, Neg_Carry (Fold_Chain (S1 (5))));
      ChB : constant Carry_Array :=
        Add_Carry (CB, Neg_Carry (Fold_Chain (S2 (5))));
   begin
      Lemma_Sweep5_Chain_Tight (B);    --  CA entries <= Conv_Carry_Cap
      Lemma_Sweep5_Chain_Tight (R1);   --  CB entries <= Conv_Carry_Cap
      Lemma_Reduce_Round2 (B, S1, CA);   --  SVal_Eq (B,  Fold_Plus_P (S1), ChA)
      Lemma_Reduce_Round2 (R1, S2, CB);  --  SVal_Eq (R1, Fold_Plus_P (S2), ChB)

      --  Fold_Plus_P (S1) = Fold_Out (S1) + M_A = R1 + M_A, so adding M_A to
      --  both sides of round B aligns its left side with round A's right side.
      Lemma_Fold_Plus_P_Eq (S1);             --  Fold_Out (S1) + M_A = P+P (S1)
      pragma Assert (R1 + M_A = Fold_Plus_P (S1));
      Lemma_SVal_Add_Const (R1, Fold_Plus_P (S2), M_A, ChB);
      --  SVal_Eq (Fold_Plus_P (S1), Fold_Plus_P (S2) + M_A, ChB)

      --  Combined chain stays within Hi_Cap: CA, CB <= Conv_Carry_Cap; the
      --  Fold_Chains <= S(5) <= 2.
      pragma Assert
        (for all J in Carry_Array'Range => CA (J) in 0 .. Conv_Carry_Cap);
      pragma Assert
        (for all J in Carry_Array'Range => CB (J) in 0 .. Conv_Carry_Cap);
      pragma Assert
        (for all J in Carry_Array'Range => Fold_Chain (S1 (5)) (J) in 0 .. 2);
      pragma Assert
        (for all J in Carry_Array'Range => Fold_Chain (S2 (5)) (J) in 0 .. 2);
      pragma Assert (SC_Bounded (Add_Carry (ChA, ChB)));
      Lemma_SVal_Trans (B, Fold_Plus_P (S1), Fold_Plus_P (S2) + M_A, ChA, ChB);
      --  SVal_Eq (B, Fold_Plus_P (S2) + M_A, ChA + ChB) = Post
   end Lemma_Two_Round_Cong;

   procedure Lemma_Carry_Fold (B : Big_Nat) is
      T  : constant Big_Nat     := Sweep5_Out (B);
      D1 : constant Carry_Array := Sweep5_Chain (B);
      D2 : constant Carry_Array := Fold_Chain (T (5));
   begin
      Lemma_Sweep5_Tight_Carry (B);               --  T (5) <= Fold_C_Cap
      Lemma_Sweep5 (B);                           --  Val_Eq(B, T, D1)
      Lemma_Val_To_SVal (B, T, D1);               --  SVal_Eq(B, T, D1)
      Lemma_Fold (T);                             --  Val_Eq(Fold_Plus_P(T),T,D2)
      Lemma_Val_To_SVal (Fold_Plus_P (T), T, D2); --  SVal_Eq(Fold_Plus_P(T),T,D2)
      Lemma_SVal_Sym (Fold_Plus_P (T), T, D2);    --  SVal_Eq(T,Fold_Plus_P(T),-D2)
      pragma Assert (SC_Bounded (Add_Carry (D1, Neg_Carry (D2))));
      Lemma_SVal_Trans (B, T, Fold_Plus_P (T), D1, Neg_Carry (D2));
   end Lemma_Carry_Fold;

   function "*" (A, B : Big_Nat) return Big_Nat is
      R : Big_Nat := Zero;
   begin
      for K in Limb_Index loop
         R (K) := Mul_Col (A, B, K, K);
         pragma Loop_Invariant
           (for all J in 0 .. K => R (J) = Mul_Col (A, B, J, J));
         pragma Loop_Invariant (In_Bounds (R, Add_Cap));
      end loop;
      return R;
   end "*";

end Tls_Core.Ghost_Bignum;
