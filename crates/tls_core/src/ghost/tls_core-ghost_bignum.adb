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

   procedure Lemma_Fold (B : Big_Nat) is null;

   procedure Lemma_Subtract_P5 (B : Big_Nat) is null;

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
