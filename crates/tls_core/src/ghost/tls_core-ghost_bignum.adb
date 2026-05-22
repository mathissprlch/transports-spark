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

   procedure Lemma_Diff_Col_Eq (A, B, R : Big_Nat; K, T : Limb_Index) is
   begin
      if T /= 0 then
         Lemma_Diff_Col_Eq (A, B, R, K, T - 1);
      end if;
      --  Per-term: the difference of the T-th column products is the signed
      --  product (A (T) - B (T)) * R (K - T); the rest is the inductive
      --  hypothesis plus the Mul_Col recurrence.
      pragma Assert
        (Mul_Limb (A (T)) * Mul_Limb (R (K - T))
         - Mul_Limb (B (T)) * Mul_Limb (R (K - T))
         = (A (T) - B (T)) * R (K - T));
   end Lemma_Diff_Col_Eq;

   procedure Lemma_Diff3_Col_Eq
     (W, Wc, P, R : Big_Nat; Kc : LLI; K, T : Limb_Index) is
   begin
      if T /= 0 then
         Lemma_Diff3_Col_Eq (W, Wc, P, R, Kc, K, T - 1);
      end if;
      pragma Assert
        (Mul_Limb (W (T)) * Mul_Limb (R (K - T))
         - Mul_Limb (Wc (T)) * Mul_Limb (R (K - T))
         - Kc * (Mul_Limb (P (T)) * Mul_Limb (R (K - T)))
         = (W (T) - Wc (T) - Kc * P (T)) * R (K - T));
   end Lemma_Diff3_Col_Eq;

   procedure Lemma_Diff_Chain_Step
     (A, B, R : Big_Nat; C : Carry_Array; K, T : Limb_Index) is
   begin
      --  Term T: the SVal column relation at I = T gives
      --  A (T) - B (T) = Limb_Base * C (T+1) - C (T); multiplying by R (K-T)
      --  matches the T-th terms of Limb_Base*Shift_Chain_Col - Conv_Chain_Col.
      pragma Assert (A (T) - B (T) = Limb_Base * C (T + 1) - C (T));
      pragma Assert
        ((A (T) - B (T)) * R (K - T)
         = Limb_Base * (C (T + 1) * R (K - T)) - C (T) * R (K - T));
      if T /= 0 then
         Lemma_Diff_Chain_Step (A, B, R, C, K, T - 1);
         --  Make the three expression-function recurrences explicit so the
         --  inductive hypothesis composes with the term-T identity.
         pragma Assert
           (Diff_Col (A, B, R, K, T)
            = Diff_Col (A, B, R, K, T - 1) + (A (T) - B (T)) * R (K - T));
         pragma Assert
           (Shift_Chain_Col (C, R, K, T)
            = Shift_Chain_Col (C, R, K, T - 1) + C (T + 1) * R (K - T));
         pragma Assert
           (Conv_Chain_Col (C, R, K, T)
            = Conv_Chain_Col (C, R, K, T - 1) + C (T) * R (K - T));
      end if;
   end Lemma_Diff_Chain_Step;

   procedure Lemma_Chain_Reindex
     (C : Carry_Array; R : Big_Nat; K, T : Limb_Index) is
   begin
      if T /= 0 then
         Lemma_Chain_Reindex (C, R, K, T - 1);
      end if;
      --  Conv_Chain_Col (.., K+1, T+1) unfolds to add C (T+1) * R (K-T), the
      --  same T-th term Shift_Chain_Col (.., K, T) adds; the inductive
      --  hypothesis handles the rest. (K + 1 - (T + 1) = K - T.)
      null;
   end Lemma_Chain_Reindex;

   procedure Lemma_Diff_Col_Chain
     (A, B, R : Big_Nat; C : Carry_Array; K : Limb_Index) is
   begin
      Lemma_Diff_Chain_Step (A, B, R, C, K, K);
      --  Diff_Col (K,K) = Limb_Base * Shift_Chain_Col (K,K) - Conv_Chain_Col (K,K).
      Lemma_Chain_Reindex (C, R, K, K);
      --  Conv_Chain_Col (K+1,K+1) = C (0)*R(K+1) + Shift_Chain_Col (K,K)
      --                           = Shift_Chain_Col (K,K)   (C (0) = 0).
   end Lemma_Diff_Col_Chain;

   procedure Lemma_Diff3_Chain_Step
     (W, Wc, P, R : Big_Nat; Kc : LLI; Cc : Carry_Array; K, T : Limb_Index) is
   begin
      --  Staged: substitute the column relation, then distribute over R (K-T).
      pragma Assert
        (W (T) - Wc (T) - Kc * P (T) = Limb_Base * Cc (T + 1) - Cc (T));
      pragma Assert
        ((W (T) - Wc (T) - Kc * P (T)) * R (K - T)
         = (Limb_Base * Cc (T + 1) - Cc (T)) * R (K - T));
      pragma Assert
        ((Limb_Base * Cc (T + 1) - Cc (T)) * R (K - T)
         = Limb_Base * (Cc (T + 1) * R (K - T)) - Cc (T) * R (K - T));
      if T = 0 then
         pragma Assert
           (Diff3_Col (W, Wc, P, R, Kc, K, 0)
            = (W (0) - Wc (0) - Kc * P (0)) * R (K - 0));
         pragma Assert (Shift_Chain_Col (Cc, R, K, 0) = Cc (1) * R (K - 0));
         pragma Assert (Conv_Chain_Col (Cc, R, K, 0) = Cc (0) * R (K - 0));
         pragma Assert
           (Diff3_Col (W, Wc, P, R, Kc, K, T)
            = Limb_Base * Shift_Chain_Col (Cc, R, K, T)
              - Conv_Chain_Col (Cc, R, K, T));
      else
         Lemma_Diff3_Chain_Step (W, Wc, P, R, Kc, Cc, K, T - 1);
         pragma Assert
           (Diff3_Col (W, Wc, P, R, Kc, K, T)
            = Diff3_Col (W, Wc, P, R, Kc, K, T - 1)
              + (W (T) - Wc (T) - Kc * P (T)) * R (K - T));
         pragma Assert
           (Shift_Chain_Col (Cc, R, K, T)
            = Shift_Chain_Col (Cc, R, K, T - 1) + Cc (T + 1) * R (K - T));
         pragma Assert
           (Conv_Chain_Col (Cc, R, K, T)
            = Conv_Chain_Col (Cc, R, K, T - 1) + Cc (T) * R (K - T));
         pragma Assert
           (Diff3_Col (W, Wc, P, R, Kc, K, T)
            = Limb_Base * Shift_Chain_Col (Cc, R, K, T)
              - Conv_Chain_Col (Cc, R, K, T));
      end if;
   end Lemma_Diff3_Chain_Step;

   procedure Lemma_Diff3_Col_Chain
     (W, Wc, P, R : Big_Nat; Kc : LLI; Cc : Carry_Array; K : Limb_Index) is
   begin
      Lemma_Diff3_Chain_Step (W, Wc, P, R, Kc, Cc, K, K);
      Lemma_Chain_Reindex (Cc, R, K, K);
   end Lemma_Diff3_Col_Chain;

   procedure Lemma_SVal_To_Wide (A, B : Big_Nat; C : Carry_Array) is null;

   procedure Lemma_SVal_Chain_Zero_High (A, B : Big_Nat; C : Carry_Array) is
   begin
      for K in reverse 5 .. Max_Limbs - 1 loop
         pragma Assert (A (K) + C (K) = B (K) + Limb_Base * C (K + 1));
         pragma Assert (C (K) = Limb_Base * C (K + 1));
         pragma Loop_Invariant (for all J in K .. Max_Limbs => C (J) = 0);
      end loop;
   end Lemma_SVal_Chain_Zero_High;

   procedure Lemma_Conv_Chain_Zero
     (C : Carry_Array; R : Big_Nat; K, T : Limb_Index) is
   begin
      if T /= 0 then
         Lemma_Conv_Chain_Zero (C, R, K, T - 1);
      end if;
      --  Term T: T >= 5 => C (T) = 0; else K - T >= 5 (K >= 9, T <= 4) => R = 0.
      pragma Assert (if T >= 5 then C (T) = 0 else R (K - T) = 0);
      pragma Assert (C (T) * R (K - T) = 0);
   end Lemma_Conv_Chain_Zero;

   procedure Lemma_Mul_SVal_Cong (A, B, R : Big_Nat; C : Carry_Array) is
      GA : constant Big_Nat     := A * R;
      GB : constant Big_Nat     := B * R;
      G  : constant Carry_Array := Carry_Conv (C, R);
   begin
      Lemma_SVal_Chain_Zero_High (A, B, C);   --  C zero from limb 5
      Lemma_Mul5_Cols (A, R, GA);             --  GA zero from limb 9
      Lemma_Mul5_Cols (B, R, GB);             --  GB zero from limb 9
      for I in Limb_Index loop
         if I < 9 then
            Lemma_Diff_Col_Eq (A, B, R, I, I);
            Lemma_Diff_Col_Chain (A, B, R, C, I);
            --  GA (I) - GB (I) = Diff_Col = Limb_Base*G (I+1) - G (I).
         else
            Lemma_Conv_Chain_Zero (C, R, I, I);                --  G (I) = 0
            if I < Max_Limbs - 1 then
               Lemma_Conv_Chain_Zero (C, R, I + 1, I + 1);     --  G (I+1) = 0
            end if;
            --  GA (I) = GB (I) = 0; relation is 0 = 0.
         end if;
         pragma Loop_Invariant
           (for all J in 0 .. I =>
              GA (J) + G (J) = GB (J) + Limb_Base * G (J + 1));
      end loop;
      pragma Assert (G (0) = 0);
      pragma Assert (G (Max_Limbs) = 0);
      pragma Assert (SVal_Wide (GA, GB, G));
   end Lemma_Mul_SVal_Cong;

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

   procedure Lemma_SVal_Eq_Unique (A, B : Big_Nat; C : Carry_Array) is
   begin
      --  Identical column-forcing to Lemma_Val_Eq_Unique: C (0) = 0, and each
      --  column gives A(I) - B(I) = Limb_Base * C(I+1) with |A(I)-B(I)| <=
      --  In_Cap < Limb_Base, forcing C(I+1) = 0 and A(I) = B(I).
      for I in Limb_Index loop
         pragma Assert (C (I) = 0);
         pragma Assert (A (I) + C (I) = B (I) + Limb_Base * C (I + 1));
         pragma Assert (Limb_Base * C (I + 1) = A (I) - B (I));
         pragma Assert (C (I + 1) = 0);
         pragma Assert (A (I) = B (I));
         pragma Loop_Invariant (C (I + 1) = 0);
         pragma Loop_Invariant (for all J in 0 .. I => A (J) = B (J));
      end loop;
   end Lemma_SVal_Eq_Unique;

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

   procedure Lemma_Pos_Mult_Forces_Sub_Cond
     (A, B : Big_Nat; K : LLI; C : Carry_Array)
   is
      M : constant Big_Nat := B + Smul (K, P_Prime);
   begin
      --  M's limbs: M (I) = B (I) + K * P_Prime (I).  P_Prime is the five-limb
      --  encoding of p; limbs 0..4 are (In_Cap-4, In_Cap, In_Cap, In_Cap,
      --  In_Cap), limbs 5.. are zero.
      pragma Assert (P_Prime (0) = In_Cap - 4);
      pragma Assert
        (P_Prime (1) = In_Cap and then P_Prime (2) = In_Cap
         and then P_Prime (3) = In_Cap and then P_Prime (4) = In_Cap);
      pragma Assert
        (for all J in Limb_Index range 5 .. Max_Limbs - 1 => P_Prime (J) = 0);
      pragma Assert (for all I in Limb_Index => M (I) = B (I) + K * P_Prime (I));

      --  Upper region: A and M are zero for limbs 5.., so the carry chain is
      --  forced to all zero there (from C (Max_Limbs)=0 downward).
      pragma Assert (C (Max_Limbs) = 0);
      for J in reverse 5 .. Max_Limbs - 1 loop
         pragma Assert (A (J) = 0);
         pragma Assert (M (J) = 0);
         pragma Assert (A (J) + C (J) = M (J) + Limb_Base * C (J + 1));
         pragma Assert (C (J) = Limb_Base * C (J + 1));
         pragma Loop_Invariant (for all P2 in J .. Max_Limbs => C (P2) = 0);
      end loop;
      pragma Assert (C (5) = 0);

      --  The five column equations (substituting M (I) = B (I) + K*P_Prime(I)).
      pragma Assert (A (4) + C (4) = B (4) + K * In_Cap + Limb_Base * C (5));
      pragma Assert (A (3) + C (3) = B (3) + K * In_Cap + Limb_Base * C (4));
      pragma Assert (A (2) + C (2) = B (2) + K * In_Cap + Limb_Base * C (3));
      pragma Assert (A (1) + C (1) = B (1) + K * In_Cap + Limb_Base * C (2));
      pragma Assert
        (A (0) + C (0) = B (0) + K * (In_Cap - 4) + Limb_Base * C (1));

      --  Each "intrinsic" column term E_i = K*P_Prime(i) - (A(i)-B(i)) is
      --  non-negative for K >= 1 (K*In_Cap >= In_Cap >= A(i)), hence so is each
      --  carry c4..c1 (a non-negative term plus Limb_Base * (next carry)).
      pragma Assert (B (4) + K * In_Cap - A (4) >= 0);
      pragma Assert (B (3) + K * In_Cap - A (3) >= 0);
      pragma Assert (B (2) + K * In_Cap - A (2) >= 0);
      pragma Assert (B (1) + K * In_Cap - A (1) >= 0);
      pragma Assert (C (4) >= 0);
      pragma Assert (C (3) >= 0);
      pragma Assert (C (2) >= 0);
      pragma Assert (C (1) >= 0);

      --  Top-down forcing. c1 <= Hi_Cap with E1 >= 0 bounds Limb_Base*c2, which
      --  caps c2 below Limb_Base; c2's own column then pins c3 = 0, c3 pins
      --  c4 = 0 and E3 = 0, and c4 = 0 forces K = 1 and A(4) = In_Cap.
      pragma Assert (Limb_Base * C (2) <= Hi_Cap);
      pragma Assert (C (2) <= Hi_Cap / Limb_Base);
      pragma Assert (Limb_Base * C (3) <= C (2));
      pragma Assert (C (3) = 0);
      pragma Assert (C (4) = 0);
      pragma Assert (B (3) + K * In_Cap - A (3) = 0);
      pragma Assert (A (4) = B (4) + K * In_Cap);
      pragma Assert (K = 1);
      pragma Assert (A (4) = In_Cap);
      pragma Assert (A (3) = In_Cap);

      --  Bottom column: c0 = 0 with K = 1 gives Limb_Base*c1 = A(0)-B(0)-(p0),
      --  which is <= 4, so c1 = 0; that pins c2 = 0 and reads off A(1), A(2),
      --  and the low limb bound A(0) >= In_Cap-4 -- exactly Sub_Cond (A).
      pragma Assert (Limb_Base * C (1) = A (0) - B (0) - (In_Cap - 4));
      pragma Assert (Limb_Base * C (1) <= 4);
      pragma Assert (C (1) = 0);
      pragma Assert (C (2) = 0);
      pragma Assert (A (1) = In_Cap);
      pragma Assert (A (2) = In_Cap);
      pragma Assert (A (0) >= In_Cap - 4);
      pragma Assert (Sub_Cond (A));
   end Lemma_Pos_Mult_Forces_Sub_Cond;

   procedure Lemma_Mod_P_Unique (A, B : Big_Nat; K : LLI; C : Carry_Array) is
   begin
      if K = 0 then
         --  Smul (0, P_Prime) = Zero, so the operand is B and exact uniqueness
         --  applies.
         pragma Assert
           (for all I in Limb_Index => Smul (K, P_Prime) (I) = 0);
         pragma Assert (Smul (K, P_Prime) = Zero);
         Lemma_Add_Zero_R (B);
         pragma Assert (B + Smul (K, P_Prime) = B);
         Lemma_SVal_Eq_Unique (A, B, C);
      else
         --  K >= 1: the positive prime multiple forces Sub_Cond (A), which
         --  contradicts the precondition not Sub_Cond (A); A = B holds
         --  vacuously.
         Lemma_Pos_Mult_Forces_Sub_Cond (A, B, K, C);
         pragma Assert (Sub_Cond (A));
      end if;
   end Lemma_Mod_P_Unique;

   procedure Lemma_Smul_Add (K1, K2 : LLI; A : Big_Nat) is
      S1  : constant Big_Nat := Smul (K1, A);
      S2  : constant Big_Nat := Smul (K2, A);
      S12 : constant Big_Nat := Smul (K1 + K2, A);
      Sum : constant Big_Nat := S1 + S2;
   begin
      pragma Assert (for all I in Limb_Index => Sum (I) = S12 (I));
   end Lemma_Smul_Add;

   procedure Lemma_SVal_Cancel_Const (X, Y, M : Big_Nat; C : Carry_Array) is
   begin
      pragma Assert (C (0) = 0);
      pragma Assert (C (Max_Limbs) = 0);
      pragma Assert
        (for all I in Limb_Index =>
           X (I) + C (I) = Y (I) + Limb_Base * C (I + 1));
   end Lemma_SVal_Cancel_Const;

   procedure Lemma_Mod_P_Unique_Gen
     (A, B : Big_Nat; Ka, Kb : LLI; C : Carry_Array)
   is
   begin
      if Kb >= Ka then
         --  B + Kb*p = (B + (Kb-Ka)*p) + Ka*p; cancel the common Ka*p.
         Lemma_Smul_Add (Kb - Ka, Ka, P_Prime);
         Lemma_Bounds_Mono (B, In_Cap, Assoc_Cap);
         pragma Assert
           (In_Bounds (Smul (Kb - Ka, P_Prime), Assoc_Cap));
         pragma Assert (In_Bounds (Smul (Ka, P_Prime), Assoc_Cap));
         Lemma_Add_Assoc (B, Smul (Kb - Ka, P_Prime), Smul (Ka, P_Prime));
         pragma Assert
           (B + Smul (Kb, P_Prime)
            = (B + Smul (Kb - Ka, P_Prime)) + Smul (Ka, P_Prime));
         pragma Assert (In_Bounds (B + Smul (Kb - Ka, P_Prime), Add_Cap));
         pragma Assert
           (SVal_Eq
              (A + Smul (Ka, P_Prime),
               (B + Smul (Kb - Ka, P_Prime)) + Smul (Ka, P_Prime),
               C));
         Lemma_SVal_Cancel_Const
           (A, B + Smul (Kb - Ka, P_Prime), Smul (Ka, P_Prime), C);
         Lemma_Mod_P_Unique (A, B, Kb - Ka, C);
      else
         --  A + Ka*p = (A + (Ka-Kb)*p) + Kb*p; flip sides and cancel Kb*p.
         --  Establish In_Bounds for both sides before SVal_Sym:
         Lemma_Bounds_Mono (A, In_Cap, Assoc_Cap);
         Lemma_Bounds_Mono (B, In_Cap, Assoc_Cap);
         pragma Assert (In_Bounds (Smul (Ka, P_Prime), Assoc_Cap));
         pragma Assert (In_Bounds (Smul (Kb, P_Prime), Assoc_Cap));
         pragma Assert (In_Bounds (A + Smul (Ka, P_Prime), Add_Cap));
         pragma Assert (In_Bounds (B + Smul (Kb, P_Prime), Add_Cap));
         Lemma_SVal_Sym
           (A + Smul (Ka, P_Prime), B + Smul (Kb, P_Prime), C);
         Lemma_Smul_Add (Ka - Kb, Kb, P_Prime);
         Lemma_Bounds_Mono (A, In_Cap, Assoc_Cap);
         pragma Assert
           (In_Bounds (Smul (Ka - Kb, P_Prime), Assoc_Cap));
         pragma Assert (In_Bounds (Smul (Kb, P_Prime), Assoc_Cap));
         Lemma_Add_Assoc (A, Smul (Ka - Kb, P_Prime), Smul (Kb, P_Prime));
         pragma Assert
           (A + Smul (Ka, P_Prime)
            = (A + Smul (Ka - Kb, P_Prime)) + Smul (Kb, P_Prime));
         pragma Assert (In_Bounds (A + Smul (Ka - Kb, P_Prime), Add_Cap));
         pragma Assert
           (SVal_Eq
              (B + Smul (Kb, P_Prime),
               (A + Smul (Ka - Kb, P_Prime)) + Smul (Kb, P_Prime),
               Neg_Carry (C)));
         Lemma_SVal_Cancel_Const
           (B, A + Smul (Ka - Kb, P_Prime), Smul (Kb, P_Prime),
            Neg_Carry (C));
         Lemma_Mod_P_Unique (B, A, Ka - Kb, Neg_Carry (C));
      end if;
   end Lemma_Mod_P_Unique_Gen;

   function Normalize (B : Big_Nat) return Norm_Result is
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

      --  Congruence: B is value-equal (SVal_Eq) to S3 + PM (PM a prime
      --  multiple), so B is congruent to S3 mod p.
      declare
         PM    : constant Big_Nat :=
           Smul (S2 (5), P_Prime) + Smul (S1 (5), P_Prime);
         KM    : constant LLI := S2 (5) + S1 (5);
         Ch12  : constant Carry_Array :=
           Add_Carry
             (Add_Carry (Sweep5_Chain (B), Neg_Carry (Fold_Chain (S1 (5)))),
              Add_Carry (Sweep5_Chain (R1), Neg_Carry (Fold_Chain (S2 (5)))));
         Chain : constant Carry_Array :=
           Add_Carry (Ch12, Sweep5_Chain (R2));
      begin
         Lemma_Two_Round_Cong
           (B, S1, R1, S2, Sweep5_Chain (B), Sweep5_Chain (R1));
         --  SVal_Eq (B, Fold_Plus_P (S2) + Smul (S1 (5), P_Prime), Ch12)

         --  PM = Smul (S2 (5), P) + Smul (S1 (5), P): each Smul limb is
         --  S (5) * P_Prime (i) <= 2 In_Cap, so PM <= 4 In_Cap (well within
         --  Add_Cap; needed because "+" does not carry In_Bounds).
         pragma Assert
           (for all I in Limb_Index =>
              Smul (S2 (5), P_Prime) (I) <= 2 * In_Cap);
         pragma Assert
           (for all I in Limb_Index =>
              Smul (S1 (5), P_Prime) (I) <= 2 * In_Cap);
         pragma Assert (for all I in Limb_Index => PM (I) <= 4 * In_Cap);
         pragma Assert (In_Bounds (PM, Add_Cap));
         Lemma_Bounds_Mono (B, Prod_Cap, Add_Cap);

         --  Fold_Plus_P (S2) + Smul (S1 (5), P) = R2 + PM (Fold_Plus_P_Eq +
         --  associativity), so the round result is B =val R2 + PM.
         Lemma_Fold_Plus_P_Eq (S2);
         Lemma_Add_Assoc (R2, Smul (S2 (5), P_Prime), Smul (S1 (5), P_Prime));
         pragma Assert
           (Fold_Plus_P (S2) + Smul (S1 (5), P_Prime) = R2 + PM);
         pragma Assert (SVal_Eq (B, R2 + PM, Ch12));

         --  Final sweep R2 =val S3; add PM to both sides and compose.
         Lemma_Sweep5 (R2);
         Lemma_Val_To_SVal (R2, S3, Sweep5_Chain (R2));
         pragma Assert (for all I in Limb_Index => S3 (I) + PM (I) <= 5 * In_Cap);
         pragma Assert (In_Bounds (S3 + PM, Add_Cap));
         Lemma_SVal_Add_Const (R2, S3, PM, Sweep5_Chain (R2));
         --  SVal_Eq (R2 + PM, S3 + PM, Sweep5_Chain (R2))

         --  Combined chain within Hi_Cap: Ch12 small (CA, CB <=
         --  Conv_Carry_Cap, Fold_Chains <= 2); Sweep5_Chain (R2) <=
         --  Conv_Carry_Cap.
         Lemma_Sweep5_Chain_Tight (B);
         Lemma_Sweep5_Chain_Tight (R1);
         Lemma_Sweep5_Chain_Tight (R2);
         pragma Assert
           (for all J in Carry_Array'Range =>
              Sweep5_Chain (R2) (J) in 0 .. Conv_Carry_Cap);
         pragma Assert (SC_Bounded (Add_Carry (Ch12, Sweep5_Chain (R2))));
         Lemma_SVal_Trans (B, R2 + PM, S3 + PM, Ch12, Sweep5_Chain (R2));
         --  SVal_Eq (B, S3 + PM, Chain)

         --  PM is exactly KM copies of p: Smul (S2(5), p) + Smul (S1(5), p) =
         --  Smul (S2(5)+S1(5), p). Both carries are <= 2 (Acc_Carry), so
         --  KM <= 4 <= Mult_Cap.
         pragma Assert (S1 (5) in 0 .. 2);
         pragma Assert (S2 (5) in 0 .. 2);
         Lemma_Smul_Add (S2 (5), S1 (5), P_Prime);
         pragma Assert (PM = Smul (KM, P_Prime));
         pragma Assert (KM in 0 .. 4);

         --  Tight chain bound: Ch12 = two sweep chains (<= Conv_Carry_Cap)
         --  minus two fold chains (each entry <= 2), so |Ch12| <= 2**33;
         --  Chain adds one more sweep chain, so |Chain| <= 3*Conv_Carry_Cap
         --  < Cong_Cap = 2**34.
         pragma Assert
           (for all J in Carry_Array'Range =>
              Sweep5_Chain (B) (J) in 0 .. Conv_Carry_Cap);
         pragma Assert
           (for all J in Carry_Array'Range =>
              Sweep5_Chain (R1) (J) in 0 .. Conv_Carry_Cap);
         pragma Assert
           (for all J in Carry_Array'Range =>
              Fold_Chain (S1 (5)) (J) in 0 .. 2);
         pragma Assert
           (for all J in Carry_Array'Range =>
              Fold_Chain (S2 (5)) (J) in 0 .. 2);
         pragma Assert
           (for all J in Carry_Array'Range => Ch12 (J) in -Cong_Cap .. Cong_Cap);
         pragma Assert
           (for all J in Carry_Array'Range =>
              Chain (J) in -Cong_Cap .. Cong_Cap);
         return (Val => S3, PMult => PM, KMult => KM, Cn => Chain);
      end;
   end Normalize;

   procedure Lemma_Canonical_Cong
     (B : Big_Nat; Kc : out LLI; Cc : out Carry_Array)
   is
      N   : constant Norm_Result := Normalize (B);
      Val : constant Big_Nat := N.Val;
      Kr  : constant LLI := (if Sub_Cond (Val) then 1 else 0);
   begin
      --  Canonical (B) = Reduce_Canonical (Val) = Subtract_P5_Out (Val): Val is
      --  reduced (Normalize's output), so its sweep is the identity.
      Lemma_Reduced_No_Carry (Val);
      pragma Assert (Canonical (B) = Subtract_P5_Out (Val));

      --  Val = Subtract_P5_Out (Val) + Sub_Sel_P (Val), exactly (zero chain),
      --  and Sub_Sel_P (Val) is Kr copies of p (Kr in {0,1}).
      Lemma_Subtract_P5 (Val);
      pragma Assert (Subtract_P5_Out (Val) + Sub_Sel_P (Val) = Val);
      pragma Assert (Smul (1, P_Prime) = P_Prime);
      pragma Assert (Smul (0, P_Prime) = Zero);
      pragma Assert (Sub_Sel_P (Val) = Smul (Kr, P_Prime));
      pragma Assert (Canonical (B) + Smul (Kr, P_Prime) = Val);

      --  Fold Normalize's KMult copies and the final Kr into one multiple.
      Kc := Kr + N.KMult;
      Cc := N.Cn;
      Lemma_Bounds_Mono (Canonical (B), In_Cap, Assoc_Cap);
      pragma Assert (In_Bounds (Smul (Kr, P_Prime), Assoc_Cap));
      pragma Assert (In_Bounds (Smul (N.KMult, P_Prime), Assoc_Cap));
      Lemma_Add_Assoc
        (Canonical (B), Smul (Kr, P_Prime), Smul (N.KMult, P_Prime));
      Lemma_Smul_Add (Kr, N.KMult, P_Prime);
      pragma Assert (Val + N.PMult = Canonical (B) + Smul (Kc, P_Prime));
      pragma Assert (SVal_Eq (B, Canonical (B) + Smul (Kc, P_Prime), Cc));
   end Lemma_Canonical_Cong;

   procedure Lemma_Canonical_Unique
     (X, Y : Big_Nat; Kin : LLI; C : Carry_Array)
   is
      KcX, KcY : LLI;
      CcX, CcY : Carry_Array;
   begin
      Lemma_Canonical_Cong (X, KcX, CcX);   --  X == CX + Smul (KcX, p)
      Lemma_Canonical_Cong (Y, KcY, CcY);   --  Y == CY + Smul (KcY, p)
      declare
         CX  : constant Big_Nat := Canonical (X);
         CY  : constant Big_Nat := Canonical (Y);
         SKX : constant Big_Nat := Smul (KcX, P_Prime);
         SKY : constant Big_Nat := Smul (KcY, P_Prime);
         SKI : constant Big_Nat := Smul (Kin, P_Prime);
         SX  : constant Big_Nat := CX + SKX;
         SY  : constant Big_Nat := CY + SKY;
         YK  : constant Big_Nat := Y + SKI;
         SYK : constant Big_Nat := SY + SKI;
         NCX : constant Carry_Array := Neg_Carry (CcX);
         Ch2 : constant Carry_Array := Add_Carry (NCX, C);
         Net : constant Carry_Array := Add_Carry (Ch2, CcY);
      begin
         --  In-bounds nudges (the operands are reduced + small multiples).
         --  Smul-Post link through the constants, then the small-K bounds
         --  (KcX, KcY <= 5; Kin <= 4), mirroring Normalize's pattern.
         Lemma_Bounds_Mono (X, Mul_Cap, Add_Cap);
         pragma Assert (for all I in Limb_Index => P_Prime (I) <= In_Cap);
         pragma Assert (for all I in Limb_Index => SKX (I) = KcX * P_Prime (I));
         pragma Assert (for all I in Limb_Index => SKY (I) = KcY * P_Prime (I));
         pragma Assert (for all I in Limb_Index => SKI (I) = Kin * P_Prime (I));
         pragma Assert (for all I in Limb_Index => SKX (I) <= 5 * In_Cap);
         pragma Assert (for all I in Limb_Index => SKY (I) <= 5 * In_Cap);
         pragma Assert (for all I in Limb_Index => SKI (I) <= 4 * In_Cap);
         pragma Assert (In_Bounds (SX, Add_Cap));
         pragma Assert (In_Bounds (SY, Add_Cap));
         pragma Assert (for all I in Limb_Index => SYK (I) <= 10 * In_Cap);
         pragma Assert (In_Bounds (SYK, Add_Cap));

         --  CX + Smul (KcX, p) == X (Sym of Canonical_Cong on X), then
         --  == Y + Smul (Kin, p) (input), then == CY + Smul (KcY, p) + Kin*p.
         Lemma_SVal_Sym (X, SX, CcX);
         pragma Assert
           (for all J in Carry_Array'Range => NCX (J) in -Cong_Cap .. Cong_Cap);
         pragma Assert
           (for all J in Carry_Array'Range =>
              Ch2 (J) in -(2 * Cong_Cap) .. 2 * Cong_Cap);
         pragma Assert (SC_Bounded (Ch2));
         Lemma_SVal_Trans (SX, X, YK, NCX, C);          --  SVal_Eq (SX, YK, Ch2)

         Lemma_SVal_Add_Const (Y, SY, SKI, CcY);        --  SVal_Eq (YK, SYK, CcY)
         pragma Assert
           (for all J in Carry_Array'Range =>
              Net (J) in -(3 * Cong_Cap) .. 3 * Cong_Cap);
         pragma Assert (SC_Bounded (Net));
         Lemma_SVal_Trans (SX, YK, SYK, Ch2, CcY);      --  SVal_Eq (SX, SYK, Net)

         --  SYK = (CY + Smul (KcY, p)) + Smul (Kin, p) = CY + Smul (KcY+Kin, p).
         Lemma_Bounds_Mono (CY, In_Cap, Assoc_Cap);
         pragma Assert (In_Bounds (SKY, Assoc_Cap));
         pragma Assert (In_Bounds (SKI, Assoc_Cap));
         Lemma_Add_Assoc (CY, SKY, SKI);
         Lemma_Smul_Add (KcY, Kin, P_Prime);
         pragma Assert (SYK = CY + Smul (KcY + Kin, P_Prime));
         pragma Assert
           (SVal_Eq (SX, CY + Smul (KcY + Kin, P_Prime), Net));

         --  Both CX, CY are canonical (< p); the residual multiples cancel.
         Lemma_Mod_P_Unique_Gen (CX, CY, KcX, KcY + Kin, Net);
         pragma Assert (Canonical (X) = Canonical (Y));
      end;
   end Lemma_Canonical_Unique;

   procedure Lemma_Canonical_Unique_Gen
     (X, Y : Big_Nat; Kx, Ky : LLI; C : Carry_Array)
   is
      KcX, KcY : LLI;
      CcX, CcY : Carry_Array;
   begin
      Lemma_Canonical_Cong (X, KcX, CcX);   --  X == CX + Smul (KcX, p)
      Lemma_Canonical_Cong (Y, KcY, CcY);   --  Y == CY + Smul (KcY, p)
      declare
         CX   : constant Big_Nat := Canonical (X);
         CY   : constant Big_Nat := Canonical (Y);
         SKcX : constant Big_Nat := Smul (KcX, P_Prime);
         SKcY : constant Big_Nat := Smul (KcY, P_Prime);
         SKx  : constant Big_Nat := Smul (Kx, P_Prime);
         SKy  : constant Big_Nat := Smul (Ky, P_Prime);
         XKx  : constant Big_Nat := X + SKx;
         YKy  : constant Big_Nat := Y + SKy;
         SX   : constant Big_Nat := CX + SKcX;
         SXx  : constant Big_Nat := SX + SKx;          --  = CX + (KcX+Kx)*p
         SYc  : constant Big_Nat := CY + SKcY;
         SYy  : constant Big_Nat := SYc + SKy;         --  = CY + (KcY+Ky)*p
         NCX  : constant Carry_Array := Neg_Carry (CcX);
         Ch2  : constant Carry_Array := Add_Carry (NCX, C);
         Net  : constant Carry_Array := Add_Carry (Ch2, CcY);
      begin
         --  In-bounds nudges (reduced bases + small multiples).
         Lemma_Bounds_Mono (X, Mul_Cap, Add_Cap);
         pragma Assert (for all I in Limb_Index => P_Prime (I) <= In_Cap);
         pragma Assert (for all I in Limb_Index => SKcX (I) = KcX * P_Prime (I));
         pragma Assert (for all I in Limb_Index => SKcY (I) = KcY * P_Prime (I));
         pragma Assert (for all I in Limb_Index => SKx (I) = Kx * P_Prime (I));
         pragma Assert (for all I in Limb_Index => SKy (I) = Ky * P_Prime (I));
         pragma Assert (In_Bounds (SKcX, Add_Cap));
         pragma Assert (In_Bounds (SKcY, Add_Cap));
         pragma Assert (In_Bounds (SKx, Add_Cap));
         pragma Assert (In_Bounds (SKy, Add_Cap));
         pragma Assert (In_Bounds (SX, Add_Cap));
         pragma Assert (In_Bounds (SYc, Add_Cap));
         pragma Assert (In_Bounds (SXx, Add_Cap));
         pragma Assert (In_Bounds (SYy, Add_Cap));

         --  CX + (KcX)*p == X (sym), + Kx*p both sides; then input; then Y side.
         Lemma_SVal_Sym (X, SX, CcX);                  --  SVal_Eq (SX, X, NCX)
         pragma Assert
           (for all J in Carry_Array'Range => NCX (J) in -Cong_Cap .. Cong_Cap);
         Lemma_SVal_Add_Const (SX, X, SKx, NCX);       --  SVal_Eq (SXx, XKx, NCX)
         pragma Assert
           (for all J in Carry_Array'Range =>
              Ch2 (J) in -(3 * Cong_Cap) .. 3 * Cong_Cap);
         pragma Assert (SC_Bounded (Ch2));
         Lemma_SVal_Trans (SXx, XKx, YKy, NCX, C);     --  SVal_Eq (SXx, YKy, Ch2)

         Lemma_SVal_Add_Const (Y, SYc, SKy, CcY);      --  SVal_Eq (YKy, SYy, CcY)
         pragma Assert
           (for all J in Carry_Array'Range =>
              Net (J) in -(4 * Cong_Cap) .. 4 * Cong_Cap);
         pragma Assert (SC_Bounded (Net));
         Lemma_SVal_Trans (SXx, YKy, SYy, Ch2, CcY);   --  SVal_Eq (SXx, SYy, Net)

         --  SXx = CX + Smul (KcX+Kx, p); SYy = CY + Smul (KcY+Ky, p).
         Lemma_Bounds_Mono (CX, In_Cap, Assoc_Cap);
         Lemma_Bounds_Mono (CY, In_Cap, Assoc_Cap);
         pragma Assert (In_Bounds (SKcX, Assoc_Cap));
         pragma Assert (In_Bounds (SKx, Assoc_Cap));
         pragma Assert (In_Bounds (SKcY, Assoc_Cap));
         pragma Assert (In_Bounds (SKy, Assoc_Cap));
         Lemma_Add_Assoc (CX, SKcX, SKx);
         Lemma_Smul_Add (KcX, Kx, P_Prime);
         pragma Assert (SXx = CX + Smul (KcX + Kx, P_Prime));
         Lemma_Add_Assoc (CY, SKcY, SKy);
         Lemma_Smul_Add (KcY, Ky, P_Prime);
         pragma Assert (SYy = CY + Smul (KcY + Ky, P_Prime));
         pragma Assert
           (SVal_Eq
              (CX + Smul (KcX + Kx, P_Prime),
               CY + Smul (KcY + Ky, P_Prime), Net));

         Lemma_Mod_P_Unique_Gen (CX, CY, KcX + Kx, KcY + Ky, Net);
         pragma Assert (Canonical (X) = Canonical (Y));
      end;
   end Lemma_Canonical_Unique_Gen;

   function Field_Add (A, N : Big_Nat) return Big_Nat is
      S : constant Big_Nat := A + N;
   begin
      --  A, N reduced => S = A + N has limbs <= 2*In_Cap < Mul_Cap, zero from
      --  5; Canonical reduces it directly.
      pragma Assert (for all I in Limb_Index => S (I) <= 2 * In_Cap);
      pragma Assert (In_Bounds (S, Mul_Cap));
      pragma Assert
        (for all I in Limb_Index range 5 .. Max_Limbs - 1 => S (I) = 0);
      return Canonical (S);
   end Field_Add;

   function Field_Mul (A, R : Big_Nat) return Big_Nat is
      Conv : constant Big_Nat := A * R;
      S    : constant Big_Nat := Sweep9_Out (Conv);
      R1   : constant Big_Nat := Fold_High_9_Out (S);
   begin
      --  Conv = A*R: nine convolution columns (<= 5*Two_Pow_54 each), zero from
      --  limb 9.  "*" Post gives Conv (K) = Mul_Col (..) <= (K+1)*Two_Pow_54;
      --  Lemma_Mul5_Cols gives the zero-from-9.
      Lemma_Mul5_Cols (A, R, Conv);
      pragma Assert
        (for all K in Limb_Index range 9 .. Max_Limbs - 1 => Conv (K) = 0);
      pragma Assert
        (for all K in Limb_Index =>
           Conv (K) <= LLI (K + 1) * Two_Pow_54);
      pragma Assert (In_Bounds (Conv, Prod_Cap));
      pragma Assert (In_Bounds (Conv, Conv_Col_Cap));

      --  Sweep9 then Fold_High_9: S (0..8) reduced, S (9) = top carry <=
      --  Fold9_Top_Cap (Sweep9_Conv); R1 = Fold_High_9_Out (S) is
      --  Round1_Out_Cap-bounded and zero from 5.
      Lemma_Sweep9_Conv (Conv);
      pragma Assert
        (for all I in Limb_Index range 0 .. 8 => S (I) in 0 .. In_Cap);
      pragma Assert (S (9) in 0 .. Fold9_Top_Cap);
      pragma Assert
        (for all I in Limb_Index range 10 .. Max_Limbs - 1 => S (I) = 0);
      pragma Assert (In_Bounds (R1, Round1_Out_Cap));
      pragma Assert
        (for all I in Limb_Index range 5 .. Max_Limbs - 1 => R1 (I) = 0);

      --  Carry_Model (R1): establish its Pre (Carry_In_Cap, Sweep5 top carry),
      --  then reduce to canonical.
      Lemma_Bounds_Mono (R1, Round1_Out_Cap, Carry_In_Cap);
      Lemma_Sweep5_Tight_Carry (R1);
      return Canonical (Carry_Model (R1));
   end Field_Mul;

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

   procedure Lemma_Carry_Mod_P (B : Big_Nat; K : out LLI; C : out Carry_Array) is
      T    : constant Big_Nat     := Sweep5_Out (B);
      FO   : constant Big_Nat     := Fold_Out (T);
      CM   : constant Big_Nat     := Carry_Model (B);
      D1   : constant Carry_Array := Sweep5_Chain (B);
      SK   : constant Big_Nat     := Smul (T (5), P_Prime);
      SCFO : constant Carry_Array := Step_Carry (FO, 0);
      Ch1  : constant Carry_Array :=
        Add_Carry (D1, Neg_Carry (Fold_Chain (T (5))));
      FOSK : constant Big_Nat := FO + SK;
      CMSK : constant Big_Nat := CM + SK;
   begin
      Lemma_Bounds_Mono (B, Mul_Cap, Carry_In_Cap);
      Lemma_Sweep5_Acc_Carry (B);          --  T (5) <= 2
      K := T (5);

      --  Sweep5 output is reduced; Fold_Out limb 0 stays small (T (5) <= 2).
      pragma Assert
        (for all I in Limb_Index range 0 .. 4 => T (I) in 0 .. In_Cap);
      pragma Assert (T (5) in 0 .. 2);
      pragma Assert
        (for all I in Limb_Index range 6 .. Max_Limbs - 1 => T (I) = 0);
      pragma Assert (FO (0) <= In_Cap + 10);
      pragma Assert (In_Bounds (FO, Prod_Cap));

      --  Step 1: B == Fold_Plus_P (T) == FO + Smul (K, P).
      Lemma_Carry_Fold (B);
      Lemma_Fold_Plus_P_Eq (T);
      pragma Assert (Fold_Plus_P (T) = FOSK);
      pragma Assert (SVal_Eq (B, FOSK, Ch1));

      --  Step 2: FO == Carry_Model (B) exactly (the normalising Step_Out).
      pragma Assert (CM = Step_Out (FO, 0));
      Lemma_Carry_Step (FO, 0);
      pragma Assert (Val_Eq (FO, CM, SCFO));
      Lemma_Val_To_SVal (FO, CM, SCFO);

      --  Step 3: add Smul (K, P) to both, then transitivity.
      pragma Assert (In_Bounds (SK, Add_Cap));
      pragma Assert (for all I in Limb_Index => SK (I) = T (5) * P_Prime (I));
      pragma Assert (for all I in Limb_Index => SK (I) <= 2 * In_Cap);
      pragma Assert (for all I in Limb_Index => FOSK (I) <= 3 * In_Cap + 10);
      pragma Assert (In_Bounds (FOSK, Add_Cap));
      pragma Assert (In_Bounds (CMSK, Add_Cap));
      Lemma_SVal_Add_Const (FO, CM, SK, SCFO);

      --  Chain bounds: D1 <= Conv_Carry_Cap, Fold_Chain (K) <= 2,
      --  Step_Carry (FO,0)(1) = Hi26 (FO(0)) <= 1, so C is tight.
      Lemma_Sweep5_Chain_Tight (B);
      pragma Assert
        (for all J in Carry_Array'Range => D1 (J) in 0 .. Conv_Carry_Cap);
      pragma Assert
        (for all J in Carry_Array'Range => Fold_Chain (T (5)) (J) in 0 .. 2);
      pragma Assert (Hi26 (FO (0)) <= 1);
      pragma Assert (for all J in Carry_Array'Range => SCFO (J) in 0 .. 1);
      pragma Assert
        (for all J in Carry_Array'Range => Ch1 (J) in -2 .. Conv_Carry_Cap);
      C := Add_Carry (Ch1, SCFO);
      pragma Assert
        (for all J in Carry_Array'Range => C (J) in -Cong_Cap .. Cong_Cap);
      Lemma_Bounds_Mono (B, Mul_Cap, Add_Cap);
      Lemma_SVal_Trans (B, FOSK, CMSK, Ch1, SCFO);
      pragma Assert (SVal_Eq (B, Carry_Model (B) + Smul (K, P_Prime), C));
   end Lemma_Carry_Mod_P;

   procedure Lemma_Carry_Model_Lt (B : Big_Nat) is
      S  : constant Big_Nat := Sweep5_Out (B);
      FO : constant Big_Nat := Fold_Out (S);
      CM : constant Big_Nat := Carry_Model (B);
   begin
      --  S reduced (limbs 0..4 <= In_Cap), S (5) <= Fold_C_Cap (Pre).
      pragma Assert
        (for all I in Limb_Index range 0 .. 4 => S (I) in 0 .. In_Cap);
      pragma Assert (S (5) <= Fold_C_Cap);

      --  FO = Fold_Out (S): limb0 = S(0)+5*S(5) <= In_Cap + 5*Fold_C_Cap,
      --  limbs 1..4 reduced.
      pragma Assert (FO (0) <= In_Cap + 5 * Fold_C_Cap);
      pragma Assert
        (for all I in Limb_Index range 1 .. 4 => FO (I) in 0 .. In_Cap);

      --  CM = Step_Out (FO, 0): limb0 < 2**26, limb1 = FO(1)+Hi26(FO(0)), the
      --  carry Hi26(FO(0)) < 2**12 so limb1 < 2**27; limbs 2..4 reduced.
      pragma Assert (CM = Step_Out (FO, 0));
      pragma Assert (CM (0) < Limb_Base);
      pragma Assert (Hi26 (FO (0)) < 2**12);
      pragma Assert (CM (1) = FO (1) + Hi26 (FO (0)));
      pragma Assert (CM (1) < 2**27);
      pragma Assert
        (for all I in Limb_Index range 2 .. 4 => CM (I) in 0 .. In_Cap);
      pragma Assert
        (for all I in Limb_Index range 5 .. Max_Limbs - 1 => CM (I) = 0);
      pragma Assert (In_Bounds (CM, Prod_Cap));

      --  Sweep5 of CM: c0 = 0 (CM(0) < 2**26); each later carry <= 1 because
      --  the running limb stays < 2**27. So the carry out of limb 4 is <= 1.
      pragma Assert (Sw_C0 (CM) = 0);
      pragma Assert (Sw_C1 (CM) <= 1);
      pragma Assert (Sw_C2 (CM) <= 1);
      pragma Assert (Sw_C3 (CM) <= 1);
      pragma Assert (Sw_C4 (CM) <= 1);
      pragma Assert (Sweep5_Out (CM) (5) = Sw_C4 (CM));
   end Lemma_Carry_Model_Lt;

   procedure Lemma_Carry_Mod_P_Wide
     (B : Big_Nat; K : out LLI; C : out Carry_Array)
   is
      T    : constant Big_Nat     := Sweep5_Out (B);
      FO   : constant Big_Nat     := Fold_Out (T);
      CM   : constant Big_Nat     := Carry_Model (B);
      D1   : constant Carry_Array := Sweep5_Chain (B);
      SK   : constant Big_Nat     := Smul (T (5), P_Prime);
      SCFO : constant Carry_Array := Step_Carry (FO, 0);
      Ch1  : constant Carry_Array :=
        Add_Carry (D1, Neg_Carry (Fold_Chain (T (5))));
      FOSK : constant Big_Nat := FO + SK;
      CMSK : constant Big_Nat := CM + SK;
   begin
      Lemma_Bounds_Mono (B, Round1_Out_Cap, Carry_In_Cap);
      K := T (5);

      --  T = Sweep5_Out (B): limbs 0..4 reduced, T (5) = K <= Conv_Carry_Cap
      --  (Pre). Fold_Out limb 0 = T(0)+5*K stays well below Prod_Cap.
      pragma Assert
        (for all I in Limb_Index range 0 .. 4 => T (I) in 0 .. In_Cap);
      pragma Assert (T (5) in 0 .. Conv_Carry_Cap);
      pragma Assert
        (for all I in Limb_Index range 6 .. Max_Limbs - 1 => T (I) = 0);
      pragma Assert (FO (0) <= In_Cap + 5 * Conv_Carry_Cap);
      pragma Assert (In_Bounds (FO, Prod_Cap));

      --  Step 1: B == Fold_Plus_P (T) == FO + Smul (K, P).
      Lemma_Carry_Fold (B);
      Lemma_Fold_Plus_P_Eq (T);
      pragma Assert (Fold_Plus_P (T) = FOSK);
      pragma Assert (SVal_Eq (B, FOSK, Ch1));
      --  FOSK = Fold_Plus_P (T) is In_Bounds (Add_Cap) by Fold_Plus_P's Post --
      --  no need to bound the (large-K) Smul term directly.
      pragma Assert (In_Bounds (FOSK, Add_Cap));
      pragma Assert
        (for all I in Limb_Index =>
           FOSK (I) <= In_Cap + 5 * Fold_C_Cap + Fold_C_Cap * In_Cap);

      --  Step 2: FO == Carry_Model (B) exactly (the normalising Step_Out).
      pragma Assert (CM = Step_Out (FO, 0));
      Lemma_Carry_Step (FO, 0);
      pragma Assert (Val_Eq (FO, CM, SCFO));
      Lemma_Val_To_SVal (FO, CM, SCFO);

      --  Step 3: CMSK = CM + SK differs from FOSK = FO + SK only in limbs 0,1
      --  (Step_Out): CMSK(I) <= FOSK(I) + Hi26(FO(0)). SK cancels, so no
      --  large-K Smul bound is needed; In_Bounds (CMSK) follows.
      pragma Assert (In_Bounds (SK, Add_Cap));
      pragma Assert (Hi26 (FO (0)) <= 2**9);
      pragma Assert
        (for all I in Limb_Index => CMSK (I) <= FOSK (I) + Hi26 (FO (0)));
      pragma Assert (In_Bounds (CMSK, Add_Cap));
      Lemma_SVal_Add_Const (FO, CM, SK, SCFO);

      --  Chain: D1 <= Conv_Carry_Cap (Sweep5_Chain_Tight), Fold_Chain (K) <= K
      --  <= Conv_Carry_Cap, Step_Carry (FO,0)(1) = Hi26 (FO(0)) <= 2**9. So C
      --  stays within Cong_Cap.
      Lemma_Sweep5_Chain_Tight (B);
      pragma Assert
        (for all J in Carry_Array'Range => D1 (J) in 0 .. Conv_Carry_Cap);
      pragma Assert
        (for all J in Carry_Array'Range =>
           Fold_Chain (T (5)) (J) in 0 .. Conv_Carry_Cap);
      pragma Assert
        (for all J in Carry_Array'Range => SCFO (J) in 0 .. 2**9);
      pragma Assert
        (for all J in Carry_Array'Range =>
           Ch1 (J) in -Conv_Carry_Cap .. Conv_Carry_Cap);
      C := Add_Carry (Ch1, SCFO);
      pragma Assert
        (for all J in Carry_Array'Range => C (J) in -Cong_Cap .. Cong_Cap);
      Lemma_Bounds_Mono (B, Round1_Out_Cap, Add_Cap);
      Lemma_SVal_Trans (B, FOSK, CMSK, Ch1, SCFO);
      pragma Assert (SVal_Eq (B, Carry_Model (B) + Smul (K, P_Prime), C));
   end Lemma_Carry_Mod_P_Wide;

   procedure Lemma_Field_Add_Bridge (Ab, Nb, Xr : Big_Nat) is
      Sum : constant Big_Nat := Ab + Nb;
      K1  : LLI;
      C1  : Carry_Array;
      Kc  : LLI;
      Cc  : Carry_Array;
   begin
      --  X side: Sum == Carry_Model (Sum) + K1*p == Xr + K1*p.
      Lemma_Carry_Mod_P_Wide (Sum, K1, C1);
      pragma Assert (Xr = Carry_Model (Sum));
      pragma Assert (K1 in 0 .. Conv_Carry_Cap);

      --  Y side: Ab == Canonical (Ab) + Kc*p.
      Lemma_Canonical_Cong (Ab, Kc, Cc);

      declare
         CanAb : constant Big_Nat     := Canonical (Ab);
         SK1   : constant Big_Nat     := Smul (K1, P_Prime);
         SKc   : constant Big_Nat     := Smul (Kc, P_Prime);
         Y     : constant Big_Nat     := CanAb + Nb;
         RhsY  : constant Big_Nat     := CanAb + SKc;
         XK1   : constant Big_Nat     := Xr + SK1;
         YKc   : constant Big_Nat     := Y + SKc;
         NC1   : constant Carry_Array := Neg_Carry (C1);
         Cbr   : constant Carry_Array := Add_Carry (NC1, Cc);
      begin
         --  Shapes of X, Y for Canonical_Unique_Gen.
         pragma Assert (In_Bounds (Y, Mul_Cap));
         pragma Assert
           (for all I in Limb_Index range 5 .. Max_Limbs - 1 => Y (I) = 0);

         --  Smul-post links + in-bounds (small Kc, K1 <= Conv_Carry_Cap).
         pragma Assert (for all I in Limb_Index => P_Prime (I) <= In_Cap);
         pragma Assert (for all I in Limb_Index => SK1 (I) = K1 * P_Prime (I));
         pragma Assert (for all I in Limb_Index => SKc (I) = Kc * P_Prime (I));
         pragma Assert (In_Bounds (SK1, Add_Cap));
         pragma Assert (In_Bounds (SKc, Add_Cap));
         pragma Assert (In_Bounds (RhsY, Add_Cap));
         pragma Assert (In_Bounds (XK1, Add_Cap));
         pragma Assert (In_Bounds (YKc, Add_Cap));

         --  Y side congruence: add Nb to both sides of Canonical_Cong, then
         --  realign (CanAb + SKc) + Nb == (CanAb + Nb) + SKc.
         pragma Assert (SVal_Eq (Ab, RhsY, Cc));
         Lemma_SVal_Add_Const (Ab, RhsY, Nb, Cc);   --  SVal_Eq (Sum, RhsY+Nb, Cc)
         pragma Assert (RhsY + Nb = YKc);
         pragma Assert (SVal_Eq (Sum, YKc, Cc));

         --  X side: SVal_Eq (Sum, XK1, C1); flip then compose.
         pragma Assert (SVal_Eq (Sum, XK1, C1));
         Lemma_SVal_Sym (Sum, XK1, C1);             --  SVal_Eq (XK1, Sum, NC1)
         pragma Assert
           (for all J in Carry_Array'Range => NC1 (J) in -Cong_Cap .. Cong_Cap);
         pragma Assert
           (for all J in Carry_Array'Range =>
              Cbr (J) in -(2 * Cong_Cap) .. 2 * Cong_Cap);
         pragma Assert (SC_Bounded (Cbr));
         Lemma_SVal_Trans (XK1, Sum, YKc, NC1, Cc); --  SVal_Eq (XK1, YKc, Cbr)

         --  Two-sided uniqueness: Canonical (Xr) = Canonical (Y).
         pragma Assert (K1 in 0 .. Mult_Cap - 6);
         pragma Assert (Kc in 0 .. Mult_Cap - 6);
         Lemma_Canonical_Unique_Gen (Xr, Y, K1, Kc, Cbr);
         pragma Assert (Canonical (Xr) = Canonical (Y));

         --  Field_Add (CanAb, Nb) = Canonical (CanAb + Nb) = Canonical (Y).
         pragma Assert (Field_Add (CanAb, Nb) = Canonical (Y));
      end;
   end Lemma_Field_Add_Bridge;

end Tls_Core.Ghost_Bignum;
