pragma Ada_2022;

package body Tls_Core.Ghost_Bignum.Value
  with SPARK_Mode
is

   procedure Lemma_Limb_Val_Succ (X : Val_Int) is
   begin
      if X < 0 then
         --  Def at X (< 0): Limb_Val (X) = Limb_Val (X + 1) - 1.
         pragma Assert (Limb_Val (X) = Limb_Val (X + 1) - 1);
      else
         --  X + 1 > 0, so def at X + 1: Limb_Val (X + 1) = Limb_Val (X) + 1.
         pragma Assert (Limb_Val (X + 1) = Limb_Val (X) + 1);
      end if;
   end Lemma_Limb_Val_Succ;

   procedure Lemma_Limb_Val_Pred (X : Val_Int) is
   begin
      Lemma_Limb_Val_Succ (X - 1);  --  Limb_Val (X) = Limb_Val (X - 1) + 1.
   end Lemma_Limb_Val_Pred;

   procedure Lemma_Limb_Val_Add (X, Y : Val_Int) is
   begin
      if Y = 0 then
         null;  --  Limb_Val (X + 0) = Limb_Val (X) = Limb_Val (X) + 0.
      elsif Y > 0 then
         Lemma_Limb_Val_Add (X, Y - 1);   --  IH on X + (Y - 1).
         Lemma_Limb_Val_Succ
           (X + Y - 1); --  Limb_Val (X+Y) = Limb_Val (X+Y-1)+1.
         Lemma_Limb_Val_Succ
           (Y - 1);     --  Limb_Val (Y)   = Limb_Val (Y-1)+1.
      else
         Lemma_Limb_Val_Add (X, Y + 1);   --  IH on X + (Y + 1).
         Lemma_Limb_Val_Pred
           (X + Y + 1); --  Limb_Val (X+Y) = Limb_Val (X+Y+1)-1.
         Lemma_Limb_Val_Pred
           (Y + 1);     --  Limb_Val (Y)   = Limb_Val (Y+1)-1.
      end if;
   end Lemma_Limb_Val_Add;

   procedure Lemma_Limb_Val_Neg (X : Val_Int) is
   begin
      Lemma_Limb_Val_Add
        (X, -X);  --  Limb_Val (0) = Limb_Val (X) + Limb_Val (-X).
   end Lemma_Limb_Val_Neg;

   procedure Lemma_Limb_Val_Mul (X : Mul_X_Int; Y : Mul_Y_Int) is
   begin
      if Y = 0 then
         null;  --  Limb_Val (X*0) = Limb_Val (0) = 0 = Limb_Val (X) * 0.
      elsif Y > 0 then
         pragma Assert (X * Y = X * (Y - 1) + X);
         Lemma_Limb_Val_Mul (X, Y - 1);                  --  IH.
         Lemma_Limb_Val_Add (X * (Y - 1), X);            --  split the product.
         Lemma_Limb_Val_Succ (Y - 1);                    --  Limb_Val (Y) bump.
         pragma
           Assert
             (Limb_Val (X * Y)
                = Limb_Val (X) * Limb_Val (Y - 1) + Limb_Val (X));
         pragma
           Assert
             (Limb_Val (X) * Limb_Val (Y - 1) + Limb_Val (X)
                = Limb_Val (X) * (Limb_Val (Y - 1) + 1));
      else
         pragma Assert (X * Y = X * (Y + 1) - X);
         Lemma_Limb_Val_Mul (X, Y + 1);                  --  IH.
         Lemma_Limb_Val_Add (X * (Y + 1), -X);           --  split the product.
         Lemma_Limb_Val_Neg (X);                         --  Limb_Val (-X).
         Lemma_Limb_Val_Pred (Y + 1);                    --  Limb_Val (Y) bump.
         pragma
           Assert
             (Limb_Val (X * Y)
                = Limb_Val (X) * Limb_Val (Y + 1) - Limb_Val (X));
         pragma
           Assert
             (Limb_Val (X) * Limb_Val (Y + 1) - Limb_Val (X)
                = Limb_Val (X) * (Limb_Val (Y + 1) - 1));
      end if;
   end Lemma_Limb_Val_Mul;

   procedure Lemma_Val_Tele (A, B : Big_Nat; C : Carry_Array; I : Limb_Index)
   is
   begin
      --  Collapse column I:  A(I)+C(I) = B(I)+Limb_Base*C(I+1)  (SVal_Wide).
      Lemma_Limb_Val_Add (A (I), C (I));
      Lemma_Limb_Val_Add (B (I), Limb_Base * C (I + 1));
      Lemma_Limb_Val_Mul (Limb_Base, C (I + 1));
      pragma
        Assert
          (Limb_Val (A (I)) + Limb_Val (C (I))
             = Limb_Val (B (I)) + Base * Limb_Val (C (I + 1)));

      if I = Max_Limbs - 1 then
         pragma Assert (C (I + 1) = 0);            --  C(Max_Limbs) = 0.

      else
         Lemma_Val_Tele (A, B, C, I + 1);          --  IH at I+1.
         pragma
           Assert
             (Val_From (A, I) + Limb_Val (C (I))
                = Limb_Val (B (I))
                  + Base * (Limb_Val (C (I + 1)) + Val_From (A, I + 1)));
      end if;
   end Lemma_Val_Tele;

   procedure Lemma_SVal_To_Val (A, B : Big_Nat; C : Carry_Array) is
   begin
      Lemma_Val_Tele (A, B, C, 0);
      pragma Assert (C (0) = 0);                   --  Limb_Val (0) = 0.
   end Lemma_SVal_To_Val;

   procedure Lemma_Val_From_Zero_High (A : Big_Nat; N, I : Limb_Index) is
   begin
      pragma Assert (A (I) = 0);                   --  I >= N.
      if I /= Max_Limbs - 1 then
         Lemma_Val_From_Zero_High (A, N, I + 1);
      end if;
   end Lemma_Val_From_Zero_High;

   procedure Lemma_Val_From_Smul (S : LLI; A : Big_Nat; I : Limb_Index) is
   begin
      Lemma_Limb_Val_Mul
        (A (I), S);   --  Limb_Val (A(I)*S) = Limb_Val(A(I))*Limb_Val(S).
      pragma Assert (Smul (S, A) (I) = S * A (I));
      pragma
        Assert (Limb_Val (Smul (S, A) (I)) = Limb_Val (S) * Limb_Val (A (I)));
      if I /= Max_Limbs - 1 then
         Lemma_Val_From_Smul (S, A, I + 1);        --  IH.
         pragma
           Assert
             (Val_From (Smul (S, A), I)
                = Limb_Val (S)
                  * Limb_Val (A (I))
                  + Base * (Limb_Val (S) * Val_From (A, I + 1)));
         pragma
           Assert
             (Limb_Val (S)
                * Limb_Val (A (I))
                + Base * (Limb_Val (S) * Val_From (A, I + 1))
                = Limb_Val (S)
                  * (Limb_Val (A (I)) + Base * Val_From (A, I + 1)));
      end if;
   end Lemma_Val_From_Smul;

   procedure Lemma_Val_Smul (S : LLI; A : Big_Nat) is
   begin
      Lemma_Val_From_Smul (S, A, 0);
   end Lemma_Val_Smul;

   procedure Lemma_Val_From_Add (A, B : Big_Nat; I : Limb_Index) is
   begin
      Lemma_Limb_Val_Add (A (I), B (I));
      --  "+" Post gives (A + B) (I) = A (I) + B (I) for free.
      if I /= Max_Limbs - 1 then
         Lemma_Val_From_Add (A, B, I + 1);        --  IH.
         pragma
           Assert
             (Val_From (A + B, I)
                = (Limb_Val (A (I)) + Limb_Val (B (I)))
                  + Base * (Val_From (A, I + 1) + Val_From (B, I + 1)));
      end if;
   end Lemma_Val_From_Add;

   procedure Lemma_Val_Add (A, B : Big_Nat) is
   begin
      Lemma_Val_From_Add (A, B, 0);
   end Lemma_Val_Add;

   procedure Lemma_Col_Val (A, B : Big_Nat; K, T : Limb_Index) is
   begin
      Lemma_Limb_Val_Mul (A (T), B (K - T));
      if T /= 0 then
         Lemma_Col_Val (A, B, K, T - 1);          --  IH.
         Lemma_Limb_Val_Add (Mul_Col (A, B, K, T - 1), A (T) * B (K - T));
      end if;
   end Lemma_Col_Val;

   procedure Lemma_Shift1_Suffix (X : Big_Nat; I : Limb_Index) is
   begin
      if I = Max_Limbs - 2 then
         pragma Assert (X (Max_Limbs - 1) = 0);   --  Limb_Val (0) = 0.

      else
         Lemma_Shift1_Suffix (X, I + 1);          --  IH.
      end if;
   end Lemma_Shift1_Suffix;

   procedure Lemma_Val_Shift1 (X : Big_Nat) is
   begin
      Lemma_Shift1_Suffix (X, 0);
   --  Val (Shift1g X) = Limb_Val (0) + Base * Val_From (Shift1g X, 1)
   --                  = Base * Val_From (X, 0) = Base * Val (X).
   end Lemma_Val_Shift1;

   procedure Lemma_Val_From_Cong (X, Y : Big_Nat; I : Limb_Index) is
   begin
      if I /= Max_Limbs - 1 then
         Lemma_Val_From_Cong
           (X, Y, I + 1);       --  IH; X (I) = Y (I) from X = Y.

      end if;
   end Lemma_Val_From_Cong;

   procedure Lemma_Val_Cong (X, Y : Big_Nat) is
   begin
      Lemma_Val_From_Cong (X, Y, 0);
   end Lemma_Val_Cong;

   procedure Lemma_Mul_Unit_Col (A : Big_Nat; V : LLI; M, K, T : Limb_Index) is
   begin
      pragma Assert (Unit_Limb (V, M) (K - T) = (if K - T = M then V else 0));
      if T /= 0 then
         Lemma_Mul_Unit_Col (A, V, M, K, T - 1);   --  IH.

      end if;
   end Lemma_Mul_Unit_Col;

   procedure Lemma_Mul_Unit (A : Big_Nat; V : LLI; M : Limb_Index) is
      U  : constant Big_Nat := Unit_Limb (V, M);
      P  : constant Big_Nat := A * U;
      SS : constant Big_Nat := Smul (V, Shift_By (A, M));
   begin
      for K in Limb_Index loop
         Lemma_Mul_Unit_Col (A, V, M, K, K);
         pragma Assert (P (K) = SS (K));
         pragma
           Loop_Invariant
             (for all KK in Limb_Index range 0 .. K => P (KK) = SS (KK));
      end loop;
      pragma Assert (P = SS);
   end Lemma_Mul_Unit;

   procedure Lemma_Mul_Col_Cong (A, X, Y : Big_Nat; K, T : Limb_Index) is
   begin
      if T /= 0 then
         Lemma_Mul_Col_Cong
           (A, X, Y, K, T - 1);   --  IH; X (K-T) = Y (K-T) from X = Y.

      end if;
   end Lemma_Mul_Col_Cong;

   procedure Lemma_Mul_Cong_R (A, X, Y : Big_Nat) is
      PX : constant Big_Nat := A * X;
      PY : constant Big_Nat := A * Y;
   begin
      for K in Limb_Index loop
         Lemma_Mul_Col_Cong (A, X, Y, K, K);
         pragma Assert (PX (K) = PY (K));
         pragma
           Loop_Invariant
             (for all KK in Limb_Index range 0 .. K => PX (KK) = PY (KK));
      end loop;
      pragma Assert (PX = PY);
   end Lemma_Mul_Cong_R;

   procedure Lemma_Mul_Col_Cong_L (A, A2, B : Big_Nat; K, T : Limb_Index) is
   begin
      if T /= 0 then
         Lemma_Mul_Col_Cong_L (A, A2, B, K, T - 1);   --  IH; A (T) = A2 (T).

      end if;
   end Lemma_Mul_Col_Cong_L;

   procedure Lemma_Mul_Cong_LR (A, A2, B, B2 : Big_Nat) is
      PX : constant Big_Nat := A * B;
      PY : constant Big_Nat := A2 * B2;
   begin
      for K in Limb_Index loop
         Lemma_Mul_Col_Cong
           (A, B, B2, K, K);     --  Mul_Col(A,B)=Mul_Col(A,B2).
         Lemma_Mul_Col_Cong_L
           (A, A2, B2, K, K);  --  Mul_Col(A,B2)=Mul_Col(A2,B2).
         pragma Assert (PX (K) = PY (K));
         pragma
           Loop_Invariant
             (for all KK in Limb_Index range 0 .. K => PX (KK) = PY (KK));
      end loop;
      pragma Assert (PX = PY);
   end Lemma_Mul_Cong_LR;

   procedure Lemma_Mul_Zero_Col (A : Big_Nat; K, T : Limb_Index) is
   begin
      pragma Assert (Zero (K - T) = 0);
      if T /= 0 then
         Lemma_Mul_Zero_Col (A, K, T - 1);
      end if;
   end Lemma_Mul_Zero_Col;

   procedure Lemma_Mul_Zero_R (A : Big_Nat) is
      P : constant Big_Nat := A * Zero;
   begin
      for K in Limb_Index loop
         Lemma_Mul_Zero_Col (A, K, K);
         pragma Assert (P (K) = 0);
         pragma
           Loop_Invariant
             (for all KK in Limb_Index range 0 .. K => P (KK) = 0);
      end loop;
      pragma Assert (P = Zero);
   end Lemma_Mul_Zero_R;

   procedure Lemma_Val_Unit (V : LLI; M : Limb_Index) is
      U0 : constant Big_Nat := Unit_Limb (V, 0);
   begin
      Lemma_Val_From_Zero_High (U0, 1, 1);     --  Val_From (U0, 1) = 0.
      pragma Assert (Val (U0) = Limb_Val (V));
      pragma
        Assert
          (for all K in Limb_Index =>
             Unit_Limb (V, M) (K) = Shift_By (U0, M) (K));
      pragma Assert (Unit_Limb (V, M) = Shift_By (U0, M));
      Lemma_Val_Cong (Unit_Limb (V, M), Shift_By (U0, M));
      Lemma_Val_Shift_By
        (U0, M);              --  Val (Shift_By (U0,M)) = Base_Pow(M)*Val(U0).
   end Lemma_Val_Unit;

   procedure Lemma_Val_Lo_Step (B : Big_Nat; M : Limb_Index) is
      Lo : constant Big_Nat := B_Lo (B, M);
      U  : constant Big_Nat := Unit_Limb (B (M), M);
   begin
      pragma
        Assert
          (for all K in Limb_Index => B_Lo (B, M + 1) (K) = Lo (K) + U (K));
      pragma Assert (B_Lo (B, M + 1) = Lo + U);
      Lemma_Val_Add (Lo, U);
      Lemma_Val_Cong (B_Lo (B, M + 1), Lo + U);
      Lemma_Val_Unit (B (M), M);
   end Lemma_Val_Lo_Step;

   procedure Lemma_Val_Mul_Acc (A, B : Big_Nat; Na, Nb, M : Lo_Count) is
   begin
      if M = 0 then
         pragma Assert (B_Lo (B, 0) = Zero);
         Lemma_Mul_Zero_R (A);                 --  A * Zero = Zero.
         Lemma_Mul_Cong_R (A, B_Lo (B, 0), Zero);
         Lemma_Val_From_Zero_High (Zero, 0, 0);
         Lemma_Val_Cong (A * B_Lo (B, 0), Zero);
         Lemma_Val_Cong (B_Lo (B, 0), Zero);
      else
         Lemma_Val_Mul_Acc (A, B, Na, Nb, M - 1);   --  IH.
         declare
            Lo1 : constant Big_Nat := B_Lo (B, M - 1);
            LoM : constant Big_Nat := B_Lo (B, M);
            U   : constant Big_Nat := Unit_Limb (B (M - 1), M - 1);
            SH  : constant Big_Nat := Shift_By (A, M - 1);
         begin
            pragma
              Assert (for all K in Limb_Index => LoM (K) = Lo1 (K) + U (K));
            Lemma_Mul_Distrib (A, Lo1, U, LoM);       --  A*LoM = A*Lo1 + A*U.
            Lemma_Mul_Unit
              (A, B (M - 1), M - 1);     --  A*U = Smul (B(M-1), SH).
            Lemma_Val_Add (A * Lo1, A * U);
            Lemma_Val_Cong (A * LoM, A * Lo1 + A * U);
            Lemma_Val_Cong (A * U, Smul (B (M - 1), SH));
            Lemma_Val_Smul (B (M - 1), SH);
            pragma
              Assert
                (for all K in
                   Limb_Index range Max_Limbs - (M - 1) .. Max_Limbs - 1 =>
                   A (K) = 0);
            Lemma_Val_Shift_By
              (A, M - 1);            --  Val(SH) = Base_Pow(M-1)*Val(A).
            Lemma_Val_Lo_Step (B, M - 1);
            --  Val(LoM) = Val(Lo1) + Limb_Val(B(M-1))*Base_Pow(M-1).
            pragma
              Assert
                (Val (A * LoM)
                   = Val (A)
                     * Val (Lo1)
                     + Limb_Val (B (M - 1)) * Base_Pow (M - 1) * Val (A));
         end;
      end if;
   end Lemma_Val_Mul_Acc;

   procedure Lemma_Val_Mul (A, B : Big_Nat; Na, Nb : Lo_Count) is
   begin
      Lemma_Val_Mul_Acc (A, B, Na, Nb, Nb);
      pragma Assert (for all K in Limb_Index => B_Lo (B, Nb) (K) = B (K));
      pragma Assert (B_Lo (B, Nb) = B);
      Lemma_Mul_Cong_R (A, B_Lo (B, Nb), B);
      Lemma_Val_Cong (A * B_Lo (B, Nb), A * B);
      Lemma_Val_Cong (B_Lo (B, Nb), B);
   end Lemma_Val_Mul;

   procedure Lemma_Val_P_Prime is
   begin
      Lemma_Limb_Val_Pred
        (Limb_Base);         --  Limb_Val (In_Cap)   = Base - 1.
      Lemma_Limb_Val_Pred (Limb_Base - 1);
      Lemma_Limb_Val_Pred (Limb_Base - 2);
      Lemma_Limb_Val_Pred (Limb_Base - 3);
      Lemma_Limb_Val_Pred
        (Limb_Base - 4);     --  Limb_Val (In_Cap-4) = Base - 5.
      Lemma_Val_From_Zero_High (P_Prime, 5, 5);
      pragma Assert (Limb_Val (P_Prime (0)) = Base - 5);
      pragma
        Assert
          (for all K in Limb_Index range 1 .. 4 =>
             Limb_Val (P_Prime (K)) = Base - 1);
      --  Telescope the all-(Base-1) tail: Val_From (P_Prime, k) = Base**(5-k) - 1.
      pragma Assert (Val_From (P_Prime, 4) = Base - 1);
      pragma Assert (Val_From (P_Prime, 3) = Base * Base - 1);
      pragma Assert (Val_From (P_Prime, 2) = Base * Base * Base - 1);
      pragma Assert (Val_From (P_Prime, 1) = Base * Base * Base * Base - 1);
      pragma
        Assert (Val_From (P_Prime, 0) = Base * Base * Base * Base * Base - 5);
      pragma Assert (Base_Pow (5) = Base * (Base * (Base * (Base * Base))));
   end Lemma_Val_P_Prime;

   procedure Lemma_Val_P_Mul (R : Big_Nat) is
   begin
      Lemma_Val_Mul
        (P_Prime, R, 5, 5);   --  Val(P_Prime*R) = Val(P_Prime)*Val(R).
      Lemma_Val_P_Prime;                   --  Val(P_Prime)   = Base_Pow(5)-5.
   end Lemma_Val_P_Mul;

   procedure Lemma_ValEq_To_Val (A, B : Big_Nat; C : Carry_Array) is
   begin
      pragma
        Assert
          (SC_Bounded (C));         --  Carry_Bounded => non-negative bound.
      Lemma_Val_To_SVal (A, B, C);            --  SVal_Eq (A, B, C).
      Lemma_SVal_To_Wide (A, B, C);           --  SVal_Wide (A, B, C).
      Lemma_SVal_To_Val (A, B, C);            --  Val (A) = Val (B).
   end Lemma_ValEq_To_Val;

   procedure Lemma_Limb_Val_Nonneg (X : Val_Int) is
   begin
      if X /= 0 then
         Lemma_Limb_Val_Nonneg
           (X - 1);       --  Limb_Val (X) = Limb_Val (X-1) + 1.

      end if;
   end Lemma_Limb_Val_Nonneg;

   procedure Lemma_Limb_Val_Mono (X, Y : Val_Int) is
   begin
      if X /= Y then
         Lemma_Limb_Val_Mono
           (X, Y - 1);      --  Limb_Val (Y) = Limb_Val (Y-1) + 1.

      end if;
   end Lemma_Limb_Val_Mono;

   procedure Lemma_Val_From_Reduced_Ub (X : Big_Nat; K : Lo_Count) is
   begin
      Lemma_Limb_Val_Nonneg (Limb_Base - 1);      --  Base >= 1.
      pragma Assert (Base >= 1);
      if K = 5 then
         Lemma_Val_From_Zero_High (X, 5, 5);      --  Val_From (X, 5) = 0.

      else
         Lemma_Val_From_Reduced_Ub (X, K + 1);    --  IH.
         Lemma_Limb_Val_Nonneg (X (K));           --  Limb_Val (X(K)) >= 0.
         Lemma_Limb_Val_Mono (X (K), In_Cap);     --  <= Limb_Val (In_Cap).
         Lemma_Limb_Val_Pred
           (Limb_Base);         --  Limb_Val (In_Cap) = Base - 1.
         pragma Assert (Limb_Val (X (K)) <= Base - 1);
         pragma Assert (Base_Pow (5 - K) = Base * Base_Pow (4 - K));
         --  Multiply-monotone: 0 <= Val_From(X,K+1) <= Base_Pow(4-K)-1, Base>=1.
         pragma
           Assert
             (Base * Val_From (X, K + 1) <= Base * (Base_Pow (4 - K) - 1));
         pragma Assert (Base * Val_From (X, K + 1) >= 0);
      end if;
   end Lemma_Val_From_Reduced_Ub;

   procedure Lemma_Val_Lt_No_Carry (X : Big_Nat) is
      S   : constant Big_Nat := Sweep5_Out (X);
      S0  : constant Big_Nat :=
        [for I in Big_Nat'Range => (if I <= 4 then S (I) else 0)];
      Hi  : constant Big_Nat :=
        [for I in Big_Nat'Range => (if I = 5 then S (I) else 0)];
      Sum : constant Big_Nat := S0 + Hi;
   begin
      --  Val (X) = Val (S): the sweep preserves value.
      Lemma_Sweep5 (X);
      Lemma_Bounds_Mono (S, Add_Cap, Val_Cap);
      Lemma_ValEq_To_Val (X, S, Sweep5_Chain (X));

      --  S = S0 + Hi: the reduced low-5 view plus the carry limb (only limb 5).
      pragma Assert (In_Bounds (S0, In_Cap));
      pragma
        Assert
          (for all I in Limb_Index range 5 .. Max_Limbs - 1 => S0 (I) = 0);
      pragma Assert (In_Bounds (Hi, Add_Cap));
      pragma Assert (for all I in Big_Nat'Range => Sum (I) = S (I));
      pragma Assert (Sum = S);
      Lemma_Val_From_Reduced_Ub (S0, 0);            --  Val (S0) >= 0.
      Lemma_Val_From_Add
        (S0, Hi, 0);               --  Val (Sum)=Val(S0)+Val(Hi)
      Lemma_Val_From_Cong (Sum, S, 0);              --  Val (Sum) = Val (S)
      --  Hence Val (S) = Val (S0) + Val (Hi), with Val (S0) >= 0.

      --  A non-zero carry forces Val (Hi) >= Base_Pow (5), contradicting
      --  Val (S) = Val (X) < Base_Pow (5). Lower-bound ladder (each step a
      --  single 2-factor multiply, Base * Base_Pow): Val_From (Hi, K) >=
      --  Base_Pow (5 - K).
      if S (5) >= 1 then
         Lemma_Val_From_Zero_High (Hi, 6, 6);       --  Val_From (Hi, 6) = 0.
         Lemma_Base_Ge_6;                           --  Base >= 6 > 0.
         Lemma_Limb_Val_Mono (1, S (5));
         pragma Assert (Limb_Val (0) = 0);
         pragma Assert (Limb_Val (1) = 1);
         pragma Assert (Base_Pow (0) = 1);
         pragma Assert (Val_From (Hi, 5) >= Base_Pow (0));

         pragma Assert (Val_From (Hi, 4) = Base * Val_From (Hi, 5));
         pragma Assert (Base_Pow (1) = Base * Base_Pow (0));
         Lemma_BI_Mul_Mono (Base, Base_Pow (0), Val_From (Hi, 5));
         pragma Assert (Val_From (Hi, 4) >= Base_Pow (1));

         pragma Assert (Val_From (Hi, 3) = Base * Val_From (Hi, 4));
         pragma Assert (Base_Pow (2) = Base * Base_Pow (1));
         Lemma_BI_Mul_Mono (Base, Base_Pow (1), Val_From (Hi, 4));
         pragma Assert (Val_From (Hi, 3) >= Base_Pow (2));

         pragma Assert (Val_From (Hi, 2) = Base * Val_From (Hi, 3));
         pragma Assert (Base_Pow (3) = Base * Base_Pow (2));
         Lemma_BI_Mul_Mono (Base, Base_Pow (2), Val_From (Hi, 3));
         pragma Assert (Val_From (Hi, 2) >= Base_Pow (3));

         pragma Assert (Val_From (Hi, 1) = Base * Val_From (Hi, 2));
         pragma Assert (Base_Pow (4) = Base * Base_Pow (3));
         Lemma_BI_Mul_Mono (Base, Base_Pow (3), Val_From (Hi, 2));
         pragma Assert (Val_From (Hi, 1) >= Base_Pow (4));

         pragma Assert (Val_From (Hi, 0) = Base * Val_From (Hi, 1));
         pragma Assert (Base_Pow (5) = Base * Base_Pow (4));
         Lemma_BI_Mul_Mono (Base, Base_Pow (4), Val_From (Hi, 1));
         pragma Assert (Val_From (Hi, 0) >= Base_Pow (5));
         pragma Assert (Val (S) >= Base_Pow (5));
      end if;
      pragma Assert (Sweep5_Out (X) (5) = 0);
   end Lemma_Val_Lt_No_Carry;

   procedure Lemma_Val_Carry_Bound (X : Big_Nat) is
      S   : constant Big_Nat := Sweep5_Out (X);
      S0  : constant Big_Nat :=
        [for I in Big_Nat'Range => (if I <= 4 then S (I) else 0)];
      Hi  : constant Big_Nat :=
        [for I in Big_Nat'Range => (if I = 5 then S (I) else 0)];
      Sum : constant Big_Nat := S0 + Hi;
   begin
      --  Val (X) = Val (S) = Val (S0) + Val (Hi), Val (S0) <= Base_Pow (5) - 1.
      Lemma_Sweep5 (X);
      Lemma_Bounds_Mono (S, Add_Cap, Val_Cap);
      Lemma_ValEq_To_Val (X, S, Sweep5_Chain (X));
      pragma Assert (In_Bounds (S0, In_Cap));
      pragma
        Assert
          (for all I in Limb_Index range 5 .. Max_Limbs - 1 => S0 (I) = 0);
      pragma Assert (In_Bounds (Hi, Add_Cap));
      pragma Assert (for all I in Big_Nat'Range => Sum (I) = S (I));
      pragma Assert (Sum = S);
      Lemma_Val_From_Reduced_Ub (S0, 0);
      Lemma_Val_From_Add (S0, Hi, 0);
      Lemma_Val_From_Cong (Sum, S, 0);

      --  Upper-bound ladder: Val_From (Hi, K) <= Base_Pow (5 - K) (carry <= 1).
      Lemma_Val_From_Zero_High (Hi, 6, 6);
      Lemma_Base_Ge_6;
      Lemma_Limb_Val_Mono (S (5), 1);
      pragma Assert (Limb_Val (0) = 0);
      pragma Assert (Limb_Val (1) = 1);
      pragma Assert (Base_Pow (0) = 1);
      pragma Assert (Val_From (Hi, 5) <= Base_Pow (0));

      pragma Assert (Val_From (Hi, 4) = Base * Val_From (Hi, 5));
      pragma Assert (Base_Pow (1) = Base * Base_Pow (0));
      Lemma_BI_Mul_Mono (Base, Val_From (Hi, 5), Base_Pow (0));
      pragma Assert (Val_From (Hi, 4) <= Base_Pow (1));

      pragma Assert (Val_From (Hi, 3) = Base * Val_From (Hi, 4));
      pragma Assert (Base_Pow (2) = Base * Base_Pow (1));
      Lemma_BI_Mul_Mono (Base, Val_From (Hi, 4), Base_Pow (1));
      pragma Assert (Val_From (Hi, 3) <= Base_Pow (2));

      pragma Assert (Val_From (Hi, 2) = Base * Val_From (Hi, 3));
      pragma Assert (Base_Pow (3) = Base * Base_Pow (2));
      Lemma_BI_Mul_Mono (Base, Val_From (Hi, 3), Base_Pow (2));
      pragma Assert (Val_From (Hi, 2) <= Base_Pow (3));

      pragma Assert (Val_From (Hi, 1) = Base * Val_From (Hi, 2));
      pragma Assert (Base_Pow (4) = Base * Base_Pow (3));
      Lemma_BI_Mul_Mono (Base, Val_From (Hi, 2), Base_Pow (3));
      pragma Assert (Val_From (Hi, 1) <= Base_Pow (4));

      pragma Assert (Val_From (Hi, 0) = Base * Val_From (Hi, 1));
      pragma Assert (Base_Pow (5) = Base * Base_Pow (4));
      Lemma_BI_Mul_Mono (Base, Val_From (Hi, 1), Base_Pow (4));
      pragma Assert (Val_From (Hi, 0) <= Base_Pow (5));

      pragma Assert (Val (Hi) <= Base_Pow (5));
      pragma Assert (Val (X) < 2 * Base_Pow (5));
   end Lemma_Val_Carry_Bound;

   procedure Lemma_Val_Carry_Bound_2 (X : Big_Nat) is
      S   : constant Big_Nat := Sweep5_Out (X);
      S0  : constant Big_Nat :=
        [for I in Big_Nat'Range => (if I <= 4 then S (I) else 0)];
      Hi  : constant Big_Nat :=
        [for I in Big_Nat'Range => (if I = 5 then S (I) else 0)];
      Sum : constant Big_Nat := S0 + Hi;
   begin
      --  Val (X) = Val (S) = Val (S0) + Val (Hi), Val (S0) <= Base_Pow (5) - 1.
      Lemma_Sweep5 (X);
      Lemma_Bounds_Mono (S, Add_Cap, Val_Cap);
      Lemma_ValEq_To_Val (X, S, Sweep5_Chain (X));
      pragma Assert (In_Bounds (S0, In_Cap));
      pragma
        Assert
          (for all I in Limb_Index range 5 .. Max_Limbs - 1 => S0 (I) = 0);
      pragma Assert (In_Bounds (Hi, Add_Cap));
      pragma Assert (for all I in Big_Nat'Range => Sum (I) = S (I));
      pragma Assert (Sum = S);
      Lemma_Val_From_Reduced_Ub (S0, 0);
      Lemma_Val_From_Add (S0, Hi, 0);
      Lemma_Val_From_Cong (Sum, S, 0);

      --  Upper-bound ladder: Val_From (Hi, K) <= 2 * Base_Pow (5 - K)
      --  (carry <= 2). Each multiply-by-Base step keeps the literal 2 factor,
      --  so the reassoc 2 * (Base * Y) = Base * (2 * Y) stays linear.
      Lemma_Val_From_Zero_High (Hi, 6, 6);
      Lemma_Base_Ge_6;
      Lemma_Limb_Val_Mono (S (5), 2);
      pragma Assert (Limb_Val (0) = 0);
      pragma Assert (Limb_Val (2) = 2);
      pragma Assert (Base_Pow (0) = 1);
      pragma Assert (Val_From (Hi, 5) <= 2 * Base_Pow (0));

      pragma Assert (Val_From (Hi, 4) = Base * Val_From (Hi, 5));
      pragma Assert (2 * Base_Pow (1) = Base * (2 * Base_Pow (0)));
      Lemma_BI_Mul_Mono (Base, Val_From (Hi, 5), 2 * Base_Pow (0));
      pragma Assert (Val_From (Hi, 4) <= 2 * Base_Pow (1));

      pragma Assert (Val_From (Hi, 3) = Base * Val_From (Hi, 4));
      pragma Assert (2 * Base_Pow (2) = Base * (2 * Base_Pow (1)));
      Lemma_BI_Mul_Mono (Base, Val_From (Hi, 4), 2 * Base_Pow (1));
      pragma Assert (Val_From (Hi, 3) <= 2 * Base_Pow (2));

      pragma Assert (Val_From (Hi, 2) = Base * Val_From (Hi, 3));
      pragma Assert (2 * Base_Pow (3) = Base * (2 * Base_Pow (2)));
      Lemma_BI_Mul_Mono (Base, Val_From (Hi, 3), 2 * Base_Pow (2));
      pragma Assert (Val_From (Hi, 2) <= 2 * Base_Pow (3));

      pragma Assert (Val_From (Hi, 1) = Base * Val_From (Hi, 2));
      pragma Assert (2 * Base_Pow (4) = Base * (2 * Base_Pow (3)));
      Lemma_BI_Mul_Mono (Base, Val_From (Hi, 2), 2 * Base_Pow (3));
      pragma Assert (Val_From (Hi, 1) <= 2 * Base_Pow (4));

      pragma Assert (Val_From (Hi, 0) = Base * Val_From (Hi, 1));
      pragma Assert (2 * Base_Pow (5) = Base * (2 * Base_Pow (4)));
      Lemma_BI_Mul_Mono (Base, Val_From (Hi, 1), 2 * Base_Pow (4));
      pragma Assert (Val_From (Hi, 0) <= 2 * Base_Pow (5));

      pragma Assert (Val (Hi) <= 2 * Base_Pow (5));
      pragma Assert (Val (X) < 3 * Base_Pow (5));
   end Lemma_Val_Carry_Bound_2;

   procedure Lemma_Carry_Model_Val_Tight (B : Big_Nat) is
      CM : constant Big_Nat := Carry_Model (B);
      K  : LLI;
      C  : Carry_Array;
   begin
      --  B == CM + K*p (carry-fold congruence), K = Sweep5_Out (B)(5) in 0 .. 2.
      Lemma_Carry_Mod_P (B, K, C);
      declare
         SK : constant Big_Nat := Smul (K, P_Prime);
      begin
         pragma Assert (In_Bounds (CM, Add_Cap));
         pragma Assert (for all I in Limb_Index => P_Prime (I) <= In_Cap);
         pragma Assert (for all I in Limb_Index => SK (I) = K * P_Prime (I));
         pragma Assert (In_Bounds (SK, Add_Cap));
         pragma Assert (In_Bounds (CM + SK, Add_Cap));
         pragma Assert (SVal_Eq (B, CM + SK, C));

         --  Lift the carry congruence to Val: Val (B) = Val (CM) + K * p.
         Lemma_SValEq_To_Val (B, CM + SK, C);
         Lemma_Val_Add (CM, SK);
         Lemma_Val_Smul (K, P_Prime);
         Lemma_Val_P_Prime;
         pragma
           Assert (Val (B) = Val (CM) + Limb_Val (K) * (Base_Pow (5) - 5));

         --  Per-K0 upper bound on Val (B); cancel to Val (CM) <= 2^130-1 + 5*K0.
         if K = 0 then
            pragma Assert (Limb_Val (K) = 0);
            Lemma_Sweep5 (B);
            Lemma_Bounds_Mono (Sweep5_Out (B), Add_Cap, Val_Cap);
            Lemma_ValEq_To_Val (B, Sweep5_Out (B), Sweep5_Chain (B));
            pragma Assert (In_Bounds (Sweep5_Out (B), In_Cap));
            pragma
              Assert
                (for all I in Limb_Index range 5 .. Max_Limbs - 1 =>
                   Sweep5_Out (B) (I) = 0);
            Lemma_Val_From_Reduced_Ub (Sweep5_Out (B), 0);
            pragma Assert (Val (B) <= Base_Pow (5) - 1);
            pragma
              Assert
                (Val (CM)
                   <= Base_Pow (5) - 1 + 5 * Limb_Val (Sweep5_Out (B) (5)));
         elsif K = 1 then
            pragma Assert (Limb_Val (K) = 1);
            Lemma_Val_Carry_Bound (B);
            pragma Assert (Val (B) <= 2 * Base_Pow (5) - 1);
            pragma
              Assert
                (Val (CM)
                   <= Base_Pow (5) - 1 + 5 * Limb_Val (Sweep5_Out (B) (5)));
         else
            pragma Assert (Limb_Val (K) = 2);
            Lemma_Val_Carry_Bound_2 (B);
            pragma Assert (Val (B) <= 3 * Base_Pow (5) - 1);
            pragma
              Assert
                (Val (CM)
                   <= Base_Pow (5) - 1 + 5 * Limb_Val (Sweep5_Out (B) (5)));
         end if;
      end;
   end Lemma_Carry_Model_Val_Tight;

   procedure Lemma_BI_Mul_Mono (C, A, B : BI.Big_Integer) is
   begin
      null;
   end Lemma_BI_Mul_Mono;

   procedure Lemma_Val_From_Max_Forces (X : Big_Nat; K : Lo_Count) is
   begin
      if K = 5 then
         null;  --  range 5 .. 4 empty.

      else
         Lemma_Limb_Val_Nonneg (Limb_Base - 1);    --  Base >= 1.
         Lemma_Val_From_Reduced_Ub
           (X, K + 1);     --  Val_From(X,K+1) <= Base_Pow(4-K)-1.
         Lemma_Limb_Val_Mono (X (K), In_Cap);
         Lemma_Limb_Val_Pred
           (Limb_Base);          --  Limb_Val(In_Cap) = Base-1.
         pragma Assert (Limb_Val (X (K)) <= Base - 1);
         pragma Assert (Base_Pow (5 - K) = Base * Base_Pow (4 - K));
         pragma
           Assert
             (Base * Val_From (X, K + 1) <= Base * (Base_Pow (4 - K) - 1));
         --  sum = sum-of-maxes and each <= its max => each = its max.
         pragma Assert (Limb_Val (X (K)) = Base - 1);
         --  Cancellation-free: a strictly smaller suffix would drop the sum by
         --  >= Base (multiply-monotone), contradicting the maximal sum.
         if Val_From (X, K + 1) < Base_Pow (4 - K) - 1 then
            pragma Assert (Val_From (X, K + 1) <= Base_Pow (4 - K) - 2);
            Lemma_BI_Mul_Mono
              (Base, Val_From (X, K + 1), Base_Pow (4 - K) - 2);
            pragma
              Assert
                (Base * (Base_Pow (4 - K) - 2)
                   = Base * (Base_Pow (4 - K) - 1) - Base);
            pragma Assert (False);
         end if;
         pragma Assert (Val_From (X, K + 1) = Base_Pow (4 - K) - 1);
         --  Limb_Val(X(K)) = Base-1 = Limb_Val(In_Cap) forces X(K) = In_Cap.
         if X (K) < In_Cap then
            Lemma_Limb_Val_Succ (X (K));
            Lemma_Limb_Val_Mono (X (K) + 1, In_Cap);
            pragma Assert (Limb_Val (X (K)) <= Base - 2);   --  contradiction.

         end if;
         pragma Assert (X (K) = In_Cap);
         Lemma_Val_From_Max_Forces (X, K + 1);     --  IH on the rest.
      end if;
   end Lemma_Val_From_Max_Forces;

   procedure Lemma_Base_Ge_6 is
   begin
      Lemma_Limb_Val_Mono (6, Limb_Base);          --  Limb_Val(6) <= Base.
      pragma Assert (Limb_Val (6) = 6);            --  unit recursion, 6 deep.
   end Lemma_Base_Ge_6;

   procedure Lemma_Val_Lt_P (X : Big_Nat) is
   begin
      Lemma_Base_Ge_6;                             --  Base >= 6.
      Lemma_Val_From_Reduced_Ub
        (X, 0);            --  0 <= Val(X) <= Base_Pow(5)-1.
      Lemma_Val_From_Reduced_Ub
        (X, 1);            --  Val_From(X,1) <= Base_Pow(4)-1.
      Lemma_Limb_Val_Nonneg (X (0));
      Lemma_Limb_Val_Mono (X (0), In_Cap);
      Lemma_Limb_Val_Pred
        (Limb_Base);             --  Limb_Val(In_Cap) = Base-1.
      pragma Assert (Base_Pow (5) = Base * Base_Pow (4));
      pragma Assert (Val (X) = Limb_Val (X (0)) + Base * Val_From (X, 1));

      if Val_From (X, 1) <= Base_Pow (4) - 2 then
         --  Case A: top 4 not all maxed -> Base deficit dominates the 5 margin.
         pragma Assert (Base * Val_From (X, 1) <= Base * (Base_Pow (4) - 2));
         pragma Assert (Val (X) <= (Base - 1) + Base * (Base_Pow (4) - 2));
         pragma Assert (Val (X) <= Base_Pow (5) - Base - 1);
      else
         --  Case B: Val_From(X,1) = Base_Pow(4)-1 -> X(1..4) all = In_Cap.
         pragma Assert (Val_From (X, 1) = Base_Pow (4) - 1);
         Lemma_Val_From_Max_Forces (X, 1);
         pragma
           Assert
             (X (1) = In_Cap
                and then X (2) = In_Cap
                and then X (3) = In_Cap
                and then X (4) = In_Cap);
         pragma Assert (X (0) < In_Cap - 4);       --  from not Sub_Cond.
         --  Limb_Val(X(0)) <= Limb_Val(In_Cap-5) = Base-6.
         Lemma_Limb_Val_Pred (Limb_Base - 1);
         Lemma_Limb_Val_Pred (Limb_Base - 2);
         Lemma_Limb_Val_Pred (Limb_Base - 3);
         Lemma_Limb_Val_Pred (Limb_Base - 4);
         Lemma_Limb_Val_Pred
           (Limb_Base - 5);      --  Limb_Val(In_Cap-5)=Base-6.
         Lemma_Limb_Val_Mono (X (0), In_Cap - 5);
         pragma Assert (Limb_Val (X (0)) <= Base - 6);
         pragma Assert (Val (X) <= (Base - 6) + Base * (Base_Pow (4) - 1));
         pragma Assert (Val (X) <= Base_Pow (5) - 6);
      end if;
   end Lemma_Val_Lt_P;

   procedure Lemma_Limb_Val_Inj (X, Y : Val_Int) is
   begin
      if X < Y then
         Lemma_Limb_Val_Succ
           (X);              --  Limb_Val(X+1) = Limb_Val(X)+1.
         Lemma_Limb_Val_Mono
           (X + 1, Y);       --  <= Limb_Val(Y): strict, contra.
         pragma Assert (Limb_Val (X) < Limb_Val (Y));
      elsif Y < X then
         Lemma_Limb_Val_Succ (Y);
         Lemma_Limb_Val_Mono (Y + 1, X);
         pragma Assert (Limb_Val (Y) < Limb_Val (X));
      end if;
   end Lemma_Limb_Val_Inj;

   procedure Lemma_Val_From_Inj (X, Y : Big_Nat; K : Lo_Count) is
   begin
      if K /= 5 then
         Lemma_Limb_Val_Nonneg (Limb_Base - 1);     --  Base >= 1.
         Lemma_Limb_Val_Nonneg (X (K));
         Lemma_Limb_Val_Nonneg (Y (K));
         Lemma_Limb_Val_Mono (X (K), In_Cap);
         Lemma_Limb_Val_Mono (Y (K), In_Cap);
         Lemma_Limb_Val_Pred
           (Limb_Base);           --  Limb_Val(In_Cap) = Base-1.
         Lemma_Val_From_Reduced_Ub (X, K + 1);      --  suffixes >= 0.
         Lemma_Val_From_Reduced_Ub (Y, K + 1);
         declare
            B1 : constant BI.Big_Integer := Val_From (X, K + 1);
            B2 : constant BI.Big_Integer := Val_From (Y, K + 1);
         begin
            --  Limb_Val(X(K)) + Base*B1 = Limb_Val(Y(K)) + Base*B2, low parts
            --  in [0,Base) -> the Base-multiples must match (no small multiple).
            if B1 < B2 then
               Lemma_BI_Mul_Mono (Base, 1, B2 - B1);
               pragma Assert (Base * (B2 - B1) >= Base);
               pragma Assert (False);
            elsif B2 < B1 then
               Lemma_BI_Mul_Mono (Base, 1, B1 - B2);
               pragma Assert (Base * (B1 - B2) >= Base);
               pragma Assert (False);
            end if;
            pragma Assert (B1 = B2);
            pragma Assert (Limb_Val (X (K)) = Limb_Val (Y (K)));
         end;
         Lemma_Limb_Val_Inj (X (K), Y (K));         --  X(K) = Y(K).
         Lemma_Val_From_Inj (X, Y, K + 1);          --  IH on the suffix.

      end if;
   end Lemma_Val_From_Inj;

   procedure Lemma_Val_Inj_Reduced (X, Y : Big_Nat) is
   begin
      Lemma_Val_From_Inj (X, Y, 0);
      pragma Assert (for all J in Limb_Index => X (J) = Y (J));
      pragma Assert (X = Y);
   end Lemma_Val_Inj_Reduced;

   procedure Lemma_Base_Pow_Ge_1 (N : Limb_Index) is
   begin
      Lemma_Limb_Val_Nonneg (Limb_Base - 1);       --  Base >= 1.
      if N /= 0 then
         Lemma_Base_Pow_Ge_1
           (N - 1);              --  Base_Pow(N) = Base*Base_Pow(N-1).
         Lemma_BI_Mul_Mono (Base, 1, Base_Pow (N - 1));
      end if;
   end Lemma_Base_Pow_Ge_1;

   procedure Lemma_Val_Canonical_Eq (X, Y : Big_Nat; Ka, Kb : BI.Big_Integer)
   is
      P : constant BI.Big_Integer := Base_Pow (5) - 5;
   begin
      Lemma_Base_Ge_6;                             --  Base >= 6.
      Lemma_Base_Pow_Ge_1 (4);
      pragma Assert (Base_Pow (5) = Base * Base_Pow (4));
      Lemma_BI_Mul_Mono
        (Base, 1, Base_Pow (4));   --  Base_Pow(5) >= Base >= 6.
      pragma Assert (P >= 1);
      Lemma_Val_Lt_P (X);                          --  0 <= Val(X) < P.
      Lemma_Val_Lt_P (Y);                          --  0 <= Val(Y) < P.
      --  Val(X) - Val(Y) = (Kb - Ka)*P, and |Val(X)-Val(Y)| < P -> Kb = Ka.
      if Ka < Kb then
         Lemma_BI_Mul_Mono (P, 1, Kb - Ka);
         pragma Assert ((Kb - Ka) * P >= P);       --  but = Val(X)-Val(Y) < P.
         pragma Assert (False);
      elsif Kb < Ka then
         Lemma_BI_Mul_Mono (P, 1, Ka - Kb);
         pragma Assert ((Ka - Kb) * P >= P);
         pragma Assert (False);
      end if;
      pragma Assert (Ka = Kb);
      pragma Assert (Val (X) = Val (Y));
      Lemma_Val_Inj_Reduced (X, Y);
   end Lemma_Val_Canonical_Eq;

   procedure Lemma_Val_B_From (GWc, GPr, B : Big_Nat; Kc : LLI; I : Limb_Index)
   is
   begin
      Lemma_Limb_Val_Mul (Kc, GPr (I));
      --  Limb_Val (Kc * GPr(I)) = Limb_Val (Kc) * Limb_Val (GPr(I)).
      Lemma_Limb_Val_Add (GWc (I), Kc * GPr (I));
      pragma
        Assert
          (Limb_Val (B (I))
             = Limb_Val (GWc (I)) + Limb_Val (Kc) * Limb_Val (GPr (I)));
      if I /= Max_Limbs - 1 then
         Lemma_Val_B_From (GWc, GPr, B, Kc, I + 1);   --  IH.
         pragma
           Assert
             (Val_From (B, I)
                = (Limb_Val (GWc (I)) + Limb_Val (Kc) * Limb_Val (GPr (I)))
                  + Base
                    * (Val_From (GWc, I + 1)
                       + Limb_Val (Kc) * Val_From (GPr, I + 1)));
         pragma
           Assert
             (Base * (Limb_Val (Kc) * Val_From (GPr, I + 1))
                = Limb_Val (Kc) * (Base * Val_From (GPr, I + 1)));
         pragma
           Assert
             (Limb_Val (Kc)
                * Limb_Val (GPr (I))
                + Limb_Val (Kc) * (Base * Val_From (GPr, I + 1))
                = Limb_Val (Kc)
                  * (Limb_Val (GPr (I)) + Base * Val_From (GPr, I + 1)));
         pragma
           Assert
             (Val_From (B, I)
                = Val_From (GWc, I) + Limb_Val (Kc) * Val_From (GPr, I));
      end if;
   end Lemma_Val_B_From;

   procedure Lemma_Val_B_Combine (GWc, GPr, B : Big_Nat; Kc : LLI) is
   begin
      Lemma_Val_B_From (GWc, GPr, B, Kc, 0);
   end Lemma_Val_B_Combine;

   procedure Lemma_Val_From_Nonneg (X : Big_Nat; I : Limb_Index) is
   begin
      Lemma_Limb_Val_Nonneg (Limb_Base - 1);       --  Base >= 1.
      Lemma_Limb_Val_Nonneg (X (I));
      if I /= Max_Limbs - 1 then
         Lemma_Val_From_Nonneg (X, I + 1);
      end if;
   end Lemma_Val_From_Nonneg;

   procedure Lemma_Field_Mul_Reduce_Cong
     (A, R : Big_Nat; Kg : out BI.Big_Integer)
   is
      Conv : constant Big_Nat := A * R;
      S    : constant Big_Nat := Sweep9_Out (Conv);
      R1   : constant Big_Nat := Fold_High_9_Out (S);
      CM   : constant Big_Nat := Carry_Model (R1);
      FM   : constant Big_Nat := Field_Mul (A, R);
      P    : constant BI.Big_Integer := Base_Pow (5) - 5;
      K    : LLI;
      C    : Carry_Array;
      Kf   : BI.Big_Integer;
   begin
      --  Conv = A*R: tight 9-limb bound + zero from 9 (mirror Field_Mul body).
      Lemma_Mul5_Cols (A, R, Conv);
      pragma
        Assert
          (for all KK in Limb_Index range 9 .. Max_Limbs - 1 => Conv (KK) = 0);
      pragma
        Assert
          (for all KK in Limb_Index => Conv (KK) <= LLI (KK + 1) * Two_Pow_54);
      pragma Assert (In_Bounds (Conv, Conv_Col_Cap));
      --  Val(S) = Val(Conv); Val(R1) = Val(Conv) - p*Val(High5(S)).
      Lemma_Val_Sweep9 (Conv);
      Lemma_Sweep9_Conv (Conv);                    --  S(9) <= Conv_Carry_Cap.
      Lemma_Val_FH9_Out (S);
      pragma Assert (Val (R1) = Val (Conv) - P * Val (High5 (S)));
      --  Carry_Model lift: Val(CM) = Val(R1) - Limb_Val(K)*p.
      Lemma_Sweep5_Chain_Tight (R1);
      Lemma_Carry_Mod_P_Wide (R1, K, C);
      Lemma_SValEq_To_Val (R1, CM + Smul (K, P_Prime), C);
      pragma Assert (Val (R1) = Val (CM + Smul (K, P_Prime)));
      Lemma_Val_Add (CM, Smul (K, P_Prime));
      Lemma_Val_Smul (K, P_Prime);
      Lemma_Val_P_Prime;
      Lemma_BI_MulR_Cong (Limb_Val (K), Val (P_Prime), P);
      pragma Assert (Val (Smul (K, P_Prime)) = Limb_Val (K) * P);
      pragma Assert (Val (CM) = Val (R1) - Limb_Val (K) * P);
      --  Canonical lift: Val(FM) = Val(CM) - Kf*p; FM = Canonical(CM).
      Lemma_Canonical_Val_Cong (CM, Kf);
      pragma Assert (FM = Canonical (CM));
      Lemma_Val_Cong (FM, Canonical (CM));
      pragma Assert (Val (FM) = Val (CM) - Kf * P);
      pragma
        Assert
          (Val (FM)
             = Val (Conv) - P * Val (High5 (S)) - Limb_Val (K) * P - Kf * P);
      --  Collect the three p-multiples into Kg.
      Lemma_BI_Factor3 (Val (High5 (S)), Limb_Val (K), Kf, P);
      Kg := Val (High5 (S)) + Limb_Val (K) + Kf;
      pragma Assert (Val (FM) + Kg * P = Val (Conv));
      --  Kg >= 0.
      Lemma_Val_From_Nonneg (High5 (S), 0);        --  Val(High5(S)) >= 0.
      Lemma_Limb_Val_Nonneg (K);
   end Lemma_Field_Mul_Reduce_Cong;

   procedure Lemma_Field_Mul_P_Zero (R : Big_Nat) is
      FM : constant Big_Nat := Field_Mul (P_Prime, R);
      P  : constant BI.Big_Integer := Base_Pow (5) - 5;
      Kg : BI.Big_Integer;
      Ka : BI.Big_Integer;
   begin
      Lemma_Field_Mul_Reduce_Cong
        (P_Prime, R, Kg);   --  Val(FM)+Kg*p = Val(P_Prime*R).
      Lemma_Val_P_Mul
        (R);                            --  Val(P_Prime*R) = p*Val(R).
      Ka := Val (R) - Kg;
      pragma Assert (Val (FM) + Kg * P = P * Val (R));
      pragma Assert (Val (FM) = P * Val (R) - Kg * P);
      Lemma_BI_Factor2
        (Val (R), Kg, P);              --  P*Val(R) - Kg*P = (Val(R)-Kg)*P.
      pragma Assert (Val (FM) = Ka * P);
      --  Ka >= 0: Val(FM) >= 0 and p >= 1.
      Lemma_Base_Ge_6;
      Lemma_Base_Pow_Ge_1 (4);
      pragma Assert (Base_Pow (5) = Base * Base_Pow (4));
      Lemma_BI_Mul_Mono (Base, 1, Base_Pow (4));
      Lemma_Val_Lt_P (FM);
      if Ka < 0 then
         Lemma_BI_Mul_Mono (P, Ka, -1);
         pragma Assert (False);
      end if;
      Lemma_Val_Canonical_Zero (FM, Ka);
   end Lemma_Field_Mul_P_Zero;

   procedure Lemma_Mul_Conv_Bound (A, B, AB : Big_Nat) is
   begin
      Lemma_Bounds_Mono (A, In_Cap, Mul_Cap);
      Lemma_Bounds_Mono (B, In_Cap, Mul_Cap);
      Lemma_Mul5_Cols (A, B, AB);
      pragma
        Assert
          (for all KK in Limb_Index range 9 .. Max_Limbs - 1 => AB (KK) = 0);
      pragma
        Assert
          (for all KK in Limb_Index => AB (KK) <= LLI (KK + 1) * Two_Pow_54);
   end Lemma_Mul_Conv_Bound;

   procedure Lemma_Field_Mul_Bridge (Acc, R : Big_Nat) is
      CA  : constant Big_Nat := Canonical (Acc);
      GWc : constant Big_Nat := CA * R;
      GPr : constant Big_Nat := P_Prime * R;
      FMa : constant Big_Nat := Field_Mul (Acc, R);
      FMc : constant Big_Nat := Field_Mul (CA, R);
      P   : constant BI.Big_Integer := Base_Pow (5) - 5;
      Kc  : LLI;
      Cc  : Carry_Array;
      Bm  : Big_Nat;
      Kg1 : BI.Big_Integer;
      Kg2 : BI.Big_Integer;
      Kb  : BI.Big_Integer;
   begin
      --  CA = Canonical (Acc): In_Cap, zero from 5 (Canonical Post).
      Lemma_Bounds_Mono (CA, In_Cap, Mul_Cap);

      --  Congruence Acc == CA + Kc*P_Prime, with a chain that is zero from 5.
      Lemma_Canonical_Cong (Acc, Kc, Cc);
      Lemma_SVal_Chain_Zero_High (Acc, CA + Smul (Kc, P_Prime), Cc);

      --  Convolution operands and their tight column bounds (mirror Reduce_Cong).
      Bm := [for I in Limb_Index => GWc (I) + Kc * GPr (I)];
      Lemma_Mul_Conv_Bound (CA, R, GWc);
      Lemma_Mul_Conv_Bound (P_Prime, R, GPr);
      pragma Assert (In_Bounds (Bm, Add_Cap));

      --  Lift the congruence through the convolution: SVal_Wide (Acc*R, Bm, ..).
      Lemma_Mul_Cong_Prime (Acc, CA, P_Prime, R, GWc, GPr, Bm, Kc, Cc);
      Lemma_SVal_To_Val (Acc * R, Bm, Carry_Conv (Cc, R));
      --  Val (Acc*R) = Val (Bm) = Val (GWc) + Limb_Val (Kc) * Val (GPr).
      Lemma_Val_B_Combine (GWc, GPr, Bm, Kc);
      Lemma_Val_P_Mul
        (R);                          --  Val (GPr) = P * Val (R).
      Lemma_BI_MulR_Cong (Limb_Val (Kc), Val (GPr), P * Val (R));
      pragma
        Assert (Val (Acc * R) = Val (GWc) + Limb_Val (Kc) * (P * Val (R)));

      --  Reduce both products to their field residues.
      Lemma_Field_Mul_Reduce_Cong
        (Acc, R, Kg1);    --  Val(FMa)+Kg1*p = Val(Acc*R).
      Lemma_Field_Mul_Reduce_Cong
        (CA, R, Kg2);     --  Val(FMc)+Kg2*p = Val(GWc).
      pragma Assert (Val (FMc) + Kg2 * P = Val (GWc));
      pragma Assert (Val (FMa) + Kg1 * P = Val (Acc * R));

      --  Compose: Val(FMa)+Kg1*p = Val(FMc) + (Kg2 + Limb_Val(Kc)*Val(R))*p.
      Lemma_BI_FactorMul (Limb_Val (Kc), Val (R), Kg2, P);
      Kb := Kg2 + Limb_Val (Kc) * Val (R);
      pragma Assert (Val (FMa) + Kg1 * P = Val (FMc) + Kb * P);

      --  Kb >= 0: Kg2 >= 0, Limb_Val(Kc) >= 0, Val(R) >= 0.
      Lemma_Limb_Val_Nonneg (Kc);
      Lemma_Val_From_Nonneg (R, 0);
      Lemma_BI_Mul_Mono (Limb_Val (Kc), 0, Val (R));

      Lemma_Val_Canonical_Eq (FMa, FMc, Kg1, Kb);
   end Lemma_Field_Mul_Bridge;

   procedure Lemma_Val_Canonical_Zero (X : Big_Nat; Ka : BI.Big_Integer) is
   begin
      Lemma_Val_From_Zero_High (Zero, 0, 0);       --  Val(Zero) = 0.
      pragma Assert (not Sub_Cond (Zero));         --  Zero(4)=0 /= In_Cap.
      Lemma_Val_Canonical_Eq
        (X, Zero, 0, Ka);     --  Val(X)+0*p = Val(Zero)+Ka*p.
   end Lemma_Val_Canonical_Zero;

   procedure Lemma_SValEq_To_Val (A, B : Big_Nat; C : Carry_Array) is
   begin
      Lemma_SVal_To_Wide (A, B, C);                --  SVal_Wide (A, B, C).
      Lemma_SVal_To_Val (A, B, C);                 --  Val (A) = Val (B).
   end Lemma_SValEq_To_Val;

   procedure Lemma_Canonical_Val_Cong (B : Big_Nat; Kf : out BI.Big_Integer) is
      N   : constant Norm_Result := Normalize (B);
      NV  : constant Big_Nat := N.Val;
      PM  : constant Big_Nat := N.PMult;
      RC  : constant Big_Nat := Reduce_Canonical (NV);
      SS  : constant Big_Nat := Sub_Sel_P (Sweep5_Out (NV));
      P_V : constant BI.Big_Integer := Base_Pow (5) - 5;
   begin
      Lemma_Limb_Val_Nonneg (N.KMult);             --  Limb_Val(KMult) >= 0.

      --  Step 1: Val(B) = Val(NV) + Limb_Val(KMult) * p.
      Lemma_SValEq_To_Val (B, NV + PM, N.Cn);      --  Val(B) = Val(NV + PM).
      Lemma_Val_Add (NV, PM);                      --  = Val(NV) + Val(PM).
      Lemma_Val_Cong (PM, Smul (N.KMult, P_Prime));
      Lemma_Val_Smul
        (N.KMult,
         P_Prime);           --  Val(PM) = Limb_Val(KMult)*Val(P_Prime).
      Lemma_Val_P_Prime;                           --  Val(P_Prime) = P_V.
      pragma Assert (Val (B) = Val (NV) + Limb_Val (N.KMult) * P_V);

      --  Step 2: Val(NV) = Val(Canonical(B)) + (Sub_Cond? p : 0).
      Lemma_Reduce_Canonical (NV);
      pragma
        Assert
          (SC_Bounded (Sweep5_Chain (NV)));   --  Carry_Bounded => SC_Bounded.
      Lemma_SValEq_To_Val (NV, RC + SS, Sweep5_Chain (NV));
      Lemma_Val_Add
        (RC, SS);                      --  Val(NV) = Val(RC) + Val(SS).
      pragma Assert (Canonical (B) = RC);          --  definitional.

      if Sub_Cond (Sweep5_Out (NV)) then
         Lemma_Val_Cong (SS, P_Prime);
         Lemma_Val_P_Prime;
         pragma Assert (Val (SS) = P_V);
         Kf := Limb_Val (N.KMult) + 1;
      else
         Lemma_Val_Cong (SS, Zero);
         Lemma_Val_From_Zero_High (Zero, 0, 0);
         pragma Assert (Val (SS) = 0);
         Kf := Limb_Val (N.KMult);
      end if;
      pragma Assert (Val (B) = Val (RC) + Kf * P_V);
   end Lemma_Canonical_Val_Cong;

   procedure Lemma_Val_Sweep9 (Conv : Big_Nat) is
   begin
      Lemma_Bounds_Mono
        (Conv, Conv_Col_Cap, Prod_Cap);  --  Conv_Col_Cap <= Prod_Cap.
      Lemma_Sweep9
        (Conv);                               --  Val_Eq(Conv, Sweep9_Out, chain).
      Lemma_ValEq_To_Val (Conv, Sweep9_Out (Conv), Sweep9_Chain (Conv));
   end Lemma_Val_Sweep9;

   procedure Lemma_FH9_Split (B : Big_Nat) is
      O  : constant Big_Nat := Fold_High_9_Out (B);
      PP : constant Big_Nat := Fold_High_9_PrimePart (B);
      Sm : constant Big_Nat := O + PP;
   begin
      pragma
        Assert
          (for all K in Limb_Index => Fold_High_9_Plus_P (B) (K) = Sm (K));
   end Lemma_FH9_Split;

   procedure Lemma_Val_FH9_Out (S : Big_Nat) is
      O  : constant Big_Nat := Fold_High_9_Out (S);
      PP : constant Big_Nat := Fold_High_9_PrimePart (S);
   begin
      Lemma_FH9_Split (S);                          --  Plus_P(S) = O + PP.
      Lemma_Fold_High_9
        (S);                        --  Val_Eq(Plus_P(S), S, chain).
      Lemma_ValEq_To_Val (Fold_High_9_Plus_P (S), S, Fold_High_9_Chain (S));
      Lemma_Val_Cong (Fold_High_9_Plus_P (S), O + PP);
      Lemma_Val_Add
        (O, PP);                        --  Val(O+PP) = Val(O)+Val(PP).
      Lemma_Val_PrimePart
        (S);                      --  Val(PP) = p*Val(High5(S)).
   end Lemma_Val_FH9_Out;

   procedure Lemma_BI_Reassoc (X, Y, Z : BI.Big_Integer) is
   begin
      null;
   end Lemma_BI_Reassoc;

   procedure Lemma_BI_Assoc (X, Y, Z : BI.Big_Integer) is
   begin
      null;
   end Lemma_BI_Assoc;

   procedure Lemma_BI_Factor5 (A, B, C, D, E, P : BI.Big_Integer) is
   begin
      null;
   end Lemma_BI_Factor5;

   procedure Lemma_BI_MulR_Cong (P, X, Y : BI.Big_Integer) is
   begin
      null;
   end Lemma_BI_MulR_Cong;

   procedure Lemma_BI_FieldKa (VR, VH, LK, Kf, P : BI.Big_Integer) is
   begin
      null;
   end Lemma_BI_FieldKa;

   procedure Lemma_BI_Factor3 (VH, LK, Kf, P : BI.Big_Integer) is
   begin
      null;
   end Lemma_BI_Factor3;

   procedure Lemma_BI_Factor2 (VR, Kg, P : BI.Big_Integer) is
   begin
      null;
   end Lemma_BI_Factor2;

   procedure Lemma_BI_FactorMul (Kc_v, Vr, Kg2, P : BI.Big_Integer) is
   begin
      null;
   end Lemma_BI_FactorMul;

   procedure Lemma_Nested5_To_Flat (A0, A1, A2, A3, A4 : BI.Big_Integer) is
   begin
      pragma Assert (Base_Pow (0) = 1);
      pragma Assert (Base_Pow (1) = Base * Base_Pow (0));
      pragma Assert (Base_Pow (2) = Base * Base_Pow (1));
      pragma Assert (Base_Pow (3) = Base * Base_Pow (2));
      pragma Assert (Base_Pow (4) = Base * Base_Pow (3));
      --  All per-term shift facts Base*(Aj*Base_Pow(k)) = Aj*Base_Pow(k+1).
      Lemma_BI_Reassoc (Base, A4, Base_Pow (0));
      Lemma_BI_Reassoc (Base, A4, Base_Pow (1));
      Lemma_BI_Reassoc (Base, A4, Base_Pow (2));
      Lemma_BI_Reassoc (Base, A4, Base_Pow (3));
      Lemma_BI_Reassoc (Base, A3, Base_Pow (0));
      Lemma_BI_Reassoc (Base, A3, Base_Pow (1));
      Lemma_BI_Reassoc (Base, A3, Base_Pow (2));
      Lemma_BI_Reassoc (Base, A2, Base_Pow (0));
      Lemma_BI_Reassoc (Base, A2, Base_Pow (1));
      Lemma_BI_Reassoc (Base, A1, Base_Pow (0));
      pragma Assert (Base * (A4 * Base_Pow (0)) = A4 * Base_Pow (1));
      pragma Assert (Base * (A4 * Base_Pow (1)) = A4 * Base_Pow (2));
      pragma Assert (Base * (A4 * Base_Pow (2)) = A4 * Base_Pow (3));
      pragma Assert (Base * (A4 * Base_Pow (3)) = A4 * Base_Pow (4));
      pragma Assert (Base * (A3 * Base_Pow (0)) = A3 * Base_Pow (1));
      pragma Assert (Base * (A3 * Base_Pow (1)) = A3 * Base_Pow (2));
      pragma Assert (Base * (A3 * Base_Pow (2)) = A3 * Base_Pow (3));
      pragma Assert (Base * (A2 * Base_Pow (0)) = A2 * Base_Pow (1));
      pragma Assert (Base * (A2 * Base_Pow (1)) = A2 * Base_Pow (2));
      pragma Assert (Base * (A1 * Base_Pow (0)) = A1 * Base_Pow (1));
      --  Bottom-up nested -> flat, threading the previous level's flat form.
      pragma Assert (A4 = A4 * Base_Pow (0));
      pragma Assert (A3 + Base * A4 = A3 * Base_Pow (0) + A4 * Base_Pow (1));
      pragma
        Assert
          (A2 + Base * (A3 * Base_Pow (0) + A4 * Base_Pow (1))
             = A2 * Base_Pow (0) + A3 * Base_Pow (1) + A4 * Base_Pow (2));
      pragma
        Assert
          (A1
             + Base
               * (A2 * Base_Pow (0) + A3 * Base_Pow (1) + A4 * Base_Pow (2))
             = A1
               * Base_Pow (0)
               + A2 * Base_Pow (1)
               + A3 * Base_Pow (2)
               + A4 * Base_Pow (3));
      pragma
        Assert
          (A0
             + Base
               * (A1
                  * Base_Pow (0)
                  + A2 * Base_Pow (1)
                  + A3 * Base_Pow (2)
                  + A4 * Base_Pow (3))
             = A0
               * Base_Pow (0)
               + A1 * Base_Pow (1)
               + A2 * Base_Pow (2)
               + A3 * Base_Pow (3)
               + A4 * Base_Pow (4));
   end Lemma_Nested5_To_Flat;

   procedure Lemma_Val_High5_Flat (B : Big_Nat) is
      H : constant Big_Nat := High5 (B);
   begin
      Lemma_Val_From_Zero_High (H, 5, 5);          --  Val_From(H,5) = 0.
      --  Val (H) in nested Horner form (Val_From unfolds, limbs are B(5..9)).
      pragma Assert (Val_From (H, 4) = Limb_Val (B (9)));
      pragma
        Assert (Val_From (H, 3) = Limb_Val (B (8)) + Base * Val_From (H, 4));
      pragma
        Assert (Val_From (H, 2) = Limb_Val (B (7)) + Base * Val_From (H, 3));
      pragma
        Assert (Val_From (H, 1) = Limb_Val (B (6)) + Base * Val_From (H, 2));
      pragma
        Assert (Val_From (H, 0) = Limb_Val (B (5)) + Base * Val_From (H, 1));
      pragma
        Assert
          (Val (H)
             = Limb_Val (B (5))
               + Base
                 * (Limb_Val (B (6))
                    + Base
                      * (Limb_Val (B (7))
                         + Base
                           * (Limb_Val (B (8)) + Base * Limb_Val (B (9))))));
      --  Nested -> flat (isolated degree-4 ring identity).
      Lemma_Nested5_To_Flat
        (Limb_Val (B (5)),
         Limb_Val (B (6)),
         Limb_Val (B (7)),
         Limb_Val (B (8)),
         Limb_Val (B (9)));
   end Lemma_Val_High5_Flat;

   procedure Lemma_Val_PrimeTerm (S : LLI; J : Limb_Index) is
   begin
      Lemma_Val_Smul
        (S,
         Shift_By (P_Prime, J));   --  Val(Smul) = Limb_Val(S)*Val(Shift_By).
      Lemma_Val_Shift_By
        (P_Prime, J);             --  Val(Shift_By) = Base_Pow(J)*Val(P_Prime).
      Lemma_Val_P_Prime;                           --  Val(P_Prime) = Base_Pow(5)-5.
      Lemma_BI_Assoc (Limb_Val (S), Base_Pow (J), Base_Pow (5) - 5);
   end Lemma_Val_PrimeTerm;

   procedure Lemma_PrimePart_Decomp (B : Big_Nat) is
      T0  : constant Big_Nat := Smul (B (5), Shift_By (P_Prime, 0));
      T1  : constant Big_Nat := Smul (B (6), Shift_By (P_Prime, 1));
      T2  : constant Big_Nat := Smul (B (7), Shift_By (P_Prime, 2));
      T3  : constant Big_Nat := Smul (B (8), Shift_By (P_Prime, 3));
      T4  : constant Big_Nat := Smul (B (9), Shift_By (P_Prime, 4));
      --  Tight per-limb product bounds keep every partial sum within Add_Cap.
      pragma Assert (for all K in Limb_Index => T0 (K) <= In_Cap * In_Cap);
      pragma Assert (for all K in Limb_Index => T1 (K) <= In_Cap * In_Cap);
      pragma Assert (for all K in Limb_Index => T2 (K) <= In_Cap * In_Cap);
      pragma Assert (for all K in Limb_Index => T3 (K) <= In_Cap * In_Cap);
      pragma
        Assert (for all K in Limb_Index => T4 (K) <= Fold9_Top_Cap * In_Cap);
      S1  : constant Big_Nat := T0 + T1;
      S2  : constant Big_Nat := S1 + T2;
      S3  : constant Big_Nat := S2 + T3;
      Sum : constant Big_Nat := S3 + T4;
   begin
      pragma
        Assert
          (for all K in Limb_Index => Sum (K) = Fold_High_9_PrimePart (B) (K));
   end Lemma_PrimePart_Decomp;

   procedure Lemma_Val_PrimePart (B : Big_Nat) is
      P0  : constant Big_Nat := Shift_By (P_Prime, 0);
      P1  : constant Big_Nat := Shift_By (P_Prime, 1);
      P2  : constant Big_Nat := Shift_By (P_Prime, 2);
      P3  : constant Big_Nat := Shift_By (P_Prime, 3);
      P4  : constant Big_Nat := Shift_By (P_Prime, 4);
      T0  : constant Big_Nat := Smul (B (5), P0);
      T1  : constant Big_Nat := Smul (B (6), P1);
      T2  : constant Big_Nat := Smul (B (7), P2);
      T3  : constant Big_Nat := Smul (B (8), P3);
      T4  : constant Big_Nat := Smul (B (9), P4);
      pragma Assert (for all K in Limb_Index => T0 (K) <= In_Cap * In_Cap);
      pragma Assert (for all K in Limb_Index => T1 (K) <= In_Cap * In_Cap);
      pragma Assert (for all K in Limb_Index => T2 (K) <= In_Cap * In_Cap);
      pragma Assert (for all K in Limb_Index => T3 (K) <= In_Cap * In_Cap);
      pragma
        Assert (for all K in Limb_Index => T4 (K) <= Fold9_Top_Cap * In_Cap);
      S1  : constant Big_Nat := T0 + T1;
      S2  : constant Big_Nat := S1 + T2;
      S3  : constant Big_Nat := S2 + T3;
      Sum : constant Big_Nat := S3 + T4;
      P_V : constant BI.Big_Integer := Base_Pow (5) - 5;
   begin
      Lemma_PrimePart_Decomp
        (B);              --  Fold_High_9_PrimePart(B) = Sum.

      --  Val of each term: Limb_Val (B(5+j)) * Base_Pow(j) * p.
      Lemma_Val_Smul (B (5), P0);
      Lemma_Val_Shift_By (P_Prime, 0);
      Lemma_Val_Smul (B (6), P1);
      Lemma_Val_Shift_By (P_Prime, 1);
      Lemma_Val_Smul (B (7), P2);
      Lemma_Val_Shift_By (P_Prime, 2);
      Lemma_Val_Smul (B (8), P3);
      Lemma_Val_Shift_By (P_Prime, 3);
      Lemma_Val_Smul (B (9), P4);
      Lemma_Val_Shift_By (P_Prime, 4);
      Lemma_Val_P_Prime;

      --  Val of the sum (chain Val_Add over the named partials).
      Lemma_Val_Add (T0, T1);
      Lemma_Val_Add (S1, T2);
      Lemma_Val_Add (S2, T3);
      Lemma_Val_Add (S3, T4);
      Lemma_Val_Cong (Fold_High_9_PrimePart (B), Sum);

      --  Each term fully evaluated via the isolated term lemma:
      --  Val (Tj) = Limb_Val (B(5+j)) * Base_Pow(j) * P_V.
      Lemma_Val_PrimeTerm (B (5), 0);
      Lemma_Val_PrimeTerm (B (6), 1);
      Lemma_Val_PrimeTerm (B (7), 2);
      Lemma_Val_PrimeTerm (B (8), 3);
      Lemma_Val_PrimeTerm (B (9), 4);

      --  Val (High5 (B)) flattened (isolated lemma) + factor out P_V.
      Lemma_Val_High5_Flat (B);
      pragma
        Assert
          (Val (Sum)
             = Limb_Val (B (5))
               * Base_Pow (0)
               * P_V
               + Limb_Val (B (6)) * Base_Pow (1) * P_V
               + Limb_Val (B (7)) * Base_Pow (2) * P_V
               + Limb_Val (B (8)) * Base_Pow (3) * P_V
               + Limb_Val (B (9)) * Base_Pow (4) * P_V);
      Lemma_BI_Factor5
        (Limb_Val (B (5)) * Base_Pow (0),
         Limb_Val (B (6)) * Base_Pow (1),
         Limb_Val (B (7)) * Base_Pow (2),
         Limb_Val (B (8)) * Base_Pow (3),
         Limb_Val (B (9)) * Base_Pow (4),
         P_V);
      pragma
        Assert
          (Val (Sum)
             = P_V
               * (Limb_Val (B (5))
                  * Base_Pow (0)
                  + Limb_Val (B (6)) * Base_Pow (1)
                  + Limb_Val (B (7)) * Base_Pow (2)
                  + Limb_Val (B (8)) * Base_Pow (3)
                  + Limb_Val (B (9)) * Base_Pow (4)));
      Lemma_BI_MulR_Cong
        (P_V,
         Limb_Val (B (5))
         * Base_Pow (0)
         + Limb_Val (B (6)) * Base_Pow (1)
         + Limb_Val (B (7)) * Base_Pow (2)
         + Limb_Val (B (8)) * Base_Pow (3)
         + Limb_Val (B (9)) * Base_Pow (4),
         Val (High5 (B)));
      pragma Assert (Val (Sum) = P_V * Val (High5 (B)));
   end Lemma_Val_PrimePart;

   procedure Lemma_Val_Shift_By (B : Big_Nat; N : Limb_Index) is
   begin
      if N = 0 then
         pragma
           Assert (for all K in Limb_Index => Shift_By (B, 0) (K) = B (K));
         pragma Assert (Shift_By (B, 0) = B);     --  Base_Pow (0) = 1.
         Lemma_Val_Cong (Shift_By (B, 0), B);
      else
         Lemma_Val_Shift_By (B, N - 1);           --  IH.
         declare
            SN1 : constant Big_Nat := Shift_By (B, N - 1);
            SN  : constant Big_Nat := Shift_By (B, N);
         begin
            pragma Assert (SN1 (Max_Limbs - 1) = 0);   --  = B (Max_Limbs - N).
            Lemma_Val_Shift1
              (SN1);              --  Val (Shift1g SN1) = Base * Val (SN1).
            pragma
              Assert (for all K in Limb_Index => SN (K) = Shift1g (SN1) (K));
            pragma Assert (SN = Shift1g (SN1));
            Lemma_Val_Cong (SN, Shift1g (SN1));
            pragma Assert (Val (SN) = Base * Val (SN1));
            pragma Assert (Base_Pow (N) = Base * Base_Pow (N - 1));
         end;
      end if;
   end Lemma_Val_Shift_By;

end Tls_Core.Ghost_Bignum.Value;
