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
         Lemma_Limb_Val_Succ (X + Y - 1); --  Limb_Val (X+Y) = Limb_Val (X+Y-1)+1.
         Lemma_Limb_Val_Succ (Y - 1);     --  Limb_Val (Y)   = Limb_Val (Y-1)+1.
      else
         Lemma_Limb_Val_Add (X, Y + 1);   --  IH on X + (Y + 1).
         Lemma_Limb_Val_Pred (X + Y + 1); --  Limb_Val (X+Y) = Limb_Val (X+Y+1)-1.
         Lemma_Limb_Val_Pred (Y + 1);     --  Limb_Val (Y)   = Limb_Val (Y+1)-1.
      end if;
   end Lemma_Limb_Val_Add;

   procedure Lemma_Limb_Val_Neg (X : Val_Int) is
   begin
      Lemma_Limb_Val_Add (X, -X);  --  Limb_Val (0) = Limb_Val (X) + Limb_Val (-X).
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
         pragma Assert
           (Limb_Val (X * Y) = Limb_Val (X) * Limb_Val (Y - 1) + Limb_Val (X));
         pragma Assert
           (Limb_Val (X) * Limb_Val (Y - 1) + Limb_Val (X)
            = Limb_Val (X) * (Limb_Val (Y - 1) + 1));
      else
         pragma Assert (X * Y = X * (Y + 1) - X);
         Lemma_Limb_Val_Mul (X, Y + 1);                  --  IH.
         Lemma_Limb_Val_Add (X * (Y + 1), -X);           --  split the product.
         Lemma_Limb_Val_Neg (X);                         --  Limb_Val (-X).
         Lemma_Limb_Val_Pred (Y + 1);                    --  Limb_Val (Y) bump.
         pragma Assert
           (Limb_Val (X * Y) = Limb_Val (X) * Limb_Val (Y + 1) - Limb_Val (X));
         pragma Assert
           (Limb_Val (X) * Limb_Val (Y + 1) - Limb_Val (X)
            = Limb_Val (X) * (Limb_Val (Y + 1) - 1));
      end if;
   end Lemma_Limb_Val_Mul;

   procedure Lemma_Val_Tele (A, B : Big_Nat; C : Carry_Array; I : Limb_Index) is
   begin
      --  Collapse column I:  A(I)+C(I) = B(I)+Limb_Base*C(I+1)  (SVal_Wide).
      Lemma_Limb_Val_Add (A (I), C (I));
      Lemma_Limb_Val_Add (B (I), Limb_Base * C (I + 1));
      Lemma_Limb_Val_Mul (Limb_Base, C (I + 1));
      pragma Assert
        (Limb_Val (A (I)) + Limb_Val (C (I))
         = Limb_Val (B (I)) + Base * Limb_Val (C (I + 1)));

      if I = Max_Limbs - 1 then
         pragma Assert (C (I + 1) = 0);            --  C(Max_Limbs) = 0.
      else
         Lemma_Val_Tele (A, B, C, I + 1);          --  IH at I+1.
         pragma Assert
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
      Lemma_Limb_Val_Mul (A (I), S);   --  Limb_Val (A(I)*S) = Limb_Val(A(I))*Limb_Val(S).
      pragma Assert (Smul (S, A) (I) = S * A (I));
      pragma Assert
        (Limb_Val (Smul (S, A) (I)) = Limb_Val (S) * Limb_Val (A (I)));
      if I /= Max_Limbs - 1 then
         Lemma_Val_From_Smul (S, A, I + 1);        --  IH.
         pragma Assert
           (Val_From (Smul (S, A), I)
            = Limb_Val (S) * Limb_Val (A (I))
              + Base * (Limb_Val (S) * Val_From (A, I + 1)));
         pragma Assert
           (Limb_Val (S) * Limb_Val (A (I))
            + Base * (Limb_Val (S) * Val_From (A, I + 1))
            = Limb_Val (S) * (Limb_Val (A (I)) + Base * Val_From (A, I + 1)));
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
         pragma Assert
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
         Lemma_Limb_Val_Add
           (Mul_Col (A, B, K, T - 1), A (T) * B (K - T));
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
         Lemma_Val_From_Cong (X, Y, I + 1);       --  IH; X (I) = Y (I) from X = Y.
      end if;
   end Lemma_Val_From_Cong;

   procedure Lemma_Val_Cong (X, Y : Big_Nat) is
   begin
      Lemma_Val_From_Cong (X, Y, 0);
   end Lemma_Val_Cong;

   procedure Lemma_Mul_Unit_Col (A : Big_Nat; V : LLI; M, K, T : Limb_Index) is
   begin
      pragma Assert
        (Unit_Limb (V, M) (K - T) = (if K - T = M then V else 0));
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
         pragma Loop_Invariant
           (for all KK in Limb_Index range 0 .. K => P (KK) = SS (KK));
      end loop;
      pragma Assert (P = SS);
   end Lemma_Mul_Unit;

   procedure Lemma_Mul_Col_Cong (A, X, Y : Big_Nat; K, T : Limb_Index) is
   begin
      if T /= 0 then
         Lemma_Mul_Col_Cong (A, X, Y, K, T - 1);   --  IH; X (K-T) = Y (K-T) from X = Y.
      end if;
   end Lemma_Mul_Col_Cong;

   procedure Lemma_Mul_Cong_R (A, X, Y : Big_Nat) is
      PX : constant Big_Nat := A * X;
      PY : constant Big_Nat := A * Y;
   begin
      for K in Limb_Index loop
         Lemma_Mul_Col_Cong (A, X, Y, K, K);
         pragma Assert (PX (K) = PY (K));
         pragma Loop_Invariant
           (for all KK in Limb_Index range 0 .. K => PX (KK) = PY (KK));
      end loop;
      pragma Assert (PX = PY);
   end Lemma_Mul_Cong_R;

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
         pragma Loop_Invariant
           (for all KK in Limb_Index range 0 .. K => P (KK) = 0);
      end loop;
      pragma Assert (P = Zero);
   end Lemma_Mul_Zero_R;

   procedure Lemma_Val_Unit (V : LLI; M : Limb_Index) is
      U0 : constant Big_Nat := Unit_Limb (V, 0);
   begin
      Lemma_Val_From_Zero_High (U0, 1, 1);     --  Val_From (U0, 1) = 0.
      pragma Assert (Val (U0) = Limb_Val (V));
      pragma Assert
        (for all K in Limb_Index => Unit_Limb (V, M) (K) = Shift_By (U0, M) (K));
      pragma Assert (Unit_Limb (V, M) = Shift_By (U0, M));
      Lemma_Val_Cong (Unit_Limb (V, M), Shift_By (U0, M));
      Lemma_Val_Shift_By (U0, M);              --  Val (Shift_By (U0,M)) = Base_Pow(M)*Val(U0).
   end Lemma_Val_Unit;

   procedure Lemma_Val_Lo_Step (B : Big_Nat; M : Limb_Index) is
      Lo : constant Big_Nat := B_Lo (B, M);
      U  : constant Big_Nat := Unit_Limb (B (M), M);
   begin
      pragma Assert
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
            pragma Assert
              (for all K in Limb_Index => LoM (K) = Lo1 (K) + U (K));
            Lemma_Mul_Distrib (A, Lo1, U, LoM);       --  A*LoM = A*Lo1 + A*U.
            Lemma_Mul_Unit (A, B (M - 1), M - 1);     --  A*U = Smul (B(M-1), SH).
            Lemma_Val_Add (A * Lo1, A * U);
            Lemma_Val_Cong (A * LoM, A * Lo1 + A * U);
            Lemma_Val_Cong (A * U, Smul (B (M - 1), SH));
            Lemma_Val_Smul (B (M - 1), SH);
            pragma Assert
              (for all K in Limb_Index range Max_Limbs - (M - 1) .. Max_Limbs - 1
               => A (K) = 0);
            Lemma_Val_Shift_By (A, M - 1);            --  Val(SH) = Base_Pow(M-1)*Val(A).
            Lemma_Val_Lo_Step (B, M - 1);             --  Val(LoM) = Val(Lo1)+Limb_Val(B(M-1))*Base_Pow(M-1).
            pragma Assert
              (Val (A * LoM)
               = Val (A) * Val (Lo1)
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
      Lemma_Limb_Val_Pred (Limb_Base);         --  Limb_Val (In_Cap)   = Base - 1.
      Lemma_Limb_Val_Pred (Limb_Base - 1);
      Lemma_Limb_Val_Pred (Limb_Base - 2);
      Lemma_Limb_Val_Pred (Limb_Base - 3);
      Lemma_Limb_Val_Pred (Limb_Base - 4);     --  Limb_Val (In_Cap-4) = Base - 5.
      Lemma_Val_From_Zero_High (P_Prime, 5, 5);
      pragma Assert (Limb_Val (P_Prime (0)) = Base - 5);
      pragma Assert
        (for all K in Limb_Index range 1 .. 4 => Limb_Val (P_Prime (K)) = Base - 1);
      --  Telescope the all-(Base-1) tail: Val_From (P_Prime, k) = Base**(5-k) - 1.
      pragma Assert (Val_From (P_Prime, 4) = Base - 1);
      pragma Assert (Val_From (P_Prime, 3) = Base * Base - 1);
      pragma Assert (Val_From (P_Prime, 2) = Base * Base * Base - 1);
      pragma Assert (Val_From (P_Prime, 1) = Base * Base * Base * Base - 1);
      pragma Assert
        (Val_From (P_Prime, 0) = Base * Base * Base * Base * Base - 5);
      pragma Assert (Base_Pow (5) = Base * (Base * (Base * (Base * Base))));
   end Lemma_Val_P_Prime;

   procedure Lemma_Val_Shift_By (B : Big_Nat; N : Limb_Index) is
   begin
      if N = 0 then
         pragma Assert (for all K in Limb_Index => Shift_By (B, 0) (K) = B (K));
         pragma Assert (Shift_By (B, 0) = B);     --  Base_Pow (0) = 1.
         Lemma_Val_Cong (Shift_By (B, 0), B);
      else
         Lemma_Val_Shift_By (B, N - 1);           --  IH.
         declare
            SN1 : constant Big_Nat := Shift_By (B, N - 1);
            SN  : constant Big_Nat := Shift_By (B, N);
         begin
            pragma Assert (SN1 (Max_Limbs - 1) = 0);   --  = B (Max_Limbs - N).
            Lemma_Val_Shift1 (SN1);              --  Val (Shift1g SN1) = Base * Val (SN1).
            pragma Assert
              (for all K in Limb_Index => SN (K) = Shift1g (SN1) (K));
            pragma Assert (SN = Shift1g (SN1));
            Lemma_Val_Cong (SN, Shift1g (SN1));
            pragma Assert (Val (SN) = Base * Val (SN1));
            pragma Assert (Base_Pow (N) = Base * Base_Pow (N - 1));
         end;
      end if;
   end Lemma_Val_Shift_By;

end Tls_Core.Ghost_Bignum.Value;
