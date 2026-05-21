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

   procedure Lemma_Carry26 (X : LLI) is null;

   procedure Lemma_Hi26_Bound (X : LLI) is null;

   procedure Lemma_Val_Eq_Refl (A : Big_Nat) is null;

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
