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

end Tls_Core.Ghost_Bignum.Value;
