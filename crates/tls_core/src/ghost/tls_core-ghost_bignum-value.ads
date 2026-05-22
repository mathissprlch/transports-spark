pragma Ada_2022;
with Ada.Numerics.Big_Numbers.Big_Integers;

--  SPIKE (codomain go/no-go for the §0e Mul-bridge value layer).
--
--  Goal: a Big_Integer-valued ghost `Val` whose limb ingress is OURS (unit
--  recursion), so the §0e-opaque `To_Big_Integer` is never touched. This unit
--  is entirely Ghost; it must ghost-eliminate so Ada.Numerics.Big_Numbers does
--  NOT enter any bare-metal build closure (isolation gate).
package Tls_Core.Ghost_Bignum.Value
  with SPARK_Mode, Ghost
is

   package BI renames Ada.Numerics.Big_Numbers.Big_Integers;
   use type BI.Big_Integer;

   --  Non-opaque limb -> Big_Integer ingress: builds the value by unit
   --  recursion (base 0, step +1), NEVER via the opaque To_Big_Integer.
   function Limb_Val (X : LLI) return BI.Big_Integer
   is (if X = 0 then 0 else Limb_Val (X - 1) + 1)
   with
     Pre                => X >= 0,
     Subprogram_Variant => (Decreases => X);

   --  COST GATE: additivity of the recursive ingress (proven by induction on
   --  Y). If gnatprove digests this at acceptable cost, the codomain is locked.
   procedure Lemma_Limb_Val_Add (X, Y : LLI)
   with
     Pre                =>
       X >= 0 and then Y >= 0 and then X <= LLI'Last - Y,
     Post               => Limb_Val (X + Y) = Limb_Val (X) + Limb_Val (Y),
     Subprogram_Variant => (Decreases => Y);

end Tls_Core.Ghost_Bignum.Value;
