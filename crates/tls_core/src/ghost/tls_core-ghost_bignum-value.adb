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

end Tls_Core.Ghost_Bignum.Value;
