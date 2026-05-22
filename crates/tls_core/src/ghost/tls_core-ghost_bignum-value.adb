pragma Ada_2022;
package body Tls_Core.Ghost_Bignum.Value
  with SPARK_Mode
is

   procedure Lemma_Limb_Val_Add (X, Y : LLI) is
   begin
      if Y = 0 then
         null;  --  Limb_Val (X+0) = Limb_Val (X) = Limb_Val (X) + 0.
      else
         Lemma_Limb_Val_Add (X, Y - 1);
         --  IH: Limb_Val (X + Y - 1) = Limb_Val (X) + Limb_Val (Y - 1).
         pragma Assert (Limb_Val (X + Y) = Limb_Val (X + Y - 1) + 1);
         pragma Assert (Limb_Val (Y) = Limb_Val (Y - 1) + 1);
      end if;
   end Lemma_Limb_Val_Add;

end Tls_Core.Ghost_Bignum.Value;
