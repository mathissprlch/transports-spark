with Interfaces;

package body Tls_Core.Hmac_Sha384
with SPARK_Mode
is

   use type Interfaces.Unsigned_8;

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   Block_Length : constant := Tls_Core.Sha384.Block_Length;  --  128
   Hash_Length  : constant := Tls_Core.Sha384.Hash_Length;   --  48

   subtype Block_Buf is Octet_Array (1 .. Block_Length);

   procedure Compute
     (Key     : Octet_Array;
      Message : Octet_Array;
      Out_Tag : out Tag)
   is
      K_Prime    : Block_Buf := (others => 0);
      Inner_Pad  : Block_Buf;
      Outer_Pad  : Block_Buf;
      Inner_Hash : Tls_Core.Sha384.Digest;
      Pre_Hashed : Tls_Core.Sha384.Digest;
      Ctx        : Tls_Core.Sha384.Context;
   begin
      if Key'Length > Block_Length then
         Tls_Core.Sha384.Hash (Key, Pre_Hashed);
         K_Prime (1 .. Hash_Length) := Pre_Hashed;
      else
         for I in 1 .. Key'Length loop
            K_Prime (I) := Key (Key'First + I - 1);
         end loop;
      end if;

      for I in Block_Buf'Range loop
         Inner_Pad (I) := K_Prime (I) xor 16#36#;
         Outer_Pad (I) := K_Prime (I) xor 16#5C#;
      end loop;

      Tls_Core.Sha384.Init (Ctx);
      Tls_Core.Sha384.Update (Ctx, Inner_Pad);
      Tls_Core.Sha384.Update (Ctx, Message);
      Tls_Core.Sha384.Finalize (Ctx, Inner_Hash);

      Tls_Core.Sha384.Init (Ctx);
      Tls_Core.Sha384.Update (Ctx, Outer_Pad);
      Tls_Core.Sha384.Update (Ctx, Inner_Hash);
      Tls_Core.Sha384.Finalize (Ctx, Out_Tag);
   end Compute;

end Tls_Core.Hmac_Sha384;
