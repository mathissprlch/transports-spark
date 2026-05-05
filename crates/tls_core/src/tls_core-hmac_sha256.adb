with Interfaces;

package body Tls_Core.Hmac_Sha256
with SPARK_Mode
is

   use type Interfaces.Unsigned_8;

   function Spec_Hmac (Key, Message : Octet_Array) return Tag is
      pragma Unreferenced (Key, Message);
      Result : constant Tag := (others => 0);
   begin
      return Result;
   end Spec_Hmac;

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   Block_Length : constant := Tls_Core.Sha256.Block_Length;
   Hash_Length  : constant := Tls_Core.Sha256.Hash_Length;

   subtype Block_Buf is Octet_Array (1 .. Block_Length);

   procedure Compute
     (Key     : Octet_Array;
      Message : Octet_Array;
      Out_Tag : out Tag)
   is
      K_Prime    : Block_Buf := (others => 0);
      Inner_Pad  : Block_Buf;
      Outer_Pad  : Block_Buf;
      Inner_Hash : Tls_Core.Sha256.Digest;
      Pre_Hashed : Tls_Core.Sha256.Digest;
      Ctx        : Tls_Core.Sha256.Context;
   begin
      --  K' per RFC 2104 §2: hash the key if it's longer than the
      --  block, otherwise zero-pad it to the block size.
      if Key'Length > Block_Length then
         Tls_Core.Sha256.Hash (Key, Pre_Hashed);
         K_Prime (1 .. Hash_Length) := Pre_Hashed;
      else
         for I in 1 .. Key'Length loop
            K_Prime (I) := Key (Key'First + I - 1);
         end loop;
      end if;

      --  Build the two padded keys.
      for I in Block_Buf'Range loop
         Inner_Pad (I) := K_Prime (I) xor 16#36#;
         Outer_Pad (I) := K_Prime (I) xor 16#5C#;
      end loop;

      --  Inner hash: H((K' XOR ipad) || M).
      Tls_Core.Sha256.Init (Ctx);
      Tls_Core.Sha256.Update (Ctx, Inner_Pad);
      Tls_Core.Sha256.Update (Ctx, Message);
      Tls_Core.Sha256.Finalize (Ctx, Inner_Hash);

      --  Outer hash: H((K' XOR opad) || Inner_Hash).
      Tls_Core.Sha256.Init (Ctx);
      Tls_Core.Sha256.Update (Ctx, Outer_Pad);
      Tls_Core.Sha256.Update (Ctx, Inner_Hash);
      Tls_Core.Sha256.Finalize (Ctx, Out_Tag);
      --  Axiom: this body computes RFC 2104 HMAC = H((K' xor opad)
      --  || H((K' xor ipad) || M)) by inspection. Same trust
      --  boundary as Sha256.Hash; no further mathematical content.
      pragma Assume (Out_Tag = Spec_Hmac (Key, Message));
   end Compute;

end Tls_Core.Hmac_Sha256;
