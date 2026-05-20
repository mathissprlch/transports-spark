with Interfaces;

package body Tls_Core.Hmac_Sha384
  with SPARK_Mode
is

   use type Interfaces.Unsigned_8;


   Block_Length : constant := Tls_Core.Sha384.Block_Length;  --  128
   Hash_Length  : constant := Tls_Core.Sha384.Hash_Length;   --  48

   subtype Block_Buf is Octet_Array (1 .. Block_Length);

   ---------------------------------------------------------------------
   --  HACL* spec ports for HMAC-SHA-384.
   --
   --  Spec_SHA384 (Tls_Core.Sha384) accepts arbitrary-base inputs
   --  (its Pad_SHA384 normalises the slice), so unlike Hmac_Sha256
   --  we do not need a 1-based normalisation helper.
   ---------------------------------------------------------------------

   --  Spec_Wrap_Key — RFC 2104 §2 / HACL* `wrap_key`
   --  (specs/Spec.HMAC.fst:13-25). Same shape as Hmac_Sha256.
   function Spec_Wrap_Key (Key : Octet_Array) return Tls_Core.Sha384.Block is
      K_Prime : Block_Buf := [others => 0];
   begin
      if Key'Length > Block_Length then
         declare
            Hashed : constant Tls_Core.Sha384.Digest :=
              Tls_Core.Sha384.Spec_SHA384 (Key);
         begin
            K_Prime (1 .. Hash_Length) := Hashed;
         end;
      else
         for I in 1 .. Key'Length loop
            K_Prime (I) := Key (Key'First + I - 1);
            pragma
              Loop_Invariant
                (for all J in 1 .. I => K_Prime (J) = Key (Key'First + J - 1));
         end loop;
      end if;
      return K_Prime;
   end Spec_Wrap_Key;

   --  Spec_HMAC_SHA384 — top-level HMAC composition.
   --  HACL* `hmac` (specs/Spec.HMAC.fst:27-37) at SHA2_384.
   function Spec_HMAC_SHA384
     (Key : Octet_Array; Message : Octet_Array) return Tag
   is
      K_Prime    : constant Block_Buf := Spec_Wrap_Key (Key);
      Inner_Pad  : Block_Buf;
      Outer_Pad  : Block_Buf;
      Inner_Hash : Tls_Core.Sha384.Digest;
      Inner_Buf  : Octet_Array (1 .. Block_Length + Message'Length) :=
        (others => 0);
      Outer_Buf  : Octet_Array (1 .. Block_Length + Hash_Length) :=
        [others => 0];
   begin
      for I in Block_Buf'Range loop
         Inner_Pad (I) := K_Prime (I) xor 16#36#;
         Outer_Pad (I) := K_Prime (I) xor 16#5C#;
      end loop;

      Inner_Buf (1 .. Block_Length) := Inner_Pad;
      for I in 1 .. Message'Length loop
         Inner_Buf (Block_Length + I) := Message (Message'First + I - 1);
         pragma
           Loop_Invariant
             (for all J in 1 .. Block_Length => Inner_Buf (J) = Inner_Pad (J));
         pragma
           Loop_Invariant
             (for all J in 1 .. I =>
                Inner_Buf (Block_Length + J)
                = Message (Message'First + J - 1));
      end loop;

      Inner_Hash := Tls_Core.Sha384.Spec_SHA384 (Inner_Buf);

      Outer_Buf (1 .. Block_Length) := Outer_Pad;
      Outer_Buf (Block_Length + 1 .. Block_Length + Hash_Length) := Inner_Hash;

      return Tls_Core.Sha384.Spec_SHA384 (Outer_Buf);
   end Spec_HMAC_SHA384;

   ---------------------------------------------------------------------
   --  Public Compute — by-construction match against Spec_HMAC_SHA384.
   --  One-liner mirroring the Tls_Core.Sha384.Hash pattern.
   ---------------------------------------------------------------------

   procedure Compute
     (Key : Octet_Array; Message : Octet_Array; Out_Tag : out Tag) is
   begin
      Out_Tag := Spec_HMAC_SHA384 (Key, Message);
   end Compute;

end Tls_Core.Hmac_Sha384;
