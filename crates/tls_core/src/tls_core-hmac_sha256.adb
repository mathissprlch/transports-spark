with Interfaces;

package body Tls_Core.Hmac_Sha256
with SPARK_Mode
is

   use type Interfaces.Unsigned_8;

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   Block_Length : constant := Tls_Core.Sha256.Block_Length;
   Hash_Length  : constant := Tls_Core.Sha256.Hash_Length;

   subtype Block_Buf is Octet_Array (1 .. Block_Length);

   ---------------------------------------------------------------------
   --  HACL* spec ports — bodies for Spec_Wrap_Key and Spec_HMAC_SHA256
   --  declared in the public part. These are the canonical reference
   --  algorithm; they execute, are called by Spec_HMAC_SHA256, and
   --  (indirectly) by the public Compute procedure.
   ---------------------------------------------------------------------

   --  Internal helper: normalize an arbitrary-base Octet_Array to a
   --  1-based copy. Spec_SHA256 requires Input'First = 1 so we
   --  re-base any inputs that the spec layer hands to it.
   function Spec_To_One_Based (S : Octet_Array) return Octet_Array
   with
     Pre  => S'Last < Integer'Last - 1024,
     Post =>
       Spec_To_One_Based'Result'First = 1
       and then Spec_To_One_Based'Result'Length = S'Length;

   function Spec_To_One_Based (S : Octet_Array) return Octet_Array is
      R : Octet_Array (1 .. S'Length) := (others => 0);
   begin
      for I in 1 .. S'Length loop
         R (I) := S (S'First + I - 1);
         pragma Loop_Invariant
           (for all J in 1 .. I =>
              R (J) = S (S'First + J - 1));
      end loop;
      return R;
   end Spec_To_One_Based;

   --  Spec_Wrap_Key — RFC 2104 §2 / HACL* `wrap_key`
   --  (specs/Spec.HMAC.fst:13-25). If |K| > B then K' = H(K) || 0..0,
   --  else K' = K || 0..0, padded to Block_Length bytes.
   function Spec_Wrap_Key
     (Key : Octet_Array) return Tls_Core.Sha256.Block
   is
      K_Prime : Block_Buf := (others => 0);
   begin
      if Key'Length > Block_Length then
         declare
            Hashed : constant Tls_Core.Sha256.Digest :=
              Tls_Core.Sha256.Spec_SHA256 (Spec_To_One_Based (Key));
         begin
            K_Prime (1 .. Hash_Length) := Hashed;
         end;
      else
         for I in 1 .. Key'Length loop
            K_Prime (I) := Key (Key'First + I - 1);
            pragma Loop_Invariant
              (for all J in 1 .. I =>
                 K_Prime (J) = Key (Key'First + J - 1));
         end loop;
      end if;
      return K_Prime;
   end Spec_Wrap_Key;

   --  Spec_HMAC_SHA256 — top-level HMAC composition.
   --  HACL* `hmac` (specs/Spec.HMAC.fst:27-37):
   --    let kw   = wrap_key K in
   --    let ipad = create blocksize 0x36uy in
   --    let opad = create blocksize 0x5cuy in
   --    let ki   = xor_bytes kw ipad in
   --    let ko   = xor_bytes kw opad in
   --    let h1   = hash (ki @| m)  in
   --    hash (ko @| h1)
   function Spec_HMAC_SHA256
     (Key     : Octet_Array;
      Message : Octet_Array) return Tag
   is
      K_Prime    : constant Block_Buf := Spec_Wrap_Key (Key);
      Inner_Pad  : Block_Buf;
      Outer_Pad  : Block_Buf;
      Inner_Hash : Tls_Core.Sha256.Digest;
      Inner_Buf  : Octet_Array (1 .. Block_Length + Message'Length) :=
        (others => 0);
      Outer_Buf  : Octet_Array (1 .. Block_Length + Hash_Length) :=
        (others => 0);
   begin
      --  Build the two padded keys.
      for I in Block_Buf'Range loop
         Inner_Pad (I) := K_Prime (I) xor 16#36#;
         Outer_Pad (I) := K_Prime (I) xor 16#5C#;
      end loop;

      --  Inner_Buf = (K' XOR ipad) || M.
      Inner_Buf (1 .. Block_Length) := Inner_Pad;
      for I in 1 .. Message'Length loop
         Inner_Buf (Block_Length + I) := Message (Message'First + I - 1);
         pragma Loop_Invariant
           (for all J in 1 .. Block_Length =>
              Inner_Buf (J) = Inner_Pad (J));
         pragma Loop_Invariant
           (for all J in 1 .. I =>
              Inner_Buf (Block_Length + J)
                = Message (Message'First + J - 1));
      end loop;

      Inner_Hash := Tls_Core.Sha256.Spec_SHA256 (Inner_Buf);

      --  Outer_Buf = (K' XOR opad) || Inner_Hash.
      Outer_Buf (1 .. Block_Length) := Outer_Pad;
      Outer_Buf (Block_Length + 1 .. Block_Length + Hash_Length) :=
        Inner_Hash;

      return Tls_Core.Sha256.Spec_SHA256 (Outer_Buf);
   end Spec_HMAC_SHA256;

   ---------------------------------------------------------------------
   --  Public Compute — by-construction match against Spec_HMAC_SHA256.
   --
   --  Body is a one-liner: invoke the ported HACL* spec directly.
   --  The spec function is itself executable (it composes the SHA-256
   --  spec already exposed in Tls_Core.Sha256), so this is genuine
   --  computation, not a stub-Spec bridge. Mirrors the
   --  Tls_Core.Sha256.Hash pattern.
   ---------------------------------------------------------------------

   procedure Compute
     (Key     : Octet_Array;
      Message : Octet_Array;
      Out_Tag : out Tag)
   is
   begin
      Out_Tag := Spec_HMAC_SHA256 (Key, Message);
   end Compute;

end Tls_Core.Hmac_Sha256;
