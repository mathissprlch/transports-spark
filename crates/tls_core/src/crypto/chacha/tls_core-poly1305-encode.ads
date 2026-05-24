--  Tls_Core.Poly1305.Encode — Big_Nat block encoding (RFC 8439 §2.5).
--
--  Pure, Big_Integer-free ghost model of Load_Block: the 16-byte (or short
--  final) message block, with the implicit "1" bit appended, packed into the
--  same 5x26-bit limb layout the imperative Load_Block produces. Used to state
--  Load_Block's functional Post (To_Big_Nat (Out_Limbs) = Encode_BN (...)) so
--  the Mac loop can fold over a byte-defined Big_Nat block value without the
--  Ada.Numerics.Big_Numbers axiomatisation (the §0e wall).

with Interfaces;
with Tls_Core.Ghost_Bignum;

package Tls_Core.Poly1305.Encode
  with SPARK_Mode, Ghost
is

   package GB renames Tls_Core.Ghost_Bignum;
   use type Interfaces.Unsigned_8;

   --  i-th byte (1 .. 17) of the padded block: message bytes B (1 .. len),
   --  then the implicit-1 bit at position len+1 (final short block) or 17
   --  (full 16-byte block), zero elsewhere. Mirrors Load_Block's Padded.
   function Padded_Byte
     (B           : Octet_Array;
      Block_Bytes : Natural;
      Final       : Boolean;
      I           : Positive) return Octet
   is (if I <= Block_Bytes then B (B'First + I - 1)
       elsif Final and then I = Block_Bytes + 1 then 1
       elsif not Final and then I = 17 then 1
       else 0)
   with
     Pre  => Block_Bytes in 1 .. 16
             and then Block_Bytes <= B'Length
             and then B'Last < Integer'Last - 16
             and then I <= 17,
     Post => (if I > Block_Bytes then Padded_Byte'Result <= 1);

   --  The five 26-bit limbs, packed exactly as Load_Block packs Out_Limbs.
   function Enc_Limb0
     (B : Octet_Array; Block_Bytes : Natural; Final : Boolean) return U64
   is (U64 (Padded_Byte (B, Block_Bytes, Final, 1))
       or Interfaces.Shift_Left (U64 (Padded_Byte (B, Block_Bytes, Final, 2)), 8)
       or Interfaces.Shift_Left
            (U64 (Padded_Byte (B, Block_Bytes, Final, 3)), 16)
       or Interfaces.Shift_Left
            (U64 (Padded_Byte (B, Block_Bytes, Final, 4) and 16#03#), 24))
   with Pre => Block_Bytes in 1 .. 16 and then Block_Bytes <= B'Length
               and then B'Last < Integer'Last - 16;

   function Enc_Limb1
     (B : Octet_Array; Block_Bytes : Natural; Final : Boolean) return U64
   is (Interfaces.Shift_Right (U64 (Padded_Byte (B, Block_Bytes, Final, 4)), 2)
       or Interfaces.Shift_Left (U64 (Padded_Byte (B, Block_Bytes, Final, 5)), 6)
       or Interfaces.Shift_Left
            (U64 (Padded_Byte (B, Block_Bytes, Final, 6)), 14)
       or Interfaces.Shift_Left
            (U64 (Padded_Byte (B, Block_Bytes, Final, 7) and 16#0F#), 22))
   with Pre => Block_Bytes in 1 .. 16 and then Block_Bytes <= B'Length
               and then B'Last < Integer'Last - 16;

   function Enc_Limb2
     (B : Octet_Array; Block_Bytes : Natural; Final : Boolean) return U64
   is (Interfaces.Shift_Right (U64 (Padded_Byte (B, Block_Bytes, Final, 7)), 4)
       or Interfaces.Shift_Left (U64 (Padded_Byte (B, Block_Bytes, Final, 8)), 4)
       or Interfaces.Shift_Left
            (U64 (Padded_Byte (B, Block_Bytes, Final, 9)), 12)
       or Interfaces.Shift_Left
            (U64 (Padded_Byte (B, Block_Bytes, Final, 10) and 16#3F#), 20))
   with Pre => Block_Bytes in 1 .. 16 and then Block_Bytes <= B'Length
               and then B'Last < Integer'Last - 16;

   function Enc_Limb3
     (B : Octet_Array; Block_Bytes : Natural; Final : Boolean) return U64
   is (Interfaces.Shift_Right (U64 (Padded_Byte (B, Block_Bytes, Final, 10)), 6)
       or Interfaces.Shift_Left
            (U64 (Padded_Byte (B, Block_Bytes, Final, 11)), 2)
       or Interfaces.Shift_Left
            (U64 (Padded_Byte (B, Block_Bytes, Final, 12)), 10)
       or Interfaces.Shift_Left
            (U64 (Padded_Byte (B, Block_Bytes, Final, 13)), 18))
   with Pre => Block_Bytes in 1 .. 16 and then Block_Bytes <= B'Length
               and then B'Last < Integer'Last - 16;

   function Enc_Limb4
     (B : Octet_Array; Block_Bytes : Natural; Final : Boolean) return U64
   is (U64 (Padded_Byte (B, Block_Bytes, Final, 14))
       or Interfaces.Shift_Left
            (U64 (Padded_Byte (B, Block_Bytes, Final, 15)), 8)
       or Interfaces.Shift_Left
            (U64 (Padded_Byte (B, Block_Bytes, Final, 16)), 16)
       or Interfaces.Shift_Left
            (U64 (Padded_Byte (B, Block_Bytes, Final, 17)), 24))
   with Pre => Block_Bytes in 1 .. 16 and then Block_Bytes <= B'Length
               and then B'Last < Integer'Last - 16;

   --  Top limb of the clamped r (16 bytes, NO implicit-1 bit, so no 2**24
   --  contribution from a 17th byte). Limbs 0 .. 3 of r coincide with the
   --  block encoding's (they touch only message bytes 1 .. 13).
   function R_Limb4 (B : Octet_Array) return U64
   is (U64 (Padded_Byte (B, 16, False, 14))
       or Interfaces.Shift_Left (U64 (Padded_Byte (B, 16, False, 15)), 8)
       or Interfaces.Shift_Left (U64 (Padded_Byte (B, 16, False, 16)), 16))
   with Pre => B'Length >= 16 and then B'Last < Integer'Last - 16;

   --  The clamped r as a Big_Nat (16 bytes, no implicit-1).
   function R_BN (B : Octet_Array) return GB.Big_Nat
   is ([0      => GB.LLI (Enc_Limb0 (B, 16, False)),
        1      => GB.LLI (Enc_Limb1 (B, 16, False)),
        2      => GB.LLI (Enc_Limb2 (B, 16, False)),
        3      => GB.LLI (Enc_Limb3 (B, 16, False)),
        4      => GB.LLI (R_Limb4 (B)),
        others => 0])
   with
     Pre  => B'Length >= 16 and then B'Last < Integer'Last - 16,
     Post => GB.In_Bounds (R_BN'Result, GB.In_Cap)
             and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                         R_BN'Result (I) = 0);

   --  The encoded block as a Big_Nat (limbs 0 .. 4, zero above).
   function Encode_BN
     (B : Octet_Array; Block_Bytes : Natural; Final : Boolean)
      return GB.Big_Nat
   is ([0      => GB.LLI (Enc_Limb0 (B, Block_Bytes, Final)),
        1      => GB.LLI (Enc_Limb1 (B, Block_Bytes, Final)),
        2      => GB.LLI (Enc_Limb2 (B, Block_Bytes, Final)),
        3      => GB.LLI (Enc_Limb3 (B, Block_Bytes, Final)),
        4      => GB.LLI (Enc_Limb4 (B, Block_Bytes, Final)),
        others => 0])
   with
     Pre  => Block_Bytes in 1 .. 16 and then Block_Bytes <= B'Length
             and then B'Last < Integer'Last - 16,
     Post => GB.In_Bounds (Encode_BN'Result, GB.In_Cap)
             and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                         Encode_BN'Result (I) = 0);

end Tls_Core.Poly1305.Encode;
