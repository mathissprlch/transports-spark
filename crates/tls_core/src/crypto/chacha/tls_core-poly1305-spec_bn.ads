--  Tls_Core.Poly1305.Spec_BN — Big_Nat functional spec of the Poly1305 MAC.
--
--  The accumulator fold, defined purely over Tls_Core.Ghost_Bignum (Big_Nat
--  field arithmetic) and the byte-defined block encoding (Encode_BN), with no
--  Ada.Numerics.Big_Numbers dependency. Mirrors RFC 8439 §2.5:
--      Acc := 0;  for each block b:  Acc := (Acc + encode(b)) * r  mod p
--  This is the §0e-clean target the imperative Mac is proven to compute.

with Interfaces;
with Tls_Core.Ghost_Bignum;
with Tls_Core.Poly1305.Encode;

package Tls_Core.Poly1305.Spec_BN
  with SPARK_Mode, Ghost
is

   package GB renames Tls_Core.Ghost_Bignum;
   package Enc renames Tls_Core.Poly1305.Encode;

   --  Field accumulator after folding the first N full 16-byte blocks of
   --  Message with key element R (a reduced In_Cap Big_Nat). N = 0 gives the
   --  zero accumulator; each step adds the encoded block then multiplies by R.
   function Spec_Fold
     (Message : Octet_Array; N : Natural; R : GB.Big_Nat) return GB.Big_Nat
   is (if N = 0
       then GB.Zero
       else
         GB.Field_Mul
           (GB.Field_Add
              (Spec_Fold (Message, N - 1, R),
               Enc.Encode_BN
                 (Message
                    (Message'First
                     + 16 * (N - 1)
                     .. Message'First + 16 * N - 1),
                  16,
                  False)),
            R))
   with
     Pre                =>
       GB.In_Bounds (R, GB.In_Cap)
       and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   R (I) = 0)
       and then Message'Last < Integer'Last - 16
       and then N <= Message'Length / 16,
     Post               =>
       GB.In_Bounds (Spec_Fold'Result, GB.In_Cap)
       and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   Spec_Fold'Result (I) = 0),
     Subprogram_Variant => (Decreases => N);

   --  Field accumulator after the whole message: every full 16-byte block,
   --  then (if the length is not a multiple of 16) the final partial block
   --  encoded with its implicit-1 at the message length. This is the post-loop
   --  accumulator value the imperative Mac computes before finish.
   function Spec_Mac_Acc
     (Message : Octet_Array; R : GB.Big_Nat) return GB.Big_Nat
   is (if Message'Length mod 16 = 0
       then Spec_Fold (Message, Message'Length / 16, R)
       else
         GB.Field_Mul
           (GB.Field_Add
              (Spec_Fold (Message, Message'Length / 16, R),
               Enc.Encode_BN
                 (Message
                    (Message'First
                     + 16 * (Message'Length / 16)
                     .. Message'Last),
                  Message'Length mod 16,
                  True)),
            R))
   with
     Pre  =>
       GB.In_Bounds (R, GB.In_Cap)
       and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   R (I) = 0)
       and then Message'Last < Integer'Last - 16,
     Post =>
       GB.In_Bounds (Spec_Mac_Acc'Result, GB.In_Cap)
       and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   Spec_Mac_Acc'Result (I) = 0);

   ------------------------------------------------------------------
   --  store_felem (HACL* poly1305_finish): the low 128 bits of a 5x26-bit-limb
   --  Big_Nat, little-endian. The clean sweep (Sweep5_Out) settles the limbs to
   --  26 bits; the two 64-bit words are the canonical positional repack and
   --  bits >= 128 are dropped (the mod 2^128 of the finish). Defined over
   --  Sweep5_Out so the (Acc + s) input need not be pre-normalised.
   ------------------------------------------------------------------

   --  Low 64 bits (bits 0 .. 63): limb0 | limb1 << 26 | low12 (limb2) << 52.
   function Fin_Lo (V : GB.Big_Nat) return U64
   is (U64 (GB.Sweep5_Out (V) (0))
       or Interfaces.Shift_Left (U64 (GB.Sweep5_Out (V) (1)), 26)
       or Interfaces.Shift_Left
            (U64 (GB.Sweep5_Out (V) (2)) and 16#0000_0FFF#, 52))
   with
     Pre =>
       GB.In_Bounds (V, GB.Prod_Cap)
       and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   V (I) = 0);

   --  High 64 bits (bits 64 .. 127): hi14 (limb2) | limb3 << 14 |
   --  low24 (limb4) << 40.  The top two bits of limb4 (value bits 128, 129)
   --  are masked off -- this is the mod 2^128.
   function Fin_Hi (V : GB.Big_Nat) return U64
   is (Interfaces.Shift_Right (U64 (GB.Sweep5_Out (V) (2)), 12)
       or Interfaces.Shift_Left (U64 (GB.Sweep5_Out (V) (3)), 14)
       or Interfaces.Shift_Left
            (U64 (GB.Sweep5_Out (V) (4)) and 16#00FF_FFFF#, 40))
   with
     Pre =>
       GB.In_Bounds (V, GB.Prod_Cap)
       and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   V (I) = 0);

   --  The 16-byte little-endian tag bytes: bytes 1 .. 8 from Fin_Lo, bytes
   --  9 .. 16 from Fin_Hi (byte j = (word >> 8*k) and 16#FF#).
   function Store_Le_16 (V : GB.Big_Nat) return Tag_Array
   is ([for J in Tag_Array'Range =>
          (if J <= 8
           then
             Octet
               (Interfaces.Shift_Right (Fin_Lo (V), 8 * (J - 1)) and 16#FF#)
           else
             Octet
               (Interfaces.Shift_Right (Fin_Hi (V), 8 * (J - 9)) and 16#FF#))])
   with
     Pre =>
       GB.In_Bounds (V, GB.Prod_Cap)
       and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   V (I) = 0);

end Tls_Core.Poly1305.Spec_BN;
