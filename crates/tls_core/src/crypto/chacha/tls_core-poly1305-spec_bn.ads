--  Tls_Core.Poly1305.Spec_BN — Big_Nat functional spec of the Poly1305 MAC.
--
--  The accumulator fold, defined purely over Tls_Core.Ghost_Bignum (Big_Nat
--  field arithmetic) and the byte-defined block encoding (Encode_BN), with no
--  Ada.Numerics.Big_Numbers dependency. Mirrors RFC 8439 §2.5:
--      Acc := 0;  for each block b:  Acc := (Acc + encode(b)) * r  mod p
--  This is the §0e-clean target the imperative Mac is proven to compute.

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
                    (Message'First + 16 * (N - 1)
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

end Tls_Core.Poly1305.Spec_BN;
