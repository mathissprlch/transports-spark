--  Tls_Core.Poly1305 — Poly1305 one-time MAC (RFC 8439 §2.5).
--
--  Source: RFC 8439 §2.5 — The Poly1305 Algorithm.
--
--    r = clamp(key[0..15])
--    s =       key[16..31]
--    Acc = 0
--    For each 16-byte block n_i (last block possibly partial):
--        Acc = (Acc + n_i + 2^(8*len)) mod (2^130 - 5)
--        Acc = (Acc * r)               mod (2^130 - 5)
--    Tag = (Acc + s) mod 2^128
--
--  We work over a 5-limb representation of 130-bit integers
--  (each limb 26 bits) to keep modular reductions straightforward
--  inside 64-bit accumulators. This is the same layout HACL\*
--  uses for `Hacl.Spec.Poly1305.Field32`.
--
--  RFC 8439 §2.5.2 supplies the test vector that tls_core_tests
--  pins against.
--
--  Functional spec ported from HACL\* `specs/Spec.Poly1305.fst`
--  (commit hacl-star/main, retrieved 2026-05-07). The MAC fold is
--  expressed over Tls_Core.Ghost_Bignum (Big_Nat field arithmetic) in
--  the Spec_BN child and finished by Spec_Poly1305_Mac_BN below, so the
--  proof carries no Ada.Numerics.Big_Numbers dependency (the §0e wall).

with Interfaces;
with Tls_Core.Ghost_Bignum;

package Tls_Core.Poly1305
  with SPARK_Mode
is

   use type Interfaces.Unsigned_64;
   subtype U64 is Interfaces.Unsigned_64;
   subtype U32 is Interfaces.Unsigned_32;

   Key_Length : constant := 32;
   Tag_Length : constant := 16;

   subtype Key_Array is Octet_Array (1 .. Key_Length);
   subtype Tag_Array is Octet_Array (1 .. Tag_Length);

   --  5×26-bit limb representation, public so functional Posts on
   --  the private helpers (Add / Multiply / Carry / Load_Block) can
   --  reference the Big_Nat embedding (To_Big_Nat / Feval_BN) below.
   subtype Limb_Index is Natural range 0 .. 4;
   type Limbs is array (Limb_Index) of U64;

   --  Bound predicate: every limb fits in 26 bits. After Carry the
   --  accumulator satisfies this; HACL\*'s `felem_fits5` analogue.
   function All_Limbs_Fit_26 (L : Limbs) return Boolean
   is (for all I in Limb_Index => L (I) < 2**26)
   with Ghost;

   ------------------------------------------------------------------
   --  Ghost_Bignum bridge (scalar-free value type)
   ------------------------------------------------------------------
   --
   --  Embeds the impl's five-limb representation into Tls_Core.Ghost_Bignum's
   --  Big_Nat (limbs 0..4, zero above) so the imperative Add / Multiply /
   --  Carry connect to the proven Big_Nat reduce algebra without the
   --  Ada.Numerics.Big_Numbers axiomatisation (the §0e wall). The whole MAC
   --  proof -- accumulator fold, freeze and finish -- now runs over Big_Nat.

   --  Embeddable bound: limbs must fit Long_Long_Integer for the U64->LLI
   --  conversion. 2**59 covers every Poly1305 intermediate (reduced limbs,
   --  pre-carry sums ~2**27, even a mul_felem5 limb ~2**58).
   function Limbs_Embeddable (L : Limbs) return Boolean
   is (for all I in Limb_Index => L (I) < 2**59)
   with Ghost;

   function To_Big_Nat (L : Limbs) return Ghost_Bignum.Big_Nat
   is ([for I in Ghost_Bignum.Limb_Index =>
          (if I <= 4 then Ghost_Bignum.LLI (L (I)) else 0)])
   with
     Ghost,
     Pre  => Limbs_Embeddable (L),
     Post =>
       (for all I in Ghost_Bignum.Limb_Index =>
          To_Big_Nat'Result (I)
          = (if I <= 4 then Ghost_Bignum.LLI (L (I)) else 0));

   --  A reduced five-limb value embeds to a Big_Nat that meets the reduce
   --  bricks' input contract (limbs 0..4 <= In_Cap, zero from 5).
   procedure Lemma_To_Big_Nat_Reduced (L : Limbs)
   with
     Ghost,
     Pre  => All_Limbs_Fit_26 (L),
     Post =>
       Ghost_Bignum.In_Bounds (To_Big_Nat (L), Ghost_Bignum.In_Cap)
       and then (for all I in
                   Ghost_Bignum.Limb_Index
                     range 5 .. Ghost_Bignum.Max_Limbs - 1 =>
                   To_Big_Nat (L) (I) = 0);

   --  A limb vector with limbs < 2**27 embeds within Mul_Cap (the multiply
   --  input acceptance bound), so its embedding can feed Ghost_Bignum."*".
   procedure Lemma_To_Big_Nat_Mul_Cap (L : Limbs)
   with
     Ghost,
     Pre  => (for all I in Limb_Index => L (I) < 2**27),
     Post =>
       Ghost_Bignum.In_Bounds (To_Big_Nat (L), Ghost_Bignum.Mul_Cap)
       and then (for all I in
                   Ghost_Bignum.Limb_Index
                     range 5 .. Ghost_Bignum.Max_Limbs - 1 =>
                   To_Big_Nat (L) (I) = 0);

   --  Feval_BN: the field element (canonical residue mod p) of an impl limb
   --  vector, over Ghost_Bignum (the HACL\* `feval5` analogue). For an
   --  impl op output (limbs < 2**27, the shape of every Add / Multiply / Carry
   --  result) it is the unique < p representative of To_Big_Nat (L)'s residue:
   --  Normalize to the < 2**130 reduced form, then conditionally subtract p.
   function Feval_BN (L : Limbs) return Ghost_Bignum.Big_Nat
   is (Ghost_Bignum.Reduce_Canonical
         (Ghost_Bignum.Normalize (To_Big_Nat (L)).Val))
   with Ghost, Pre => (for all I in Limb_Index => L (I) < 2**27);

   --  Feval_BN is canonical: limbs <= In_Cap, zero from 5, and < p.
   procedure Lemma_Feval_BN_Lt_P (L : Limbs)
   with
     Ghost,
     Pre  => (for all I in Limb_Index => L (I) < 2**27),
     Post =>
       Ghost_Bignum.In_Bounds (Feval_BN (L), Ghost_Bignum.In_Cap)
       and then (for all I in
                   Ghost_Bignum.Limb_Index
                     range 5 .. Ghost_Bignum.Max_Limbs - 1 =>
                   Feval_BN (L) (I) = 0)
       and then not Ghost_Bignum.Sub_Cond (Feval_BN (L));

   --  U64 carry-split bridges to the Big_Nat Lo26/Hi26 split: the impl's
   --  Shift_Right (x, 26) and (x and Mask_26) are exactly Hi26/Lo26 of the
   --  LLI value. Foundation for the Carry correspondence.
   procedure Lemma_Shift_Mask_26 (X : U64)
   with
     Ghost,
     Pre  => X < 2**59,
     Post =>
       Ghost_Bignum.LLI (Interfaces.Shift_Right (X, 26))
       = Ghost_Bignum.Hi26 (Ghost_Bignum.LLI (X))
       and then Ghost_Bignum.LLI (X and 16#03FF_FFFF#)
                = Ghost_Bignum.Lo26 (Ghost_Bignum.LLI (X));

   --  Big_Integer-free functional spec of the MAC tag (Mac's postcondition).
   --  Defined in the package body over the Encode / Spec_BN children: HACL*
   --  poly1305_mac finishes with store_felem (Spec_Mac_Acc (Message, r) + s),
   --  where r = clamp (Key (1 .. 16)) and s = Key (17 .. 32).
   function Spec_Poly1305_Mac_BN
     (Key : Key_Array; Message : Octet_Array) return Tag_Array
   with Ghost, Pre => Message'Last < Integer'Last - 16;

   ------------------------------------------------------------------
   --  Imperative API
   ------------------------------------------------------------------

   procedure Mac
     (Key : Key_Array; Message : Octet_Array; Out_Tag : out Tag_Array)
   with
     Pre  => Message'Last < Integer'Last - 16,
     Post => Out_Tag = Spec_Poly1305_Mac_BN (Key, Message);

end Tls_Core.Poly1305;
