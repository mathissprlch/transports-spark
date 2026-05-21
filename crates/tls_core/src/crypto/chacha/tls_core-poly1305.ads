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
--  (commit hacl-star/main, retrieved 2026-05-07). The F\* `let`
--  definitions in that file map line-by-line to the `Spec_*` ghost
--  functions below: `poly1305_encode_r → Spec_Encode_R`,
--  `encode → Spec_Encode_Block`, `poly1305_update1 → Spec_Update1`,
--  `poly1305_update_last → Spec_Update_Last`, `poly1305_update →
--  Spec_Update_All`, `poly1305_finish → Spec_Finish`,
--  `poly1305_mac → Spec_Poly1305_Mac`. Each Spec_* body is a real
--  computable expression in `Big_Integers_Ghost` (no stubs).

with Interfaces;
with Tls_Core.Ghost_Bignum;
pragma Warnings (Off, "is an internal GNAT unit");
pragma Warnings (Off, "use of this unit is non-portable");
with Ada.Numerics.Big_Numbers.Big_Integers_Ghost;
pragma Warnings (On, "use of this unit is non-portable");
pragma Warnings (On, "is an internal GNAT unit");

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

   ------------------------------------------------------------------
   --  Functional spec (Ghost) — port of HACL\* Spec.Poly1305.fst
   ------------------------------------------------------------------

   package Big renames Ada.Numerics.Big_Numbers.Big_Integers_Ghost;
   use type Big.Big_Integer;

   --  Helper instantiation: convert an Octet to a Big_Integer.
   package Octet_Bigint is new Big.Unsigned_Conversions (Int => Octet);

   --  Power-of-two helper, ghost-only. Expression-function form so
   --  gnatprove unfolds it automatically by inline-expansion at every
   --  call site. The recursive arm is `Spec_Pow2 (N) = 2 * Spec_Pow2
   --  (N - 1)`, base case `Spec_Pow2 (0) = 1`.
   function Spec_Pow2 (N : Natural) return Big.Big_Natural
   is (if N = 0
       then Big.To_Big_Integer (1)
       else Big.To_Big_Integer (2) * Spec_Pow2 (N - 1))
   with Ghost, Subprogram_Variant => (Decreases => N);

   --  Lemma: 2^(N+1) = 2 * 2^N. Body proves it by case analysis on
   --  whether N hits the base block of Spec_Pow2.
   procedure Lemma_Pow2_Step (N : Natural)
   with
     Ghost,
     Pre  => N < Natural'Last,
     Post => Spec_Pow2 (N + 1) = Big.To_Big_Integer (2) * Spec_Pow2 (N);

   --  Lemma: 2^(N+8) = 256 * 2^N. Used by Lemma_Bytes_Bound.
   procedure Lemma_Pow2_Plus_8 (N : Natural)
   with
     Ghost,
     Pre  => N < Natural'Last - 8,
     Post => Spec_Pow2 (N + 8) = Big.To_Big_Integer (256) * Spec_Pow2 (N);

   --  Lemma: 2^(M+N) = 2^M * 2^N. The general additive law that
   --  Lemma_Pow2_Step is the unit-step specialisation of. Body
   --  inducts on N.
   procedure Lemma_Pow2_Add (M, N : Natural)
   with
     Ghost,
     Pre                => M <= Natural'Last - N,
     Post               => Spec_Pow2 (M + N) = Spec_Pow2 (M) * Spec_Pow2 (N),
     Subprogram_Variant => (Decreases => N);

   --  Lemma: Spec_Pow2 is strictly monotonic. Used to chain
   --  bounds across non-adjacent powers of two without a manual
   --  unrolling at every call site.
   procedure Lemma_Pow2_Monotone (M, N : Natural)
   with Ghost, Pre => M <= N, Post => Spec_Pow2 (M) <= Spec_Pow2 (N);

   --  Lemma: 2^128 < 2^130 - 5 = Spec_Prime. Required to chain
   --  the Spec_Encode_R bound (< 2^128) into the Spec_Update_All
   --  precondition (< Spec_Prime).
   procedure Lemma_Pow2_128_Lt_Prime
   with Ghost, Post => Spec_Pow2 (128) < Spec_Prime;

   --  Lemma: nat_from_bytes_le is bounded by 2^(8*length). Used to
   --  bound Spec_Encode_R and Spec_Encode_Block.
   procedure Lemma_Bytes_Bound (B : Octet_Array)
   with
     Ghost,
     Pre                => B'Length <= 32,
     Post               =>
       Spec_Nat_From_Bytes_Le (B) < Spec_Pow2 (8 * B'Length),
     Always_Terminates,
     Subprogram_Variant => (Decreases => B'Length);

   --  The HACL\* `prime` constant: 2^130 - 5.
   function Spec_Prime return Big.Big_Natural
   is (Spec_Pow2 (130) - Big.To_Big_Integer (5))
   with Ghost;

   --  HACL\* `nat_from_bytes_le` over a SPARK Octet_Array, recursive
   --  little-endian decoder. Returns the integer value of B viewed
   --  as a base-256 little-endian number.
   --
   --  Pre bounds the length so the spec can compute 8 * (B'Length - 1)
   --  without overflow. All Poly1305 callers feed at most 17 bytes
   --  (one block + the implicit-1 byte) so a 32-byte cap is safe.
   --
   --  Defined as an expression function (recursing from the high end
   --  to avoid `B'First + 1` overflow on edge cases) so gnatprove can
   --  inline-expand it at every call site.
   function Spec_Nat_From_Bytes_Le (B : Octet_Array) return Big.Big_Natural
   is (if B'Length = 0
       then Big.To_Big_Integer (0)
       else
         Spec_Nat_From_Bytes_Le (B (B'First .. B'Last - 1))
         + Octet_Bigint.To_Big_Integer (B (B'Last))
           * Spec_Pow2 (8 * (B'Length - 1)))
   with
     Ghost,
     Pre                => B'Length <= 32,
     Subprogram_Variant => (Decreases => B'Length);

   --  HACL\* `poly1305_encode_r` — clamped 16-byte-LE-decoded r.
   --  `Rb` is the lower 16 bytes of the 32-byte key as supplied at
   --  wire-level; the body re-applies the byte-level clamp pattern
   --  from RFC 8439 §2.5.1.
   function Spec_Encode_R (Rb : Octet_Array) return Big.Big_Natural
   with
     Ghost,
     Pre  => Rb'Length = 16 and then Rb'Last < Integer'Last - 16,
     Post => Spec_Encode_R'Result < Spec_Pow2 (128);

   --  HACL\* `encode` — `2^(8*len) + nat_from_bytes_le(b)`. For full
   --  blocks `len = 16` so the high bit is 2^128. For the partial
   --  last block, `len < 16` so the high bit is 2^(8*len).
   function Spec_Encode_Block
     (B : Octet_Array; Len : Natural) return Big.Big_Natural
   with
     Ghost,
     Pre =>
       Len in 1 .. 16
       and then B'Length = Len
       and then B'Last < Integer'Last - 16;

   --  HACL\* `poly1305_update1` — single-block update step:
   --    acc' = (encode(b, len) + acc) * r mod prime
   function Spec_Update1
     (Acc, R : Big.Big_Natural; B : Octet_Array; Len : Natural)
      return Big.Big_Natural
   with
     Ghost,
     Pre  =>
       Len in 1 .. 16
       and then B'Length = Len
       and then B'Last < Integer'Last - 16
       and then Acc < Spec_Prime
       and then R < Spec_Prime,
     Post => Spec_Update1'Result < Spec_Prime;

   --  HACL\* `poly1305_update_last` — final partial-block update.
   --  Empty case is no-op (acc unchanged).
   function Spec_Update_Last
     (Acc, R : Big.Big_Natural; B : Octet_Array; Len : Natural)
      return Big.Big_Natural
   with
     Ghost,
     Pre  =>
       Len <= 15
       and then B'Length = Len
       and then B'Last < Integer'Last - 16
       and then Acc < Spec_Prime
       and then R < Spec_Prime,
     Post => Spec_Update_Last'Result < Spec_Prime;

   --  HACL\* `poly1305_update` — repeat_blocks fold: process every
   --  full 16-byte chunk of `Text` then a partial-tail update. The
   --  recursion is on the cursor: we strip one block from the front
   --  per recursive call until at most 15 bytes remain.
   function Spec_Update_All
     (Text : Octet_Array; Acc, R : Big.Big_Natural) return Big.Big_Natural
   with
     Ghost,
     Subprogram_Variant => (Decreases => Text'Length),
     Pre                =>
       Acc < Spec_Prime
       and then R < Spec_Prime
       and then Text'Last < Integer'Last - 16,
     Post               => Spec_Update_All'Result < Spec_Prime;

   --  HACL\* `poly1305_finish`: tag = nat_to_bytes_le_16 ((acc + s) mod 2^128).
   function Spec_Finish
     (Key : Key_Array; Acc : Big.Big_Natural) return Tag_Array
   with Ghost, Pre => Acc < Spec_Prime;

   --  HACL\* `poly1305_mac`: top-level. Init -> Update_All -> Finish.
   function Spec_Poly1305_Mac
     (Key : Key_Array; Message : Octet_Array) return Tag_Array
   with Ghost, Pre => Message'Last < Integer'Last - 16;

   ------------------------------------------------------------------
   --  Limb-projection ghost (HACL\* `as_nat5` / `feval5` port)
   ------------------------------------------------------------------
   --
   --  HACL\* `Hacl.Spec.Poly1305.Field32xN` defines:
   --
   --      let as_nat5 (s0,s1,s2,s3,s4) =
   --        v s0 + v s1 * pow2 26 + v s2 * pow2 52
   --             + v s3 * pow2 78 + v s4 * pow2 104
   --
   --      let feval5 limbs = (as_nat5 limbs) % prime
   --
   --  We mirror the structure here. The functions are exposed in the
   --  spec because Posts on private helpers (Add / Multiply / Carry /
   --  Load_Block) reference them — gnatprove needs the spec-level
   --  declarations to type-check Posts.
   --
   --  The bridging lemma chain needed to discharge `Mac`'s functional
   --  Post (`Out_Tag = Spec_Poly1305_Mac (Key, Message)`) is:
   --
   --    Lemma_Add_Correspondence       feval5 (Add a b)      = (feval5 a + feval5 b) mod prime
   --    Lemma_Multiply_Correspondence  feval5 (Mul a b)      = (feval5 a * feval5 b) mod prime
   --    Lemma_Carry_Preserves_Feval    feval5 (Carry l)      = feval5 l
   --    Lemma_Load_Block_Eq_Encode     as_nat5 (Load_Block b len final) = Spec_Encode_Block (...)
   --    Lemma_Final_Repack_Eq_Bytes    repack to bytes
   --                                     = nat_to_bytes_le_16 ((acc + s) mod 2^128)
   --
   --  HACL\* discharges these in `Hacl.Spec.Poly1305.Field32xN.Lemmas`
   --  (~3000 lines of F\*) — full SPARK port is multi-day. The
   --  scaffolding below is the start of that port.

   --  5×26-bit limb representation, public so functional Posts on
   --  the private helpers (Add / Multiply / Carry / Load_Block) can
   --  reference the projection ghost functions defined below.
   subtype Limb_Index is Natural range 0 .. 4;
   type Limbs is array (Limb_Index) of U64;

   --  Bound predicate: every limb fits in 26 bits. After Carry the
   --  accumulator satisfies this; HACL\*'s `felem_fits5` analogue.
   function All_Limbs_Fit_26 (L : Limbs) return Boolean
   is (for all I in Limb_Index => L (I) < 2**26)
   with Ghost;

   --  Power-of-two specialisations used by As_Nat5 (kept as constants
   --  to avoid repeated re-evaluation inside expression-function calls).
   function Pow2_26 return Big.Big_Natural
   is (Spec_Pow2 (26))
   with Ghost;
   function Pow2_52 return Big.Big_Natural
   is (Spec_Pow2 (52))
   with Ghost;
   function Pow2_78 return Big.Big_Natural
   is (Spec_Pow2 (78))
   with Ghost;
   function Pow2_104 return Big.Big_Natural
   is (Spec_Pow2 (104))
   with Ghost;

   package U64_Bigint is new Big.Unsigned_Conversions (Int => U64);

   --  HACL\* `as_nat5`: 5×26-bit limb array → integer value.
   function As_Nat5 (L : Limbs) return Big.Big_Natural
   is (U64_Bigint.To_Big_Integer (L (0))
       + U64_Bigint.To_Big_Integer (L (1)) * Pow2_26
       + U64_Bigint.To_Big_Integer (L (2)) * Pow2_52
       + U64_Bigint.To_Big_Integer (L (3)) * Pow2_78
       + U64_Bigint.To_Big_Integer (L (4)) * Pow2_104)
   with Ghost;

   --  HACL\* `feval5`: limb array → field element.
   function Feval5 (L : Limbs) return Big.Big_Natural
   is (As_Nat5 (L) mod Spec_Prime)
   with Ghost;

   ------------------------------------------------------------------
   --  Ghost_Bignum bridge (scalar-free value type, replaces Big_Integers)
   ------------------------------------------------------------------
   --
   --  Embeds the impl's five-limb representation into Tls_Core.Ghost_Bignum's
   --  Big_Nat (limbs 0..4, zero above) so the imperative Add / Multiply /
   --  Carry can be connected to the proven Big_Nat reduce algebra without
   --  the Ada.Numerics.Big_Numbers axiomatisation (the §0e wall). This is
   --  the migration target: once the Mac Post is re-proved over Big_Nat the
   --  Big_Integers spec above is dropped.

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
       and then
         (for all I in
            Ghost_Bignum.Limb_Index range 5 .. Ghost_Bignum.Max_Limbs - 1 =>
            To_Big_Nat (L) (I) = 0);

   --  Limbwise sum of two reduced limb vectors (the impl's pre-carry Add).
   function Sum_Limbs (A, B : Limbs) return Limbs
   is ([for I in Limb_Index => A (I) + B (I)])
   with Ghost, Pre => All_Limbs_Fit_26 (A) and then All_Limbs_Fit_26 (B);

   --  Add correspondence: the embedding of the limbwise sum equals the
   --  Big_Nat sum of the embeddings (each <= 2*In_Cap, no U64 wrap).
   procedure Lemma_Add_Embed (A, B : Limbs)
   with
     Ghost,
     Pre  => All_Limbs_Fit_26 (A) and then All_Limbs_Fit_26 (B),
     Post =>
       Ghost_Bignum."="
         (To_Big_Nat (Sum_Limbs (A, B)),
          Ghost_Bignum."+" (To_Big_Nat (A), To_Big_Nat (B)));

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

   ------------------------------------------------------------------
   --  Bit-shift / mask decomposition lemma (foundation for the carry
   --  and multiply correspondence proofs)
   ------------------------------------------------------------------
   --
   --  Identity: for any U64 X,
   --    U64 (X) = U64 (Shift_Right (X, 26)) * 2^26
   --              + U64 (X and Mask_26)
   --
   --  This is the *single* fact the Carry routine relies on for
   --  every limb. Discharging it once at the U64 level lets every
   --  subsequent As_Nat5 / Feval5 manipulation chain through.
   --
   --  HACL\* equivalent: `Hacl.Spec.Poly1305.Field32xN.Lemmas.lemma_carry26_wide`
   --  decomposed into the bitvec / arithmetic identity.

   procedure Lemma_Limb_Split_26 (X : U64)
   with
     Ghost,
     Post =>
       U64_Bigint.To_Big_Integer (X)
       = U64_Bigint.To_Big_Integer (Interfaces.Shift_Right (X, 26))
         * Pow2_26
         + U64_Bigint.To_Big_Integer (X and 16#03FF_FFFF#);

   --  The Pow2_X = Pow2 * Pow2_(X-26) commutativity lemmas. Each is
   --  a one-step chain via Lemma_Pow2_Plus_8 / Lemma_Pow2_Step. The
   --  chain `As_Nat5 (Carry l) mod prime = As_Nat5 (l) mod prime`
   --  needs each Pow2_X to be expressible as 2^26 * Pow2_(X-26) so
   --  that a carry from limb i (a multiple of 2^26 contribution at
   --  position i) lands as Pow2_(X-26) * (carry contrib) at position
   --  i+1.

   procedure Lemma_Pow2_52_Eq_26x26
   with Ghost, Post => Pow2_52 = Pow2_26 * Pow2_26;

   procedure Lemma_Pow2_78_Eq_52x26
   with Ghost, Post => Pow2_78 = Pow2_52 * Pow2_26;

   procedure Lemma_Pow2_104_Eq_78x26
   with Ghost, Post => Pow2_104 = Pow2_78 * Pow2_26;

   --  Top-limb modular fold: 2^130 ≡ 5 (mod prime). Used to discharge
   --  the Carry top-step where bits past 2^130 are folded back via × 5.
   procedure Lemma_Pow2_130_Mod_Prime
   with Ghost, Post => Spec_Pow2 (130) mod Spec_Prime = Big.To_Big_Integer (5);

   --  TODO: The following lemmas are needed to close the Mac Post
   --  (`Out_Tag = Spec_Poly1305_Mac (Key, Message)`):
   --
   --    Lemma_As_Nat5_Linear  (A, B, R)
   --      Pre  : R(I) = A(I) + B(I) with no overflow per limb
   --      Post : As_Nat5 (R) = As_Nat5 (A) + As_Nat5 (B)
   --    Lemma_Carry_Preserves_Feval (L_In, L_Out)
   --      Post : Feval5 (L_Out) = Feval5 (L_In)
   --    Lemma_Multiply_Mod_Prime (A, B, R)
   --      Post : Feval5 (R) = (As_Nat5 (A) * As_Nat5 (B)) mod prime
   --    Lemma_Load_Block_Eq_Encode  (B, Len, Final, Out_Limbs)
   --      Post : As_Nat5 (Out_Limbs) = Spec_Encode_Block (B, Len + (Final?0:1))
   --    Lemma_Repack_Eq_Bytes_LE
   --      Post : tag bytes = nat_to_bytes_le_16 ((acc + s) mod 2^128)
   --
   --  All five hit the gnatprove × Big_Integers_Ghost limitation that
   --  `To_Big_Integer (X + Y) = To_Big_Integer (X) + To_Big_Integer (Y)`
   --  is not built-in. Closing them requires either: (a) a generic
   --  `Lemma_To_Big_Add (X, Y, Z)` proven via cascading shifts and the
   --  existing `Lemma_Limb_Split_26`, or (b) a refactor of the imperative
   --  body that exposes per-limb arithmetic in a form already covered
   --  by GNAT runtime ghost lemmas (`s-aridou` `Lemma_Add_Commutation`).
   --  Either is multi-day work. Current state: foundation lemmas
   --  proved (Limb_Split_26, Pow2_Add, Pow2_*_Eq_*x26, Pow2_130_Mod_Prime).

   ------------------------------------------------------------------
   --  Imperative API
   ------------------------------------------------------------------

   procedure Mac
     (Key : Key_Array; Message : Octet_Array; Out_Tag : out Tag_Array)
   with
     Pre  => Message'Last < Integer'Last - 16,
     Post => Out_Tag = Spec_Poly1305_Mac (Key, Message);

end Tls_Core.Poly1305;
