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
pragma Warnings (Off, "is an internal GNAT unit");
pragma Warnings (Off, "use of this unit is non-portable");
with Ada.Numerics.Big_Numbers.Big_Integers_Ghost;
pragma Warnings (On, "use of this unit is non-portable");
pragma Warnings (On, "is an internal GNAT unit");

package Tls_Core.Poly1305
with SPARK_Mode
is

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
   is (if N = 0 then Big.To_Big_Integer (1)
       else Big.To_Big_Integer (2) * Spec_Pow2 (N - 1))
   with Ghost,
        Subprogram_Variant => (Decreases => N);

   --  Lemma: 2^(N+1) = 2 * 2^N. Body proves it by case analysis on
   --  whether N hits the base block of Spec_Pow2.
   procedure Lemma_Pow2_Step (N : Natural)
   with Ghost,
        Pre  => N < Natural'Last,
        Post => Spec_Pow2 (N + 1) = Big.To_Big_Integer (2) * Spec_Pow2 (N);

   --  Lemma: 2^(N+8) = 256 * 2^N. Used by Lemma_Bytes_Bound.
   procedure Lemma_Pow2_Plus_8 (N : Natural)
   with Ghost,
        Pre  => N < Natural'Last - 8,
        Post => Spec_Pow2 (N + 8) = Big.To_Big_Integer (256) * Spec_Pow2 (N);

   --  Lemma: Spec_Pow2 is strictly monotonic. Used to chain
   --  bounds across non-adjacent powers of two without a manual
   --  unrolling at every call site.
   procedure Lemma_Pow2_Monotone (M, N : Natural)
   with Ghost,
        Pre  => M <= N,
        Post => Spec_Pow2 (M) <= Spec_Pow2 (N);

   --  Lemma: 2^128 < 2^130 - 5 = Spec_Prime. Required to chain
   --  the Spec_Encode_R bound (< 2^128) into the Spec_Update_All
   --  precondition (< Spec_Prime).
   procedure Lemma_Pow2_128_Lt_Prime
   with Ghost,
        Post => Spec_Pow2 (128) < Spec_Prime;

   --  Lemma: nat_from_bytes_le is bounded by 2^(8*length). Used to
   --  bound Spec_Encode_R and Spec_Encode_Block.
   procedure Lemma_Bytes_Bound (B : Octet_Array)
   with Ghost,
        Pre  => B'Length <= 32,
        Post => Spec_Nat_From_Bytes_Le (B) < Spec_Pow2 (8 * B'Length),
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
   is
     (if B'Length = 0 then
        Big.To_Big_Integer (0)
      else
        Spec_Nat_From_Bytes_Le (B (B'First .. B'Last - 1))
          + Octet_Bigint.To_Big_Integer (B (B'Last))
            * Spec_Pow2 (8 * (B'Length - 1)))
   with
     Ghost,
     Pre => B'Length <= 32,
     Subprogram_Variant => (Decreases => B'Length);

   --  HACL\* `poly1305_encode_r` — clamped 16-byte-LE-decoded r.
   --  `Rb` is the lower 16 bytes of the 32-byte key as supplied at
   --  wire-level; the body re-applies the byte-level clamp pattern
   --  from RFC 8439 §2.5.1.
   function Spec_Encode_R (Rb : Octet_Array) return Big.Big_Natural
   with
     Ghost,
     Pre  => Rb'Length = 16
             and then Rb'Last < Integer'Last - 16,
     Post => Spec_Encode_R'Result < Spec_Pow2 (128);

   --  HACL\* `encode` — `2^(8*len) + nat_from_bytes_le(b)`. For full
   --  blocks `len = 16` so the high bit is 2^128. For the partial
   --  last block, `len < 16` so the high bit is 2^(8*len).
   function Spec_Encode_Block
     (B : Octet_Array; Len : Natural) return Big.Big_Natural
   with
     Ghost,
     Pre => Len in 1 .. 16
            and then B'Length = Len
            and then B'Last < Integer'Last - 16;

   --  HACL\* `poly1305_update1` — single-block update step:
   --    acc' = (encode(b, len) + acc) * r mod prime
   function Spec_Update1
     (Acc, R : Big.Big_Natural;
      B      : Octet_Array;
      Len    : Natural)
      return Big.Big_Natural
   with
     Ghost,
     Pre  => Len in 1 .. 16
             and then B'Length = Len
             and then B'Last < Integer'Last - 16
             and then Acc < Spec_Prime
             and then R < Spec_Prime,
     Post => Spec_Update1'Result < Spec_Prime;

   --  HACL\* `poly1305_update_last` — final partial-block update.
   --  Empty case is no-op (acc unchanged).
   function Spec_Update_Last
     (Acc, R : Big.Big_Natural;
      B      : Octet_Array;
      Len    : Natural)
      return Big.Big_Natural
   with
     Ghost,
     Pre  => Len <= 15
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
     (Text   : Octet_Array;
      Acc, R : Big.Big_Natural)
      return Big.Big_Natural
   with
     Ghost,
     Subprogram_Variant => (Decreases => Text'Length),
     Pre  => Acc < Spec_Prime and then R < Spec_Prime
             and then Text'Last < Integer'Last - 16,
     Post => Spec_Update_All'Result < Spec_Prime;

   --  HACL\* `poly1305_finish`: tag = nat_to_bytes_le_16 ((acc + s) mod 2^128).
   function Spec_Finish
     (Key : Key_Array; Acc : Big.Big_Natural) return Tag_Array
   with
     Ghost,
     Pre => Acc < Spec_Prime;

   --  HACL\* `poly1305_mac`: top-level. Init -> Update_All -> Finish.
   function Spec_Poly1305_Mac
     (Key : Key_Array; Message : Octet_Array) return Tag_Array
   with
     Ghost,
     Pre => Message'Last < Integer'Last - 16;

   ------------------------------------------------------------------
   --  Imperative API
   ------------------------------------------------------------------

   procedure Mac
     (Key     : Key_Array;
      Message : Octet_Array;
      Out_Tag : out Tag_Array)
   with
     Pre  => Message'Last < Integer'Last - 16,
     Post => Out_Tag = Spec_Poly1305_Mac (Key, Message);

end Tls_Core.Poly1305;
