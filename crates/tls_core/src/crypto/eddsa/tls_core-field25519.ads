--  Tls_Core.Field25519 — arithmetic over GF(2^255 - 19), shared by
--  X25519 (RFC 7748) and Ed25519 (RFC 8032).
--
--  Representation: 16 limbs of nominally 16 bits each, signed
--  Integer_64 accumulators. This is the TweetNaCl `gf` shape.
--  Multiplication produces 32-bit limb-products; sums of 16 such
--  in F_Mul plus the 38× fold-down stay safely inside Integer_64.
--
--  Functional Posts: every public field operation has a Post that
--  links the represented integer of the output to the canonical
--  HACL\* spec
--      Spec.Curve25519.fst :  fadd / fsub / fmul / fsqr / finv
--  via the ghost layer below. The represented integer of a Felt F
--  is `To_Big_Spec (F)` and the field-equivalence relation
--  `Equiv_Spec (A, B)` is congruence modulo p = 2^255 - 19. Every
--  Post says "the value of the output, modulo p, equals the HACL\*
--  spec value of the inputs, modulo p."
--
--  Status (v0.5 platinum push, 2026-05-07):
--    * Ghost layer is real, computable, no `Spec_X` stubs (docs/conventions.md
--      §0d clause 4).
--    * Posts are functional (docs/conventions.md §0d clause 5): each one
--      references real Big_Integer arithmetic, not a tautology.
--    * The imperative impl's AoRTE checks (overflow / range on the
--      signed-Integer_64 limb arithmetic) and the functional Post
--      proofs are NOT yet discharged at level=2. They are honest
--      unproven VCs (docs/conventions.md §0d clause 1 not yet satisfied) —
--      no SPARK_Mode (Off), no pragma Assume, no annotation has
--      been used to make them disappear. Proving them platinum
--      requires Felt-bound Pre conditions + per-limb invariants
--      tracking a refined `bounded` predicate through Carry /
--      F_Mul, mirroring HACL\*'s `felem5_seq.fst` lemma stack.
--      Multi-day work; deferred.

with Interfaces;

with Ada.Numerics.Big_Numbers.Big_Integers;

with Tls_Core.Ghost_Bignum;
with Tls_Core.Ghost_Bignum.Value;

package Tls_Core.Field25519
  with SPARK_Mode
is

   use type Interfaces.Integer_64;

   subtype Bytes_32 is Octet_Array (1 .. 32);
   subtype Felt_Index is Natural range 0 .. 15;
   type Felt is array (Felt_Index) of Interfaces.Integer_64;

   --  felem_fits analogue (HACL\* Hacl.Spec.Curve25519.Field51.Lemmas):
   --  every limb's magnitude is at or below Bound. The leaf field ops carry
   --  a bound Pre/Post so the signed-Integer_64 limb arithmetic provably
   --  stays inside the 64-bit accumulator (absence of runtime errors) and so
   --  callers (the X25519 ladder) can thread a per-step limb invariant.
   function In_Felem (F : Felt; Bound : Interfaces.Integer_64) return Boolean
   is (for all I in Felt_Index => F (I) >= -Bound and then F (I) <= Bound)
   with Ghost, Global => null, Pre => Bound >= 0;

   --  Carry-output shape (HACL\* mul_inv_t analogue): limbs 1 .. 15 are
   --  fully reduced to the low 16 bits (0 .. 2**16-1); limb 0 alone may
   --  carry the 38× top-fold and is bounded by Top. This non-uniform
   --  predicate is what lets the second carry pass in F_Mul converge to a
   --  tight re-feedable output (a uniform In_Felem loses limb 0's shape).
   function Carried (F : Felt; Top : Interfaces.Integer_64) return Boolean
   is (F (0) >= 0
       and then F (0) <= Top
       and then (for all I in Felt_Index =>
                   (if I >= 1 then F (I) >= 0 and then F (I) <= 2**16 - 1)))
   with Ghost, Global => null, Pre => Top >= 0;

   --  Limb-magnitude budget for the leaf field ops (AoRTE discipline):
   --    * Carry accepts up to Carry_In_Cap (covers the F_Mul fold output,
   --      <= 39 * 16 * (2**20)**2 = 624 * 2**40 < 2**50 < Carry_In_Cap) and
   --      reduces a wide input to a Carry_Out_Cap-bounded limb 0 (the 38×
   --      top-fold) with limbs 1 .. 15 in 0 .. 2**16-1.
   --    * A once-carried element (Carried (.,Carry_Out_Cap)) re-carries to a
   --      tight Reduced_Cap output, which re-feeds F_Mul.
   Carry_In_Cap  : constant Interfaces.Integer_64 := 2**55;
   Carry_Out_Cap : constant Interfaces.Integer_64 := 2**45;
   Reduced_Cap   : constant Interfaces.Integer_64 := 2**17;

   --  F_Mul / F_Sqr input budget: each of the 31 convolution columns sums at
   --  most 16 products of magnitude <= Bound**2 (one per outer limb), so the
   --  whole buffer is <= 16 * Bound**2; the 38× fold then gives <= 39 * 16 *
   --  Bound**2.  With Bound = 2**20 that is 624 * 2**40 < 2**50 < Carry_In_Cap.
   --  Output is the tight Reduced_Cap (two carry passes); a single F_Add of
   --  two outputs (<= 2 * Reduced_Cap = 2**18) stays within F_Mul_In_Cap.
   F_Mul_In_Cap : constant Interfaces.Integer_64 := 2**20;

   --  F_Add / F_Sub input budget: a limb sum/difference of two bounded
   --  elements must stay inside Integer_64 with headroom for the ghost
   --  Limb_Big additivity lemma (Val_Int = -2**110 .. 2**110).
   F_Add_Cap : constant Interfaces.Integer_64 := 2**62 - 1;

   ---------------------------------------------------------------------
   --  Ghost spec layer.
   --
   --  These are the bare essentials needed to write functional Posts
   --  on the public field operations. The full ported HACL\*
   --  Spec.Curve25519.fst lives in `Tls_Core.Field25519.Spec`
   --  (child); the helpers here form the minimal interface so the
   --  Posts on F_Add/F_Sub/F_Mul/F_Sqr/F_Inv don't drag the whole
   --  child package into every consumer's view.
   ---------------------------------------------------------------------

   package Big renames Ada.Numerics.Big_Numbers.Big_Integers;

   use type Big.Big_Integer;

   --  Σ F(i) * 2^(16*i) — the integer represented by 16 signed limbs.
   --  Expressed as a recursive prefix-sum so gnatprove can unfold
   --  it at proof time and reason about per-limb decomposition
   --  without a loop invariant.
   --
   --  §0e-clean ingress: Limb_Big / Pow_2_16 are built on
   --  Ghost_Bignum.Value.Limb_Val (the unit-recursion limb→Big_Integer
   --  ingress whose +/-/* algebra is provable), NOT the SPARK_Mode-Off
   --  To_Big_Integer. Big_Integer remains the codomain (the only unbounded
   --  scalar SPARK has) but the limb-array bridge never bounces off the
   --  opaque ingress, so the linearity Posts below are dischargeable.
   function Limb_Big (X : Interfaces.Integer_64) return Big.Big_Integer
   with
     Ghost,
     Global => null,
     Post   =>
       Limb_Big'Result = Ghost_Bignum.Value.Limb_Val (Ghost_Bignum.LLI (X));

   --  2 ** (16 * N) = (2^16)^N, built from Limb_Val (65536) by recursion
   --  (NOT To_Big_Integer (2) ** ..), with the one-step factor exposed in
   --  the Post so To_Big_Up_To can unfold it.
   function Pow_2_16 (N : Natural) return Big.Big_Integer
   with
     Ghost,
     Global             => null,
     Pre                => N <= 16,
     Post               =>
       Pow_2_16'Result > Big.To_Big_Integer (0)
       and then (if N = 0
                 then Pow_2_16'Result = Ghost_Bignum.Value.Limb_Val (1))
       and then (if N >= 1
                 then
                   Pow_2_16'Result
                   = Pow_2_16 (N - 1) * Ghost_Bignum.Value.Limb_Val (65536)),
     Subprogram_Variant => (Decreases => N);

   function To_Big_Up_To (F : Felt; N : Natural) return Big.Big_Integer
   is (if N = 0
       then Big.To_Big_Integer (0)
       else To_Big_Up_To (F, N - 1) + Limb_Big (F (N - 1)) * Pow_2_16 (N - 1))
   with
     Ghost,
     Global             => null,
     Pre                => N <= 16,
     Subprogram_Variant => (Decreases => N);

   function To_Big_Spec (F : Felt) return Big.Big_Integer
   is (To_Big_Up_To (F, 16))
   with Ghost, Global => null;

   --  p = 2^255 - 19, the Curve25519 base-field prime.
   function Prime_P_Spec return Big.Big_Integer
   with
     Ghost,
     Global => null,
     Post   => Prime_P_Spec'Result > Big.To_Big_Integer (0);

   --  Canonical residue mod p.
   function Mod_P_Spec (X : Big.Big_Integer) return Big.Big_Integer
   with
     Ghost,
     Global => null,
     Post   =>
       Big.In_Range
         (Mod_P_Spec'Result,
          Big.To_Big_Integer (0),
          Prime_P_Spec - Big.To_Big_Integer (1));

   --  Equivalence mod p.
   function Equiv_Spec (A, B : Big.Big_Integer) return Boolean
   is (Mod_P_Spec (A) = Mod_P_Spec (B))
   with Ghost, Global => null;

   ---------------------------------------------------------------------
   --  Public field operations with functional Posts.
   ---------------------------------------------------------------------

   --  Propagate each limb's bits past 16 into the next one (with
   --  the modulus fold-down on the top limb: 2^256 ≡ 38 mod p).
   --
   --  Carry preserves the represented integer modulo p — the
   --  fold of a top-limb spillover by 38 = 2^256 mod p witnesses
   --  this directly. Equiv post locks that property.
   --
   --  The In_Felem / Carried Pre / Post conjuncts are the AoRTE / felem_fits
   --  half (proven): a Carry_In_Cap-bounded input keeps every signed-Integer_64
   --  intermediate in range and yields a Carried (.,Carry_Out_Cap) output;
   --  if the input was already once-carried (Carried (.,Carry_Out_Cap)) the
   --  output tightens to Carried (.,Reduced_Cap). The Equiv_Spec conjunct is
   --  the mod-p functional half (the 2^255-19 reduce-algebra port over the
   --  value layer, not yet discharged — honest-unproven, no bypass).
   procedure Carry (O : in out Felt)
   with
     Pre  => In_Felem (O, Carry_In_Cap),
     Post =>
       Equiv_Spec (To_Big_Spec (O), To_Big_Spec (O'Old))
       and then Carried (O, Carry_Out_Cap)
       and then (if Carried (O'Old, Carry_Out_Cap)
                 then Carried (O, Reduced_Cap));

   --  Limb-wise add. Linearity of To_Big_Spec gives
   --      To_Big_Spec (O) = To_Big_Spec (A) + To_Big_Spec (B)
   --  exactly (no reduction). The In_Felem Pre/Post is the AoRTE half:
   --  bounded inputs give a sum bounded by twice the input cap.
   procedure F_Add (O : out Felt; A, B : Felt)
   with
     Pre  => In_Felem (A, F_Add_Cap) and then In_Felem (B, F_Add_Cap),
     Post =>
       To_Big_Spec (O) = To_Big_Spec (A) + To_Big_Spec (B)
       and then (for all I in Felt_Index => O (I) = A (I) + B (I));

   procedure F_Sub (O : out Felt; A, B : Felt)
   with
     Pre  => In_Felem (A, F_Add_Cap) and then In_Felem (B, F_Add_Cap),
     Post =>
       To_Big_Spec (O) = To_Big_Spec (A) - To_Big_Spec (B)
       and then (for all I in Felt_Index => O (I) = A (I) - B (I));

   --  Multiply mod p, with two carry passes producing canonical-
   --  ish output. F_Sqr(o, a) = F_Mul(o, a, a).
   --
   --  Post: To_Big_Spec (O) ≡ To_Big_Spec (A) * To_Big_Spec (B)
   --  modulo p.  This is the F\*  fmul  spec.
   --
   --  The In_Felem Pre/Post is the AoRTE / felem_fits half (proven): an
   --  F_Mul_In_Cap-bounded pair multiplies (16-term convolution + 38× fold)
   --  inside Carry_In_Cap, then two carry passes reduce to the tight
   --  Reduced_Cap output that re-feeds the ladder. The Equiv_Spec conjunct
   --  is the mod-p functional half (honest-unproven, no bypass).
   procedure F_Mul (O : out Felt; A, B : Felt)
   with
     Pre  => In_Felem (A, F_Mul_In_Cap) and then In_Felem (B, F_Mul_In_Cap),
     Post =>
       Equiv_Spec (To_Big_Spec (O), To_Big_Spec (A) * To_Big_Spec (B))
       and then In_Felem (O, Reduced_Cap);

   procedure F_Sqr (O : out Felt; A : Felt)
   with
     Pre  => In_Felem (A, F_Mul_In_Cap),
     Post =>
       Equiv_Spec (To_Big_Spec (O), To_Big_Spec (A) * To_Big_Spec (A))
       and then In_Felem (O, Reduced_Cap);

   --  Inverse mod p via Fermat: a^(p-2). Uses the standard
   --  exponent walk (squaring 254 times, with multiplies inserted
   --  at every bit set in p-2 = 2^255 - 21, i.e., all bits except
   --  bit 2 and bit 4).
   --
   --  Post (defining-equation form): To_Big_Spec (O) is the
   --  multiplicative inverse of To_Big_Spec (I_Val) mod p when
   --  I_Val is non-zero mod p.
   procedure F_Inv (O : out Felt; I_Val : Felt)
   with
     Pre  => In_Felem (I_Val, F_Mul_In_Cap),
     Post =>
       In_Felem (O, Reduced_Cap)
       and then (if not Equiv_Spec
                          (To_Big_Spec (I_Val), Big.To_Big_Integer (0))
                 then
                   Equiv_Spec
                     (To_Big_Spec (O) * To_Big_Spec (I_Val),
                      Big.To_Big_Integer (1)));

   --  z^((p-5)/8). Used by Ed25519 point decompression to recover
   --  x from y via the Tonelli-style square root for p ≡ 5 mod 8.
   --  Algorithm: c <- z; for a from 250 downto 0: c <- c²;
   --  if a /= 1 then c <- c*z. Same shape as TweetNaCl pow2523.
   procedure Pow_2523 (O : out Felt; Z : Felt)
   with Pre => In_Felem (Z, F_Mul_In_Cap), Post => In_Felem (O, Reduced_Cap);

   --  Constant-time conditional swap. Swap_Bit = 1 swaps every
   --  limb of P and Q; Swap_Bit = 0 leaves them untouched. No
   --  branches dependent on Swap_Bit. The XOR pun is an exact
   --  conditional swap, so the result is a permutation of the inputs
   --  (relational Post) — any per-limb bound the caller knows about the
   --  inputs therefore transfers to the outputs.
   procedure C_Swap (P, Q : in out Felt; Swap_Bit : Interfaces.Integer_64)
   with
     Pre  => Swap_Bit in 0 .. 1,
     Post =>
       (P = P'Old and then Q = Q'Old) or else (P = Q'Old and then Q = P'Old);

   --  Final reduction mod p, then serialise to 32 LE bytes.
   procedure Pack (O : out Bytes_32; N : Felt)
   with Pre => In_Felem (N, F_Mul_In_Cap);

   --  Read 32 LE bytes into a field element. The high bit of byte
   --  32 is masked off (per RFC 7748 §5 Decode-X25519 / RFC 8032
   --  §5.1.3). Each limb is a 16-bit byte pair (<= 2**16-1 <= Reduced_Cap),
   --  so the output is a reduced-shape element.
   procedure Unpack (O : out Felt; B : Bytes_32)
   with Post => In_Felem (O, Reduced_Cap);

   --  Parity test: returns the low bit of the canonical packing.
   --  Used by Ed25519 to recover the sign bit of x during point
   --  decompression.
   function Parity (N : Felt) return Interfaces.Integer_64
   with Pre => In_Felem (N, F_Mul_In_Cap);

   --  Two helpers exposed because Ed25519's scalar-bit and sign-bit
   --  extraction reuses them; both are bit-pattern operations on
   --  Integer_64 with no semantic content beyond the obvious.
   function Asr
     (X : Interfaces.Integer_64; N : Natural) return Interfaces.Integer_64;

   function And_64 (X, Y : Interfaces.Integer_64) return Interfaces.Integer_64;

end Tls_Core.Field25519;
