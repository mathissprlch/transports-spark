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

package Tls_Core.Field25519
  with SPARK_Mode
is

   use type Interfaces.Integer_64;

   subtype Bytes_32 is Octet_Array (1 .. 32);
   subtype Felt_Index is Natural range 0 .. 15;
   type Felt is array (Felt_Index) of Interfaces.Integer_64;

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
   function Limb_Big (X : Interfaces.Integer_64) return Big.Big_Integer
   with Ghost, Global => null;

   function Pow_2_16 (N : Natural) return Big.Big_Integer
   with Ghost, Global => null, Pre => N <= 16;

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
   procedure Carry (O : in out Felt)
   with Post => Equiv_Spec (To_Big_Spec (O), To_Big_Spec (O'Old));

   --  Limb-wise add. Linearity of To_Big_Spec gives
   --      To_Big_Spec (O) = To_Big_Spec (A) + To_Big_Spec (B)
   --  exactly (no reduction).
   procedure F_Add (O : out Felt; A, B : Felt)
   with Post => To_Big_Spec (O) = To_Big_Spec (A) + To_Big_Spec (B);

   procedure F_Sub (O : out Felt; A, B : Felt)
   with Post => To_Big_Spec (O) = To_Big_Spec (A) - To_Big_Spec (B);

   --  Multiply mod p, with two carry passes producing canonical-
   --  ish output. F_Sqr(o, a) = F_Mul(o, a, a).
   --
   --  Post: To_Big_Spec (O) ≡ To_Big_Spec (A) * To_Big_Spec (B)
   --  modulo p.  This is the F\*  fmul  spec.
   procedure F_Mul (O : out Felt; A, B : Felt)
   with
     Post => Equiv_Spec (To_Big_Spec (O), To_Big_Spec (A) * To_Big_Spec (B));

   procedure F_Sqr (O : out Felt; A : Felt)
   with
     Post => Equiv_Spec (To_Big_Spec (O), To_Big_Spec (A) * To_Big_Spec (A));

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
     Post =>
       (if not Equiv_Spec (To_Big_Spec (I_Val), Big.To_Big_Integer (0))
        then
          Equiv_Spec
            (To_Big_Spec (O) * To_Big_Spec (I_Val), Big.To_Big_Integer (1)));

   --  z^((p-5)/8). Used by Ed25519 point decompression to recover
   --  x from y via the Tonelli-style square root for p ≡ 5 mod 8.
   --  Algorithm: c <- z; for a from 250 downto 0: c <- c²;
   --  if a /= 1 then c <- c*z. Same shape as TweetNaCl pow2523.
   procedure Pow_2523 (O : out Felt; Z : Felt);

   --  Constant-time conditional swap. Swap_Bit = 1 swaps every
   --  limb of P and Q; Swap_Bit = 0 leaves them untouched. No
   --  branches dependent on Swap_Bit.
   procedure C_Swap (P, Q : in out Felt; Swap_Bit : Interfaces.Integer_64);

   --  Final reduction mod p, then serialise to 32 LE bytes.
   procedure Pack (O : out Bytes_32; N : Felt);

   --  Read 32 LE bytes into a field element. The high bit of byte
   --  32 is masked off (per RFC 7748 §5 Decode-X25519 / RFC 8032
   --  §5.1.3).
   procedure Unpack (O : out Felt; B : Bytes_32);

   --  Parity test: returns the low bit of the canonical packing.
   --  Used by Ed25519 to recover the sign bit of x during point
   --  decompression.
   function Parity (N : Felt) return Interfaces.Integer_64;

   --  Two helpers exposed because Ed25519's scalar-bit and sign-bit
   --  extraction reuses them; both are bit-pattern operations on
   --  Integer_64 with no semantic content beyond the obvious.
   function Asr
     (X : Interfaces.Integer_64; N : Natural) return Interfaces.Integer_64;

   function And_64 (X, Y : Interfaces.Integer_64) return Interfaces.Integer_64;

end Tls_Core.Field25519;
