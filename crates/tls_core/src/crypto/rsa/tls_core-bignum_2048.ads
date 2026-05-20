--  Tls_Core.Bignum_2048 — fixed-size 2048-bit big-integer arithmetic
--  for RSA verification.
--
--  Scope: just enough to implement RSA-PSS / PKCS#1 verify against a
--  2048-bit modulus (the RSA size mandated by every modern profile —
--  TLS 1.3 RFC 8446 §4.2.3 / NIST SP 800-131A). The modulus, the
--  signature, and the public exponent are all exchanged as 256-byte
--  big-endian buffers; that is the X.509 / PKCS#1 (RFC 8017) wire
--  convention and matches `INTEGER` encoding inside RSA SubjectPublic
--  KeyInfo.
--
--  The on-the-wire representation is therefore `Bigint`, a 256-byte
--  big-endian octet array (MSB at index 1, LSB at index 256).
--  Internally the body works in 64 little-endian 32-bit limbs (limb 0
--  is LSB) — performance: CIOS Montgomery (RFC 8017 commentary; HACL\*
--  `Hacl.Spec.Bignum.Montgomery.fst` uses the same algorithm shape).
--
--  Spec mirror (docs/conventions.md §0c):
--      hacl-star/code/bignum/Hacl.Spec.Bignum.ModExp.fst — square-and-
--      multiply at the spec layer, regardless of whether the impl uses
--      Montgomery, Barrett, or schoolbook reduction. The functional
--      Post on Mod_Exp / Mod_Mul lives at the integer layer (after
--      `Bn_V`) so the imperative impl can swap Montgomery ↔ schoolbook
--      without altering the spec.
--
--  Status (v0.5 platinum push, 2026-05-07):
--    * Ghost layer is real, computable, no `Spec_*` stubs (docs/conventions.md
--      §0d clause 4): `Bn_V` walks the 256 bytes and `Spec_Mod_Mul`
--      / `Spec_Mod_Exp` are square-and-multiply over Big_Integer.
--    * Posts are functional (clause 5): each one references real
--      Big_Integer arithmetic, not a tautology / not a length-only
--      shape.
--    * The functional Post equating the imperative CIOS Montgomery
--      output to the Big_Integer square-and-multiply spec is NOT
--      yet discharged at level=2. It is honest unproven (clause 1
--      not yet satisfied) — no SPARK_Mode (Off), no pragma Assume,
--      no annotation has been used to make it disappear (clause 6).
--      RFC 8017 §A.2 PSS test vectors and the Encode → Verify round-
--      trip in tls_core_tests exercise the chain end-to-end.

with Ada.Numerics.Big_Numbers.Big_Integers;
with Interfaces;

package Tls_Core.Bignum_2048
  with SPARK_Mode
is

   --  Make the `=` operator on Octet (Interfaces.Unsigned_8) directly
   --  visible inside `Post` expressions in this spec.
   use type Interfaces.Unsigned_8;

   Byte_Length : constant := 256;   --  2048 bits.

   subtype Bigint is Octet_Array (1 .. Byte_Length);
   --  Big-endian: Bigint (1) is the most significant byte,
   --  Bigint (256) is the least significant.

   Zero : constant Bigint := [others => 0];

   ---------------------------------------------------------------------
   --  Ghost spec layer.
   --
   --  `Bn_V` extracts the integer represented by a 256-byte big-endian
   --  buffer. `Spec_Mod_Mul` and `Spec_Mod_Exp` define modular multiply
   --  and modular exponentiation over Big_Integer: pure mathematical
   --  definitions, no representation hooks. The imperative procedures
   --  promise `Bn_V (Out_R) = Spec_Mod_X (Bn_V (A), Bn_V (B), Bn_V (N))`
   --  — the Montgomery-vs-schoolbook choice in the body is invisible.
   --
   --  Mirrors HACL\*  `Hacl.Spec.Bignum.ModExp.fst`:
   --      let bn_mod_exp_pre #t #len n a b_bits b =
   --        ... pow #(modulus n) (eval_bn a) (eval_bn b) % eval_bn n
   --  where `eval_bn` is HACL\*'s `Bn_V` (limb→nat) and `pow` is the
   --  recursive square-and-multiply on Big_Integer.
   ---------------------------------------------------------------------

   package Big renames Ada.Numerics.Big_Numbers.Big_Integers;

   use type Big.Big_Integer;

   --  Octet → Big_Integer, used to assemble Bn_V byte-by-byte.
   function Byte_Big (X : Octet) return Big.Big_Integer
   with
     Ghost,
     Global => null,
     Post   =>
       Big.In_Range
         (Byte_Big'Result, Big.To_Big_Integer (0), Big.To_Big_Integer (255));

   --  2 ** (8 * N). Bounded so it stays within reasonable proof depth.
   function Pow_2_8 (N : Natural) return Big.Big_Integer
   with
     Ghost,
     Global => null,
     Pre    => N <= Byte_Length,
     Post   => Pow_2_8'Result > Big.To_Big_Integer (0);

   --  Σ_{i=0..N-1} B (256 - i) * 2^(8*i) — integer value of the low
   --  N bytes of the BE 256-byte Bigint, expressed as a recursive
   --  prefix sum so gnatprove can unfold it at proof time. The Post
   --  is the inductive non-negativity statement: each summand is a
   --  non-negative byte times a positive power of two, and the base
   --  case is 0.
   function To_Big_Up_To (B : Bigint; N : Natural) return Big.Big_Integer
   is (if N = 0
       then Big.To_Big_Integer (0)
       else
         To_Big_Up_To (B, N - 1)
         + Byte_Big (B (Byte_Length - (N - 1))) * Pow_2_8 (N - 1))
   with
     Ghost,
     Global             => null,
     Pre                => N <= Byte_Length,
     Post               => To_Big_Up_To'Result >= Big.To_Big_Integer (0),
     Subprogram_Variant => (Decreases => N);

   --  Integer interpretation of the 256-byte big-endian Bigint
   --  (HACL\*  `eval_bn`).
   function Bn_V (B : Bigint) return Big.Big_Integer
   is (To_Big_Up_To (B, Byte_Length))
   with Ghost, Global => null, Post => Bn_V'Result >= Big.To_Big_Integer (0);

   --  Spec for modular multiplication: (A * B) mod N when N > 0,
   --  zero otherwise (mirroring the ads degenerate-case contract).
   function Spec_Mod_Mul (A, B, N : Big.Big_Integer) return Big.Big_Integer
   is (if N <= Big.To_Big_Integer (0)
       then Big.To_Big_Integer (0)
       else (A * B) mod N)
   with Ghost, Global => null;

   --  Spec for modular exponentiation: square-and-multiply over the
   --  big-integer Exp (HACL\*  `pow_mod` / `pow`), reduced mod N.
   --  N = 0 ⇒ 0 (matches the imperative degenerate path).
   --  N = 1 ⇒ 0 (everything is 0 mod 1).
   --  N even ⇒ defensively 0 — the imperative body has no Montgomery
   --  fast path for even N. RSA moduli are odd by construction
   --  (product of two odd primes); this clause is the spec mirror of
   --  the body's "be defensive about even N" guard.
   --
   --  When N is an odd integer > 1, Spec_Mod_Exp is the canonical
   --  Big_Integer modular-exponentiation result, in [0, N).
   function Spec_Mod_Exp
     (Base, Exp, N : Big.Big_Integer) return Big.Big_Integer
   with
     Ghost,
     Global => null,
     Pre    =>
       Base >= Big.To_Big_Integer (0)
       and then Exp >= Big.To_Big_Integer (0)
       and then N >= Big.To_Big_Integer (0),
     Post   =>
       Spec_Mod_Exp'Result >= Big.To_Big_Integer (0)
       and then (if N <= Big.To_Big_Integer (1)
                   or else N mod Big.To_Big_Integer (2)
                           = Big.To_Big_Integer (0)
                 then Spec_Mod_Exp'Result = Big.To_Big_Integer (0));

   --  Inverse of `Bn_V` for non-negative integers in [0, 2^2048):
   --  produces the canonical 256-byte big-endian buffer whose
   --  `Bn_V` is the input. This is HACL\*'s `nat_to_bytes_be 256`.
   --  Real, computable body — extracts each byte by mod/div on the
   --  Big_Integer value (no stub).
   --
   --  Lemma: round-trip property, `Big_To_Bigint (Bn_V (B)) = B` for
   --  any Bigint B (Bn_V is injective on Bigint into [0, 2^2048)).
   --  Stated as a separate Lemma_Bigint_Roundtrip ghost procedure so
   --  callers can invoke it on a specific Bigint to bring the equality
   --  into local scope; the Post-only formulation here would force
   --  every call to depend on the lemma.
   function Big_To_Bigint (X : Big.Big_Integer) return Bigint
   with Ghost, Global => null, Pre => X >= Big.To_Big_Integer (0);

   --  Round-trip lemma: encoding and decoding a 256-byte BE Bigint is
   --  the identity. This is HACL\*  `lib_intvector_intrinsics_vec_eq`
   --  + `nat_to_bytes_be_to_nat_eq` for our specialised 256-byte case.
   --  Honest unproven for now (would need an inductive proof over the
   --  byte loop in Big_To_Bigint vs the recursion in Bn_V); flagged
   --  per docs/conventions.md §0d clause 1 — clause-6 clean (no annotations).
   procedure Lemma_Bigint_Roundtrip (B : Bigint)
   with Ghost, Global => null, Post => Big_To_Bigint (Bn_V (B)) = B;

   --  Composed RSAVP1 / `nat_to_bytes_be` step from HACL\*
   --  `Spec.RSAPSS.fst : rsapss_verify_`:
   --      let m = pow_mod n s e in
   --      let em = nat_to_bytes_be emLen m in ...
   --  Real (executable) ghost: just the composition Big_To_Bigint
   --  ∘ Spec_Mod_Exp, both of which have real bodies.
   function Spec_Em_From_Pubkey_Sig (N, E, Signature : Bigint) return Bigint
   is (Big_To_Bigint (Spec_Mod_Exp (Bn_V (Signature), Bn_V (E), Bn_V (N))))
   with Ghost, Global => null;

   ---------------------------------------------------------------------
   --  Public API
   ---------------------------------------------------------------------

   --  --------------------------------------------------------------
   --  [VERIFIED — AoRTE]  A * B mod N.
   --
   --  Spec mirror: HACL\*  `Hacl.Spec.Bignum.ModExp.fst` :  `bn_mod_mul`.
   --  Functional:  Bn_V (Out_R) = Spec_Mod_Mul (Bn_V (A), Bn_V (B), Bn_V (N))
   --  Proven at:   honest unproven — the schoolbook→Montgomery
   --               equivalence on the imperative body is not yet
   --               discharged at level=2. Clause-6 clean (no
   --               SPARK_Mode (Off), no pragma Assume, no annotation).
   --
   --  N must be non-zero. If N is zero the output is the zero Bigint.
   --  --------------------------------------------------------------
   procedure Mod_Mul (A, B, N : Bigint; Out_R : out Bigint)
   with Post => Bn_V (Out_R) = Spec_Mod_Mul (Bn_V (A), Bn_V (B), Bn_V (N));

   --  --------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Base^Exp mod N.
   --
   --  Spec mirror: HACL\*  `Hacl.Spec.Bignum.ModExp.fst` :  `bn_mod_exp_mont`.
   --  Functional:  Bn_V (Out_R) = Spec_Mod_Exp (Bn_V (Base), Bn_V (Exp), Bn_V (N))
   --  Proven at:   honest unproven (same shape as Mod_Mul above).
   --
   --  Square-and-multiply MSB-first over the bits of Exp; CIOS
   --  Montgomery reduction in the imperative body. Spec is at the
   --  Big_Integer layer so the imperative algorithm choice is
   --  invisible to callers.
   --
   --  N must be non-zero. If N is zero or even or N = 1 the result
   --  is the zero Bigint (defensive — RSA moduli are always odd > 1
   --  by construction).
   --  --------------------------------------------------------------
   procedure Mod_Exp (Base, Exp, N : Bigint; Out_R : out Bigint)
   with
     Post => Bn_V (Out_R) = Spec_Mod_Exp (Bn_V (Base), Bn_V (Exp), Bn_V (N));

   --  Constant-time equality: no early exit on mismatch. Useful for
   --  signature comparison if the caller wants to avoid leaking via
   --  byte-position timing.
   function Equal_CT (A, B : Bigint) return Boolean
   with Post => Equal_CT'Result = (for all I in Bigint'Range => A (I) = B (I));

end Tls_Core.Bignum_2048;
