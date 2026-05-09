--  Tls_Core.X25519 — Curve25519 scalar multiplication (RFC 7748).
--
--  Source: RFC 7748 §5 — The X25519 Function.
--
--      X25519(scalar, u_coordinate) =
--         x_coord(scalar * (u, _) on Curve25519 in Montgomery form)
--
--  Curve25519 is the Montgomery curve y^2 = x^3 + 486662 x^2 + x
--  over GF(p), p = 2^255 - 19. X25519 takes a 32-byte scalar k
--  and a 32-byte u-coordinate, performs the Montgomery ladder
--  for 255 iterations of conditional-swap + add + double, and
--  returns the resulting x-coordinate as 32 bytes.
--
--  TLS 1.3 (RFC 8446 §7.4.2.2) uses X25519 as the supported
--  group `secp256r1`-equivalent NIST primitive's preferred
--  alternative; nearly every modern peer offers x25519 first.
--
--  miTLS reference: this primitive is delegated to HACL\*'s
--  `Hacl.Curve25519` (functional spec in
--  `Spec.Curve25519.fst`). Our pure-Ada implementation mirrors
--  the reference TweetNaCl algorithm — same field-element
--  shape (16 limbs of 16 bits each, signed Integer_64
--  accumulators) — and matches the RFC 7748 §5.2 test vectors
--  byte-exact.
--
--  Functional Post: `Scalar_Mult` carries
--      Out_Q = Spec_X25519 (Scalar, U_Coord)
--  where `Spec_X25519` is the ported HACL\*  scalarmult  spec
--  built from the ghost layer
--
--      Spec_X25519 (k, u) =
--          encode_point ( montgomery_ladder ( decode_point u, k ) )
--
--  defined in this package. The body of `Spec_X25519` is a real,
--  computable function (CLAUDE.md §0d clause 4 — no stub
--  ghost spec; the body is a Big_Integer-based reference
--  implementation, not `return False` / `return Default`).
--
--  Constant-time: the scalar's bits drive a CSWAP that XORs a
--  mask into both ladder branches; no branches depend on
--  scalar bits beyond the mask. The implementation is by
--  inspection constant-time over the scalar (and over u), the
--  same property the spec requires.
--
--  Status (v0.5 platinum push, 2026-05-07):
--    * `Spec_X25519` and the ladder/decode/encode helpers are real
--      Big_Integer-based functions (CLAUDE.md §0d clause 4).
--    * `Scalar_Mult` and `Derive_Public` carry the
--      `Out = Spec_X25519 (input)` Post (clause 5).
--    * The Posts on Scalar_Mult / Derive_Public are not yet
--      discharged at level=2 (clause 1 not yet satisfied).
--      Discharging them platinum requires composing
--      Field25519's per-limb F_Add/F_Mul invariants through the
--      255-step ladder — the same lemma stack HACL\*'s
--      `Hacl.Spec.Curve25519.Field51.Lemmas.fst` contains.
--      No SPARK_Mode (Off), no pragma Assume, no annotation has
--      been used to make the unproven VCs disappear (clause 6).

with Ada.Numerics.Big_Numbers.Big_Integers;

with Tls_Core.Field25519;

package Tls_Core.X25519
with SPARK_Mode
is

   subtype Bytes_32 is Octet_Array (1 .. 32);

   ---------------------------------------------------------------------
   --  Ghost layer: the HACL\*  Spec.Curve25519  port.
   --
   --  Trace from `specs/Spec.Curve25519.fst`:
   --      let prime  = pow2 255 - 19
   --      type elem  = nat < prime
   --      let fadd / fsub / fmul = (op) % prime
   --      let finv x = x ** (prime - 2)  // Fermat
   --      let decodeScalar k = clamp k
   --      let decodePoint u  = (le u % 2^255) % prime
   --      let encodePoint p  = nat_to_bytes_le 32 (x /% z)
   --      montgomery_ladder via add_and_double + cswap
   --      scalarmult = encodePoint . ladder . decodePoint
   ---------------------------------------------------------------------

   package Big renames Ada.Numerics.Big_Numbers.Big_Integers;

   use type Big.Big_Integer;

   --  Decode the scalar per RFC 7748 §5: clear bits 0,1,2 of
   --  byte 0, clear bit 7 of byte 31, set bit 6 of byte 31.
   function Spec_Decode_Scalar (Scalar : Bytes_32) return Bytes_32
   with Ghost, Global => null;

   --  Decode the u-coordinate: little-endian, mask off the high bit
   --  of byte 31, reduce mod p.
   function Spec_Decode_Point (U_Coord : Bytes_32) return Big.Big_Integer
   with Ghost, Global => null,
        Post => Big.In_Range
                  (Spec_Decode_Point'Result,
                   Big.To_Big_Integer (0),
                   Field25519.Prime_P_Spec - Big.To_Big_Integer (1));

   --  Encode an elem (a value mod p) as 32 little-endian bytes.
   function Spec_Encode_Point (P : Big.Big_Integer) return Bytes_32
   with Ghost, Global => null,
        Pre => Big.In_Range
                 (P,
                  Big.To_Big_Integer (0),
                  Field25519.Prime_P_Spec - Big.To_Big_Integer (1));

   --  The Montgomery ladder, ported line-by-line from
   --  Spec.Curve25519.fst :: montgomery_ladder. The body is a real
   --  Big_Integer implementation that exercises 255 ladder steps —
   --  not a stub. See body for the F\* trace.
   function Spec_Montgomery_Ladder
     (Init   : Big.Big_Integer;
      Scalar : Bytes_32) return Big.Big_Integer
   with Ghost, Global => null,
        Pre  => Big.In_Range
                  (Init,
                   Big.To_Big_Integer (0),
                   Field25519.Prime_P_Spec - Big.To_Big_Integer (1)),
        Post => Big.In_Range
                  (Spec_Montgomery_Ladder'Result,
                   Big.To_Big_Integer (0),
                   Field25519.Prime_P_Spec - Big.To_Big_Integer (1));

   --  Top-level  scalarmult  spec.
   function Spec_X25519
     (Scalar  : Bytes_32;
      U_Coord : Bytes_32) return Bytes_32
   is (Spec_Encode_Point
         (Spec_Montgomery_Ladder
            (Spec_Decode_Point (U_Coord),
             Spec_Decode_Scalar (Scalar))))
   with Ghost, Global => null;

   ---------------------------------------------------------------------
   --  Public API.
   --
   --  Functional Post: byte-for-byte equality with the spec.
   --  Functional content checked via RFC 7748 §5.2 test vectors
   --  in tls_core_tests.
   ---------------------------------------------------------------------

   procedure Scalar_Mult
     (Scalar  : Bytes_32;
      U_Coord : Bytes_32;
      Out_Q   : out Bytes_32)
   with Post => Out_Q = Spec_X25519 (Scalar, U_Coord);

   --  RFC 7748 §6.1: derive a public key from a private scalar
   --  by multiplying the curve's base point.
   --      base_u = 9 (32 bytes little-endian)
   procedure Derive_Public
     (Private_Key : Bytes_32;
      Out_Public  : out Bytes_32)
   with Post => Out_Public =
                  Spec_X25519
                    (Private_Key,
                     (1 => 9, others => 0));

end Tls_Core.X25519;
