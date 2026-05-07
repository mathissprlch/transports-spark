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
--  Constant-time: the scalar's bits drive a CSWAP that XORs a
--  mask into both ladder branches; no branches depend on
--  scalar bits beyond the mask. The implementation is by
--  inspection constant-time over the scalar (and over u), the
--  same property the spec requires.

package Tls_Core.X25519
with SPARK_Mode
is

   subtype Bytes_32 is Octet_Array (1 .. 32);

   --  RFC 7748 §5: q = X25519(k, u). Functional content checked
   --  via RFC 7748 §5.2 test vectors in tls_core_tests.
   procedure Scalar_Mult
     (Scalar  : Bytes_32;
      U_Coord : Bytes_32;
      Out_Q   : out Bytes_32);

   --  RFC 7748 §6.1: derive a public key from a private scalar
   --  by multiplying the curve's base point.
   --      base_u = 9 (32 bytes little-endian)
   procedure Derive_Public
     (Private_Key : Bytes_32;
      Out_Public  : out Bytes_32);

end Tls_Core.X25519;
