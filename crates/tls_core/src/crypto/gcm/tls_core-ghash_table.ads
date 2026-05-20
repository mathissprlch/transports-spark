--  Tls_Core.Ghash_Table — 4-bit precomputed multiplication table for
--  GCM's GHASH (NIST SP 800-38D §6.3 / RFC 8446 AEAD).
--
--  Pure-software speedup over bit-by-bit GF(2^128) multiplication.
--  A 16-entry table T(i) caches `i · H mod p` where i is a 4-bit
--  value injected into the leading nibble of a 128-bit MSB-first
--  polynomial. Every GHASH multiplication then walks the 32 nibbles
--  of the operand, performing a 4-bit right shift + reduction +
--  table-lookup XOR — ~16x fewer per-bit operations than the naïve
--  loop.
--
--  Algorithm: OpenSSL `crypto/modes/gcm128.c` `gcm_gmult_4bit`
--  (RFC 4543 Appendix B; cf. EverCrypt/HACL* for the verified form).
--  Table is private; only Build + Multiply are public.
--
--  Memory footprint: 16 × 16 = 256 bytes per cipher direction.

with Interfaces;

package Tls_Core.Ghash_Table
  with SPARK_Mode
is

   subtype Block_16 is Octet_Array (1 .. 16);

   --  Precomputed table type. Each entry is the product of a 4-bit
   --  nibble (placed in the leading 4 coefficients of the 128-bit
   --  polynomial) with the GCM hash key H, reduced mod p =
   --  x^128 + x^7 + x^2 + x + 1.
   type Table is private;

   --  Build T from H. Pure SPARK (no GF arithmetic library); the
   --  three power-of-two entries are derived by `mul-by-x`
   --  (right-shift-by-one with bytewise 0xE1 reduction); the
   --  remaining entries fall out by XOR.
   procedure Build (H : Block_16; T : out Table);

   --  In-place GHASH multiplication: Z := Z · H mod p, using the
   --  precomputed table T. Algorithmically equivalent to the
   --  bit-by-bit form but ~16x fewer per-bit operations.
   procedure Multiply (Z : in out Block_16; T : Table);

private

   type Table is array (Interfaces.Unsigned_8 range 0 .. 15) of Block_16;

end Tls_Core.Ghash_Table;
