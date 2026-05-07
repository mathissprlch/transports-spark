--  Tls_Core.Field25519 — arithmetic over GF(2^255 - 19), shared by
--  X25519 (RFC 7748) and Ed25519 (RFC 8032).
--
--  Representation: 16 limbs of nominally 16 bits each, signed
--  Integer_64 accumulators. This is the TweetNaCl `gf` shape.
--  Multiplication produces 32-bit limb-products; sums of 16 such
--  in F_Mul plus the 38× fold-down stay safely inside Integer_64.
--
--  No functional Posts: GF(2^255 - 19) arithmetic is exercised
--  end-to-end via the X25519 / Ed25519 RFC test vectors at
--  callsite. The leaf operations here are pure SPARK over a
--  Felt limb representation; absence of runtime errors is
--  what gnatprove discharges.

with Interfaces;

package Tls_Core.Field25519
with SPARK_Mode
is

   use type Interfaces.Integer_64;

   subtype Bytes_32 is Octet_Array (1 .. 32);
   subtype Felt_Index is Natural range 0 .. 15;
   type Felt is array (Felt_Index) of Interfaces.Integer_64;

   --  Propagate each limb's bits past 16 into the next one (with
   --  the modulus fold-down on the top limb: 2^256 ≡ 38 mod p).
   procedure Carry (O : in out Felt);

   --  Limb-wise add and subtract. No reduction (caller is expected
   --  to follow with a multiply or final reduction shortly).
   procedure F_Add (O : out Felt; A, B : Felt);

   procedure F_Sub (O : out Felt; A, B : Felt);

   --  Multiply mod p, with two carry passes producing canonical-
   --  ish output. F_Sqr(o, a) = F_Mul(o, a, a).
   procedure F_Mul (O : out Felt; A, B : Felt);

   procedure F_Sqr (O : out Felt; A : Felt);

   --  Inverse mod p via Fermat: a^(p-2). Uses the standard
   --  exponent walk (squaring 254 times, with multiplies inserted
   --  at every bit set in p-2 = 2^255 - 21, i.e., all bits except
   --  bit 2 and bit 4).
   procedure F_Inv (O : out Felt; I_Val : Felt);

   --  z^((p-5)/8). Used by Ed25519 point decompression to recover
   --  x from y via the Tonelli-style square root for p ≡ 5 mod 8.
   --  Algorithm: c <- z; for a from 250 downto 0: c <- c²;
   --  if a /= 1 then c <- c*z. Same shape as TweetNaCl pow2523.
   procedure Pow_2523 (O : out Felt; Z : Felt);

   --  Constant-time conditional swap. Swap_Bit = 1 swaps every
   --  limb of P and Q; Swap_Bit = 0 leaves them untouched. No
   --  branches dependent on Swap_Bit.
   procedure C_Swap
     (P, Q     : in out Felt;
      Swap_Bit : Interfaces.Integer_64);

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
     (X : Interfaces.Integer_64; N : Natural)
      return Interfaces.Integer_64;

   function And_64
     (X, Y : Interfaces.Integer_64)
      return Interfaces.Integer_64;

end Tls_Core.Field25519;
