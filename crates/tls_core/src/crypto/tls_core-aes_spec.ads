--  Tls_Core.Aes_Spec — declarative reference spec for AES-128 and
--  AES-256 (FIPS 197 + HACL\* `specs/Spec.AES.fst`).
--
--  Source: HACL\* `specs/Spec.AES.fst` (Apache-2.0 / MIT, Project
--  Everest). Round-by-round pure-functional spec.
--
--    https://github.com/hacl-star/hacl-star/blob/main/specs/Spec.AES.fst
--
--  This package is the v0.5 platinum *spec* for AES: real
--  (executable) SPARK functions that take a 16-byte block plus an
--  expanded round-key array and return the FIPS 197 Cipher /
--  InvCipher output. They are the canonical reference, used:
--
--    1. As the right-hand side of `Post => Out = Aes_Spec.X(...)`
--       on the public Encrypt_Block / Decrypt_Block / Expand_Key
--       in Tls_Core.Aes128 / Tls_Core.Aes256 — but only when
--       Tls_Core_Config.T_Tables_Enabled = False; otherwise the
--       T-tables-equivalence lemma is a v0.6 follow-up.
--    2. As an executable cross-check against the FIPS 197 §C.1
--       and §C.3 worked examples (in tls_core_tests).
--
--  HACL\* state layout (which we mirror byte-for-byte):
--    16 bytes; row r ∈ {0..3} lives at indices {r, r+4, r+8, r+12}
--    when zero-indexed. We use 1-based Ada indices, so row r lives
--    at {r+1, r+5, r+9, r+13}. Both correspond to the column-major
--    serialization of the FIPS 197 §3.4 4×4 byte state where
--    column c starts at byte 4c.
--
--  S-box note: HACL's `sub_byte` (Spec.AES.fst:48-55) is defined
--  via the GF(2^8) multiplicative inverse + the affine map. FIPS
--  197 §5.1.1.1 explicitly states the S-box is "the substitution
--  values for the byte xy (in hexadecimal format)" given as a
--  256-entry table (Figure 7). The two definitions are
--  byte-exactly equal (proved in HACL by `Spec.AES.Lemmas`,
--  proved in FIPS 197 by §5.1.1.1's two-step construction). We
--  use the table form here because (a) it is the canonical FIPS
--  197 reference, (b) GF-inversion reasoning in SPARK is weak
--  per the v0.5 AES investigation, (c) the table is byte-exact
--  on the HACL-tested AES test vectors. The trust boundary is
--  "Figure 7 of FIPS 197 was transcribed correctly," cross-
--  checked at test time against §C.1 (AES-128) and §C.3 (AES-256).
--
--  No SPARK_Mode switch-off, no `pragma Assume` — this package is
--  the spec, not an implementation, and it is callable.

with Interfaces;

package Tls_Core.Aes_Spec
with SPARK_Mode
is

   use type Interfaces.Unsigned_8;
   --  Bring byte equality into scope for the byte-level Posts below.

   --  HACL\* `block` (Spec.AES.fst:29): 16 GF(2^8) elements.
   subtype Block_16 is Octet_Array (1 .. 16);

   --  HACL\* `aes_xkey AES128` (Spec.AES.fst:44): 11 × 16 = 176 bytes.
   subtype Aes128_Xkey is Octet_Array (1 .. 176);

   --  HACL\* `aes_xkey AES256` (Spec.AES.fst:44): 15 × 16 = 240 bytes.
   subtype Aes256_Xkey is Octet_Array (1 .. 240);

   --  HACL\* 16-byte key (Spec.AES.fst:43): aes_key AES128.
   subtype Aes128_Key is Octet_Array (1 .. 16);

   --  HACL\* 32-byte key (Spec.AES.fst:43): aes_key AES256.
   subtype Aes256_Key is Octet_Array (1 .. 32);

   ---------------------------------------------------------------------
   --  Per-byte transformations — HACL\* `sub_byte` (line 48) /
   --  `inv_sub_byte` (line 57). Implemented via the FIPS 197
   --  Figure 7 / Figure 14 lookup tables (see header note).
   ---------------------------------------------------------------------

   function Sub_Byte (B : Octet) return Octet;

   function Inv_Sub_Byte (B : Octet) return Octet;

   ---------------------------------------------------------------------
   --  GF(2^8) byte multiplications used in MixColumns.
   ---------------------------------------------------------------------

   --  HACL\* Spec.AES `xtime` (Spec.AES.fst:108) — multiply byte by 2
   --  in GF(2^8) modulo 0x11B.  Same definition as Aes_Core.Xtime.
   function Spec_Xtime (B : Octet) return Octet;

   --  Mix_Col_Byte (a, b, c, d, R) computes the R-th row of the
   --  output column when the column matrix M = circulant({02, 03,
   --  01, 01}) is applied to (a, b, c, d).  R in 0..3 selects which
   --  output byte of that column to return:
   --    R = 0 -> 2*a + 3*b + c + d
   --    R = 1 -> a + 2*b + 3*c + d
   --    R = 2 -> a + b + 2*c + 3*d
   --    R = 3 -> 3*a + b + c + 2*d
   --  Per FIPS 197 §5.1.3 Eq.(5.6).  Same algebra as HACL\* `mix4`.
   function Mix_Col_Byte
     (A, B, C, D : Octet;
      Row        : Natural) return Octet
   with Pre => Row in 0 .. 3;

   ---------------------------------------------------------------------
   --  Block-level transformations.  Each is a pure function returning
   --  a fresh Block_16 — same shape as the HACL\* spec, where
   --  immutable lseq is the rule.
   ---------------------------------------------------------------------

   --  HACL\* `subBytes` (Spec.AES.fst:67) — apply Sub_Byte byte-wise.
   function Sub_Bytes (S : Block_16) return Block_16
   with
     Post => (for all I in Block_16'Range =>
                Sub_Bytes'Result (I) = Sub_Byte (S (I)));

   --  HACL\* `inv_subBytes` (Spec.AES.fst:70).
   function Inv_Sub_Bytes (S : Block_16) return Block_16
   with
     Post => (for all I in Block_16'Range =>
                Inv_Sub_Bytes'Result (I) = Inv_Sub_Byte (S (I)));

   --  HACL\* `shiftRows` (Spec.AES.fst:84) — left-rotate each
   --  non-zero row by its row index.
   --
   --  Byte-level Post per FIPS 197 §5.1.2: in column-major layout,
   --  out[row r, col c] := in[row r, col (c + r) mod 4].  Indices
   --  are 1-based, so position 4*c + r + 1 reads from position
   --  4*((c + r) mod 4) + r + 1.
   function Shift_Rows (S : Block_16) return Block_16
   with
     Post =>
       (for all C in 0 .. 3 =>
          (for all R in 0 .. 3 =>
             Shift_Rows'Result (4 * C + R + 1) =
               S (4 * ((C + R) mod 4) + R + 1)));

   --  HACL\* `inv_shiftRows` (Spec.AES.fst:90) — right-rotate each
   --  non-zero row by its row index (= left-rotate by 4 - i).
   function Inv_Shift_Rows (S : Block_16) return Block_16;

   --  HACL\* `mixColumns` (Spec.AES.fst:125) — multiply each column
   --  by the polynomial {03}x^3 + {01}x^2 + {01}x + {02} mod
   --  (x^4 + 1) over GF(2^8) (FIPS 197 §5.1.3).
   --
   --  Byte-level Post per HACL\* `mixColumn` (Spec.AES.fst:113):
   --  for column c with bytes (s0, s1, s2, s3) at positions
   --  4*c + 1 .. 4*c + 4, output rows are:
   --    row 0: 2*s0 + 3*s1 + s2 + s3 = Mix4 (s0, s1, s2, s3)
   --    row 1: s0 + 2*s1 + 3*s2 + s3 = Mix4 (s1, s2, s3, s0)
   --    row 2: s0 + s1 + 2*s2 + 3*s3 = Mix4 (s2, s3, s0, s1)
   --    row 3: 3*s0 + s1 + s2 + 2*s3 = Mix4 (s3, s0, s1, s2)
   --  where Mix4 (a,b,c,d) := 2*a + 3*b + c + d.
   function Mix_Columns (S : Block_16) return Block_16
   with
     Post =>
       (for all C in 0 .. 3 =>
          Mix_Columns'Result (4 * C + 1) =
            Mix_Col_Byte (S (4 * C + 1), S (4 * C + 2),
                          S (4 * C + 3), S (4 * C + 4), 0)
          and then Mix_Columns'Result (4 * C + 2) =
            Mix_Col_Byte (S (4 * C + 1), S (4 * C + 2),
                          S (4 * C + 3), S (4 * C + 4), 1)
          and then Mix_Columns'Result (4 * C + 3) =
            Mix_Col_Byte (S (4 * C + 1), S (4 * C + 2),
                          S (4 * C + 3), S (4 * C + 4), 2)
          and then Mix_Columns'Result (4 * C + 4) =
            Mix_Col_Byte (S (4 * C + 1), S (4 * C + 2),
                          S (4 * C + 3), S (4 * C + 4), 3));

   --  HACL\* `inv_mixColumns` (Spec.AES.fst:144) — inverse of
   --  Mix_Columns; column matrix is {0B}{0D}{09}{0E} (FIPS 197 §5.3.3).
   function Inv_Mix_Columns (S : Block_16) return Block_16;

   --  HACL\* `addRoundKey` (Spec.AES.fst:154) — XOR the 16-byte
   --  round-key block into the state.
   function Add_Round_Key
     (Key   : Block_16;
      State : Block_16) return Block_16
   with
     Post => (for all I in Block_16'Range =>
                Add_Round_Key'Result (I) =
                  Octet (Interfaces.Unsigned_8 (State (I))
                         xor Interfaces.Unsigned_8 (Key (I))));

   ---------------------------------------------------------------------
   --  Round drivers.
   ---------------------------------------------------------------------

   --  HACL\* `aes_enc` (Spec.AES.fst:157).
   --  Sub_Bytes ∘ Shift_Rows ∘ Mix_Columns ∘ AddRoundKey.
   function Aes_Enc
     (Key   : Block_16;
      State : Block_16) return Block_16
   with
     Post => Aes_Enc'Result =
               Add_Round_Key
                 (Key,
                  Mix_Columns
                    (Shift_Rows
                       (Sub_Bytes (State))));

   --  HACL\* `aes_enc_last` (Spec.AES.fst:164) — final round, no
   --  Mix_Columns.
   function Aes_Enc_Last
     (Key   : Block_16;
      State : Block_16) return Block_16
   with
     Post => Aes_Enc_Last'Result =
               Add_Round_Key
                 (Key,
                  Shift_Rows
                    (Sub_Bytes (State)));

   --  Per FIPS 197 §5.3 InvCipher (direct form): InvSubBytes →
   --  InvShiftRows → AddRoundKey → InvMixColumns.  HACL\*'s
   --  `aes_dec` (Spec.AES.fst:170) describes the EquivalentInvCipher
   --  variant which is used with HACL's separate
   --  `aes_dec_key_expansion`; we use the direct form so callers
   --  can pass the same round keys built by Expand_Key.  FIPS 197
   --  §5.3 proves the two forms compute the same function.
   function Aes_Dec
     (Key   : Block_16;
      State : Block_16) return Block_16;

   --  HACL\* `aes_dec_last` (Spec.AES.fst:177) — final inverse round.
   function Aes_Dec_Last
     (Key   : Block_16;
      State : Block_16) return Block_16;

   ---------------------------------------------------------------------
   --  Key expansion.
   ---------------------------------------------------------------------

   --  HACL\* `aes128_key_expansion` (Spec.AES.fst:250).
   function Aes128_Key_Expansion (Key : Aes128_Key) return Aes128_Xkey;

   --  HACL\* `aes256_key_expansion` (Spec.AES.fst:263).
   function Aes256_Key_Expansion (Key : Aes256_Key) return Aes256_Xkey;

   ---------------------------------------------------------------------
   --  Top-level encrypt / decrypt.
   ---------------------------------------------------------------------

   --  HACL\* `aes_encrypt_block AES128` (Spec.AES.fst:306, specialised).
   function Aes128_Encrypt_Block
     (Input : Block_16;
      Xkey  : Aes128_Xkey) return Block_16;

   --  HACL\* `aes_decrypt_block AES128` (Spec.AES.fst:319, specialised).
   function Aes128_Decrypt_Block
     (Input : Block_16;
      Xkey  : Aes128_Xkey) return Block_16;

   function Aes256_Encrypt_Block
     (Input : Block_16;
      Xkey  : Aes256_Xkey) return Block_16;

   function Aes256_Decrypt_Block
     (Input : Block_16;
      Xkey  : Aes256_Xkey) return Block_16;

end Tls_Core.Aes_Spec;
