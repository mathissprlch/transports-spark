--  Tls_Core.Aes_Core — shared FIPS 197 AES round operations.
--
--  AES-128 and AES-256 differ only in key length and round count;
--  the round transformations (SubBytes, ShiftRows, MixColumns,
--  AddRoundKey) are identical. This module factors them out so:
--    1. There is exactly one copy of the S-box and the round logic.
--    2. Each round op is a top-level SPARK subprogram (= its own
--       gnatprove entity), so proofs parallelise across operations
--       instead of grinding sequentially through the inlined
--       Encrypt_Block body. miTLS does the same.
--    3. T-table mode (set via the `Tls_Core_Use_T_Tables`
--       configuration constant) collapses Sub_Bytes + Shift_Rows
--       + Mix_Columns into one table-driven Round_Op, without
--       changing the round-key schedule.
--
--  Source: FIPS 197 §5.1 (the round transformations).
--
--  Functional Post pinning:
--    Each public round op carries a functional Post tying the
--    in-out Block to the corresponding Aes_Spec function (HACL\*
--    Spec.AES.fst port).  Both code paths — round-by-round and
--    T-tables — discharge the same Post; the T-tables path is no
--    longer gated.

with Interfaces;
with Tls_Core.Aes_Spec;

package Tls_Core.Aes_Core
  with SPARK_Mode
is

   use type Interfaces.Unsigned_8;
   --  Bring the byte-equality operator into scope so the Posts below
   --  can compare Octet values directly.

   subtype Block is Octet_Array (1 .. 16);

   --  AES-256 has Nr = 14, so Round ranges over 0..14 across the
   --  AddRoundKey calls.  Bounding here prevents 32-bit overflow
   --  on `Round * 16` in the Pre clauses below.
   subtype Round_Index is Natural range 0 .. 14;

   ---------------------------------------------------------------------
   --  The 16-byte round key at index Round in the expanded key
   --  schedule.  Used by every functional Post below.  Non-ghost: the
   --  bodies of Add_Round_Key / Full_Round / Final_Round can call it
   --  directly to obtain a byte-identical 16-byte slice.
   ---------------------------------------------------------------------

   function Round_Key_Slice
     (RK : Octet_Array; Round : Round_Index) return Aes_Spec.Block_16
   with
     Pre  => RK'First = 1 and then Round * 16 + 16 <= RK'Length,
     Post =>
       (for all I in 1 .. 16 =>
          Round_Key_Slice'Result (I) = RK (Round * 16 + I));

   --  FIPS 197 §5.1.1 SubBytes — apply the S-box byte-wise.
   procedure Sub_Bytes (S : in out Block)
   with Post => S = Aes_Spec.Sub_Bytes (S'Old);

   --  FIPS 197 §5.1.2 ShiftRows — cyclic-left-shift rows 1, 2, 3 by
   --  1, 2, 3 bytes respectively (row 0 is unchanged).
   procedure Shift_Rows (S : in out Block)
   with Post => S = Aes_Spec.Shift_Rows (S'Old);

   --  FIPS 197 §5.1.3 MixColumns — multiply each column by the
   --  fixed polynomial {03}x^3 + {01}x^2 + {01}x + {02} mod
   --  (x^4 + 1) over GF(2^8).
   procedure Mix_Columns (S : in out Block)
   with Post => S = Aes_Spec.Mix_Columns (S'Old);

   --  FIPS 197 §5.1.4 AddRoundKey — XOR the 16-byte slice of RK
   --  starting at Round * 16 + 1 into S.
   procedure Add_Round_Key
     (S : in out Block; RK : Octet_Array; Round : Round_Index)
   with
     Pre  => RK'First = 1 and then Round * 16 + 16 <= RK'Length,
     Post => S = Aes_Spec.Add_Round_Key (Round_Key_Slice (RK, Round), S'Old);

   --  Combined SubBytes + ShiftRows + MixColumns + AddRoundKey for
   --  one full round of AES (rounds 1..Nr-1; the final round skips
   --  MixColumns and is composed inline).
   procedure Full_Round
     (S : in out Block; RK : Octet_Array; Round : Round_Index)
   with
     Pre  => RK'First = 1 and then Round * 16 + 16 <= RK'Length,
     Post => S = Aes_Spec.Aes_Enc (Round_Key_Slice (RK, Round), S'Old);

   --  Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns).
   procedure Final_Round
     (S : in out Block; RK : Octet_Array; Round : Round_Index)
   with
     Pre  => RK'First = 1 and then Round * 16 + 16 <= RK'Length,
     Post => S = Aes_Spec.Aes_Enc_Last (Round_Key_Slice (RK, Round), S'Old);

   --  S-box and Xtime exposed because the per-AES-variant key
   --  schedule (AES-128 KeyExpansion, AES-256 KeyExpansion) needs
   --  them. Single source of truth.
   function Sub_Byte (B : Octet) return Octet;
   function Xtime (B : Octet) return Octet;

   --  Round constants Rcon[1..10]. AES-128 uses 1..10; AES-256
   --  uses 1..7. Same table.
   subtype Rcon_Index is Positive range 1 .. 10;
   type Rcon_Array is array (Rcon_Index) of Octet;
   Rcon : constant Rcon_Array;

private

   Rcon : constant Rcon_Array :=
     [16#01#,
      16#02#,
      16#04#,
      16#08#,
      16#10#,
      16#20#,
      16#40#,
      16#80#,
      16#1B#,
      16#36#];

end Tls_Core.Aes_Core;
