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

package Tls_Core.Aes_Core
with SPARK_Mode
is

   subtype Block is Octet_Array (1 .. 16);

   --  No functional Posts. FIPS 197 §C.* test vectors at the
   --  Aes128 / Aes256 layer exercise the composed primitives.

   --  FIPS 197 §5.1.1 SubBytes — apply the S-box byte-wise.
   procedure Sub_Bytes (S : in out Block);

   --  FIPS 197 §5.1.2 ShiftRows — cyclic-left-shift rows 1, 2, 3 by
   --  1, 2, 3 bytes respectively (row 0 is unchanged).
   procedure Shift_Rows (S : in out Block);

   --  FIPS 197 §5.1.3 MixColumns — multiply each column by the
   --  fixed polynomial {03}x^3 + {01}x^2 + {01}x + {02} mod
   --  (x^4 + 1) over GF(2^8).
   procedure Mix_Columns (S : in out Block);

   --  FIPS 197 §5.1.4 AddRoundKey — XOR the 16-byte slice of RK
   --  starting at Round * 16 + 1 into S.
   procedure Add_Round_Key
     (S     : in out Block;
      RK    : Octet_Array;
      Round : Natural)
   with
     Pre  => RK'First = 1
             and then Round * 16 + 16 <= RK'Length;

   --  Combined SubBytes + ShiftRows + MixColumns + AddRoundKey for
   --  one full round of AES (rounds 1..Nr-1; the final round skips
   --  MixColumns and is composed inline).
   procedure Full_Round
     (S     : in out Block;
      RK    : Octet_Array;
      Round : Natural)
   with
     Pre  => RK'First = 1
             and then Round * 16 + 16 <= RK'Length;

   --  Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns).
   procedure Final_Round
     (S     : in out Block;
      RK    : Octet_Array;
      Round : Natural)
   with
     Pre  => RK'First = 1
             and then Round * 16 + 16 <= RK'Length;

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
     (16#01#, 16#02#, 16#04#, 16#08#, 16#10#,
      16#20#, 16#40#, 16#80#, 16#1B#, 16#36#);

end Tls_Core.Aes_Core;
