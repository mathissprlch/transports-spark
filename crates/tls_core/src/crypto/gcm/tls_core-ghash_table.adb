--  Body of Tls_Core.Ghash_Table — see spec for design.

package body Tls_Core.Ghash_Table
  with SPARK_Mode
is

   use Interfaces;

   --  rem_4bit table — see OpenSSL gcm128.c. Bytes 1 and 2 of the
   --  reduction contribution when r falls off the bottom of the
   --  128-bit register during a 4-bit right shift. Derived by
   --  simulating four single-bit shifts of (r in low nibble of
   --  byte 16) under the bit-by-bit reduction rule "if low bit
   --  of byte 16 was 1, XOR 0xE1 into byte 1".
   Rem_4Bit_B1 : constant array (Unsigned_8 range 0 .. 15) of Octet :=
     [16#00#,
      16#1C#,
      16#38#,
      16#24#,
      16#70#,
      16#6C#,
      16#48#,
      16#54#,
      16#E1#,
      16#FD#,
      16#D9#,
      16#C5#,
      16#91#,
      16#8D#,
      16#A9#,
      16#B5#];

   Rem_4Bit_B2 : constant array (Unsigned_8 range 0 .. 15) of Octet :=
     [16#00#,
      16#20#,
      16#40#,
      16#60#,
      16#80#,
      16#A0#,
      16#C0#,
      16#E0#,
      16#00#,
      16#20#,
      16#40#,
      16#60#,
      16#80#,
      16#A0#,
      16#C0#,
      16#E0#];

   ---------------------------------------------------------------------
   --  Mul_By_X — multiply a 128-bit GF(2^128) value by x mod p.
   --  In our byte-MSB-first encoding (NIST §6.3) this is a 1-bit
   --  right shift across the 16 bytes, with reduction by 0xE1 in
   --  byte 1 if the low bit of byte 16 was 1 (i.e. coefficient x^127
   --  wraps to x^128).
   ---------------------------------------------------------------------

   procedure Mul_By_X (V : in out Block_16);
   procedure Mul_By_X (V : in out Block_16) is
      Carry_Out : constant Boolean := (V (16) and 16#01#) = 1;
      Prev      : Octet := 0;
      Cur_Lsb   : Octet;
   begin
      for I in 1 .. 16 loop
         Cur_Lsb := V (I) and 16#01#;
         V (I) :=
           Octet (Shift_Right (Unsigned_8 (V (I)), 1))
           or Octet (Shift_Left (Unsigned_8 (Prev), 7));
         Prev := Cur_Lsb;
      end loop;
      if Carry_Out then
         V (1) := V (1) xor 16#E1#;
      end if;
   end Mul_By_X;

   ---------------------------------------------------------------------
   --  Build — populate the 16-entry table from H.
   ---------------------------------------------------------------------

   procedure Build (H : Block_16; T : out Table) is
      H_X1 : constant Block_16 := H;   -- H · x^0 = H  (T(8))
      H_X2 : Block_16;                 -- H · x        (T(4))
      H_X3 : Block_16;                 -- H · x^2      (T(2))
      H_X4 : Block_16;                 -- H · x^3      (T(1))

      --  Local working entries — each is a Block_16 (16 octets);
      --  every byte is initialised in the loop below before the
      --  aggregate assignment to T.
      E3, E5, E6, E7, E9, E10, E11, E12, E13, E14, E15 : Block_16;
   begin
      --  Derive H · x, H · x^2, H · x^3 by repeated mul-by-x in
      --  GF(2^128). Mul_By_X is the right-shift-with-0xE1
      --  reduction.
      H_X2 := H_X1;
      Mul_By_X (H_X2);

      H_X3 := H_X2;
      Mul_By_X (H_X3);

      H_X4 := H_X3;
      Mul_By_X (H_X4);

      --  Remaining table entries: XOR combinations of the four
      --  basis values. For nibble n (bit 3, bit 2, bit 1, bit 0):
      --    bit 3 → H_X1, bit 2 → H_X2, bit 1 → H_X3, bit 0 → H_X4.
      for I in 1 .. 16 loop
         E3 (I) := H_X3 (I) xor H_X4 (I);
         E5 (I) := H_X2 (I) xor H_X4 (I);
         E6 (I) := H_X2 (I) xor H_X3 (I);
         E7 (I) := H_X2 (I) xor H_X3 (I) xor H_X4 (I);
         E9 (I) := H_X1 (I) xor H_X4 (I);
         E10 (I) := H_X1 (I) xor H_X3 (I);
         E11 (I) := H_X1 (I) xor H_X3 (I) xor H_X4 (I);
         E12 (I) := H_X1 (I) xor H_X2 (I);
         E13 (I) := H_X1 (I) xor H_X2 (I) xor H_X4 (I);
         E14 (I) := H_X1 (I) xor H_X2 (I) xor H_X3 (I);
         E15 (I) := H_X1 (I) xor H_X2 (I) xor H_X3 (I) xor H_X4 (I);
      end loop;

      --  Single aggregate write so flow analysis sees T fully
      --  initialised in one step.
      T :=
        [0  => [others => 0],
         1  => H_X4,
         2  => H_X3,
         3  => E3,
         4  => H_X2,
         5  => E5,
         6  => E6,
         7  => E7,
         8  => H_X1,
         9  => E9,
         10 => E10,
         11 => E11,
         12 => E12,
         13 => E13,
         14 => E14,
         15 => E15];
   end Build;

   ---------------------------------------------------------------------
   --  Multiply — Z := Z · H mod p using the precomputed table.
   --
   --  Algorithm (OpenSSL gcm_gmult_4bit, NIST §6.3): walk the 32
   --  nibbles of the input Y = Z (saved up-front so we can read
   --  while modifying Z), low-nibble of byte 16 first, then high
   --  nibble of byte 16, low of 15, …, high of 1.
   --
   --  Init: B = T(low nibble of byte 16).
   --  Per step (31 of them): shift B right by 4 bits, capture the
   --  fall-off nibble of B(16), XOR Rem_4Bit[fall_off] into B(1)/B(2),
   --  XOR T[next nibble of Y] into B.
   ---------------------------------------------------------------------

   function Get_Nibble (V : Block_16; K : Natural) return Unsigned_8
   with Pre => K in 0 .. 31, Post => Get_Nibble'Result <= 15;

   function Get_Nibble (V : Block_16; K : Natural) return Unsigned_8 is
      Byte_Idx : constant Positive := 16 - (K / 2);
      Is_High  : constant Boolean := (K mod 2) = 1;
   begin
      if Is_High then
         return Shift_Right (Unsigned_8 (V (Byte_Idx)), 4) and 16#0F#;
      else
         return Unsigned_8 (V (Byte_Idx)) and 16#0F#;
      end if;
   end Get_Nibble;

   procedure Multiply (Z : in out Block_16; T : Table) is
      Y        : constant Block_16 := Z;
      B        : Block_16;
      Rem_Idx  : Unsigned_8;
      Init_Idx : constant Unsigned_8 := Get_Nibble (Y, 0);
      Next_Idx : Unsigned_8;
   begin
      B := T (Init_Idx);
      for K in 1 .. 31 loop
         pragma Loop_Invariant (K in 1 .. 31);
         --  Capture the fall-off nibble.
         Rem_Idx := Unsigned_8 (B (16)) and 16#0F#;
         --  Shift B right by 4 bits across the 16 bytes.
         for J in reverse 2 .. 16 loop
            B (J) :=
              Octet (Shift_Left (Unsigned_8 (B (J - 1)) and 16#0F#, 4))
              or Octet (Shift_Right (Unsigned_8 (B (J)), 4));
         end loop;
         B (1) := Octet (Shift_Right (Unsigned_8 (B (1)), 4));
         --  Apply 4-bit reduction contribution to top of B.
         B (1) := B (1) xor Rem_4Bit_B1 (Rem_Idx);
         B (2) := B (2) xor Rem_4Bit_B2 (Rem_Idx);
         --  XOR T[next nibble of Y] into B.
         Next_Idx := Get_Nibble (Y, K);
         for I in 1 .. 16 loop
            B (I) := B (I) xor T (Next_Idx) (I);
         end loop;
      end loop;
      Z := B;
   end Multiply;

end Tls_Core.Ghash_Table;
