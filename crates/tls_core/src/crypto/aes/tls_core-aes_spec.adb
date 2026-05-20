with Interfaces;

package body Tls_Core.Aes_Spec
  with SPARK_Mode
is

   --  Mix_Columns reuses the same column variables in rotated order
   --  per FIPS 197 §5.1.3 and HACL\* `mixColumn` (Spec.AES.fst:113)
   --  — the compiler's "wrong order" heuristic doesn't apply.
   pragma Warnings (Off, "actuals for this call may be in wrong order");
   --  Sub_Bytes / Inv_Sub_Bytes / Add_Round_Key seed Out_S from a
   --  parameter to keep SPARK happy about full-array aliveness;
   --  every byte is overwritten by the immediately following loop,
   --  so gnatprove flags the seed as "init has no effect". Expected.
   pragma Warnings (Off, "initialization of ""Out_S"" has no effect");

   use Interfaces;

   ---------------------------------------------------------------------
   --  S-box (FIPS 197 §5.1.1, Figure 7) and inverse S-box (Figure 14).
   --  These are the byte tables; they encode the same value as
   --  HACL\* `sub_byte` / `inv_sub_byte` (Spec.AES.fst:48, 57) per
   --  FIPS 197 §5.1.1.1's affine-map-of-finv construction. The
   --  FIPS 197 §C.* worked examples and the round-by-round trace in
   --  HACL\* test suites are the cross-validation.
   ---------------------------------------------------------------------

   S_Box : constant array (Octet) of Octet :=
     [16#63#,
      16#7C#,
      16#77#,
      16#7B#,
      16#F2#,
      16#6B#,
      16#6F#,
      16#C5#,
      16#30#,
      16#01#,
      16#67#,
      16#2B#,
      16#FE#,
      16#D7#,
      16#AB#,
      16#76#,
      16#CA#,
      16#82#,
      16#C9#,
      16#7D#,
      16#FA#,
      16#59#,
      16#47#,
      16#F0#,
      16#AD#,
      16#D4#,
      16#A2#,
      16#AF#,
      16#9C#,
      16#A4#,
      16#72#,
      16#C0#,
      16#B7#,
      16#FD#,
      16#93#,
      16#26#,
      16#36#,
      16#3F#,
      16#F7#,
      16#CC#,
      16#34#,
      16#A5#,
      16#E5#,
      16#F1#,
      16#71#,
      16#D8#,
      16#31#,
      16#15#,
      16#04#,
      16#C7#,
      16#23#,
      16#C3#,
      16#18#,
      16#96#,
      16#05#,
      16#9A#,
      16#07#,
      16#12#,
      16#80#,
      16#E2#,
      16#EB#,
      16#27#,
      16#B2#,
      16#75#,
      16#09#,
      16#83#,
      16#2C#,
      16#1A#,
      16#1B#,
      16#6E#,
      16#5A#,
      16#A0#,
      16#52#,
      16#3B#,
      16#D6#,
      16#B3#,
      16#29#,
      16#E3#,
      16#2F#,
      16#84#,
      16#53#,
      16#D1#,
      16#00#,
      16#ED#,
      16#20#,
      16#FC#,
      16#B1#,
      16#5B#,
      16#6A#,
      16#CB#,
      16#BE#,
      16#39#,
      16#4A#,
      16#4C#,
      16#58#,
      16#CF#,
      16#D0#,
      16#EF#,
      16#AA#,
      16#FB#,
      16#43#,
      16#4D#,
      16#33#,
      16#85#,
      16#45#,
      16#F9#,
      16#02#,
      16#7F#,
      16#50#,
      16#3C#,
      16#9F#,
      16#A8#,
      16#51#,
      16#A3#,
      16#40#,
      16#8F#,
      16#92#,
      16#9D#,
      16#38#,
      16#F5#,
      16#BC#,
      16#B6#,
      16#DA#,
      16#21#,
      16#10#,
      16#FF#,
      16#F3#,
      16#D2#,
      16#CD#,
      16#0C#,
      16#13#,
      16#EC#,
      16#5F#,
      16#97#,
      16#44#,
      16#17#,
      16#C4#,
      16#A7#,
      16#7E#,
      16#3D#,
      16#64#,
      16#5D#,
      16#19#,
      16#73#,
      16#60#,
      16#81#,
      16#4F#,
      16#DC#,
      16#22#,
      16#2A#,
      16#90#,
      16#88#,
      16#46#,
      16#EE#,
      16#B8#,
      16#14#,
      16#DE#,
      16#5E#,
      16#0B#,
      16#DB#,
      16#E0#,
      16#32#,
      16#3A#,
      16#0A#,
      16#49#,
      16#06#,
      16#24#,
      16#5C#,
      16#C2#,
      16#D3#,
      16#AC#,
      16#62#,
      16#91#,
      16#95#,
      16#E4#,
      16#79#,
      16#E7#,
      16#C8#,
      16#37#,
      16#6D#,
      16#8D#,
      16#D5#,
      16#4E#,
      16#A9#,
      16#6C#,
      16#56#,
      16#F4#,
      16#EA#,
      16#65#,
      16#7A#,
      16#AE#,
      16#08#,
      16#BA#,
      16#78#,
      16#25#,
      16#2E#,
      16#1C#,
      16#A6#,
      16#B4#,
      16#C6#,
      16#E8#,
      16#DD#,
      16#74#,
      16#1F#,
      16#4B#,
      16#BD#,
      16#8B#,
      16#8A#,
      16#70#,
      16#3E#,
      16#B5#,
      16#66#,
      16#48#,
      16#03#,
      16#F6#,
      16#0E#,
      16#61#,
      16#35#,
      16#57#,
      16#B9#,
      16#86#,
      16#C1#,
      16#1D#,
      16#9E#,
      16#E1#,
      16#F8#,
      16#98#,
      16#11#,
      16#69#,
      16#D9#,
      16#8E#,
      16#94#,
      16#9B#,
      16#1E#,
      16#87#,
      16#E9#,
      16#CE#,
      16#55#,
      16#28#,
      16#DF#,
      16#8C#,
      16#A1#,
      16#89#,
      16#0D#,
      16#BF#,
      16#E6#,
      16#42#,
      16#68#,
      16#41#,
      16#99#,
      16#2D#,
      16#0F#,
      16#B0#,
      16#54#,
      16#BB#,
      16#16#];

   Inv_S_Box : constant array (Octet) of Octet :=
     [16#52#,
      16#09#,
      16#6A#,
      16#D5#,
      16#30#,
      16#36#,
      16#A5#,
      16#38#,
      16#BF#,
      16#40#,
      16#A3#,
      16#9E#,
      16#81#,
      16#F3#,
      16#D7#,
      16#FB#,
      16#7C#,
      16#E3#,
      16#39#,
      16#82#,
      16#9B#,
      16#2F#,
      16#FF#,
      16#87#,
      16#34#,
      16#8E#,
      16#43#,
      16#44#,
      16#C4#,
      16#DE#,
      16#E9#,
      16#CB#,
      16#54#,
      16#7B#,
      16#94#,
      16#32#,
      16#A6#,
      16#C2#,
      16#23#,
      16#3D#,
      16#EE#,
      16#4C#,
      16#95#,
      16#0B#,
      16#42#,
      16#FA#,
      16#C3#,
      16#4E#,
      16#08#,
      16#2E#,
      16#A1#,
      16#66#,
      16#28#,
      16#D9#,
      16#24#,
      16#B2#,
      16#76#,
      16#5B#,
      16#A2#,
      16#49#,
      16#6D#,
      16#8B#,
      16#D1#,
      16#25#,
      16#72#,
      16#F8#,
      16#F6#,
      16#64#,
      16#86#,
      16#68#,
      16#98#,
      16#16#,
      16#D4#,
      16#A4#,
      16#5C#,
      16#CC#,
      16#5D#,
      16#65#,
      16#B6#,
      16#92#,
      16#6C#,
      16#70#,
      16#48#,
      16#50#,
      16#FD#,
      16#ED#,
      16#B9#,
      16#DA#,
      16#5E#,
      16#15#,
      16#46#,
      16#57#,
      16#A7#,
      16#8D#,
      16#9D#,
      16#84#,
      16#90#,
      16#D8#,
      16#AB#,
      16#00#,
      16#8C#,
      16#BC#,
      16#D3#,
      16#0A#,
      16#F7#,
      16#E4#,
      16#58#,
      16#05#,
      16#B8#,
      16#B3#,
      16#45#,
      16#06#,
      16#D0#,
      16#2C#,
      16#1E#,
      16#8F#,
      16#CA#,
      16#3F#,
      16#0F#,
      16#02#,
      16#C1#,
      16#AF#,
      16#BD#,
      16#03#,
      16#01#,
      16#13#,
      16#8A#,
      16#6B#,
      16#3A#,
      16#91#,
      16#11#,
      16#41#,
      16#4F#,
      16#67#,
      16#DC#,
      16#EA#,
      16#97#,
      16#F2#,
      16#CF#,
      16#CE#,
      16#F0#,
      16#B4#,
      16#E6#,
      16#73#,
      16#96#,
      16#AC#,
      16#74#,
      16#22#,
      16#E7#,
      16#AD#,
      16#35#,
      16#85#,
      16#E2#,
      16#F9#,
      16#37#,
      16#E8#,
      16#1C#,
      16#75#,
      16#DF#,
      16#6E#,
      16#47#,
      16#F1#,
      16#1A#,
      16#71#,
      16#1D#,
      16#29#,
      16#C5#,
      16#89#,
      16#6F#,
      16#B7#,
      16#62#,
      16#0E#,
      16#AA#,
      16#18#,
      16#BE#,
      16#1B#,
      16#FC#,
      16#56#,
      16#3E#,
      16#4B#,
      16#C6#,
      16#D2#,
      16#79#,
      16#20#,
      16#9A#,
      16#DB#,
      16#C0#,
      16#FE#,
      16#78#,
      16#CD#,
      16#5A#,
      16#F4#,
      16#1F#,
      16#DD#,
      16#A8#,
      16#33#,
      16#88#,
      16#07#,
      16#C7#,
      16#31#,
      16#B1#,
      16#12#,
      16#10#,
      16#59#,
      16#27#,
      16#80#,
      16#EC#,
      16#5F#,
      16#60#,
      16#51#,
      16#7F#,
      16#A9#,
      16#19#,
      16#B5#,
      16#4A#,
      16#0D#,
      16#2D#,
      16#E5#,
      16#7A#,
      16#9F#,
      16#93#,
      16#C9#,
      16#9C#,
      16#EF#,
      16#A0#,
      16#E0#,
      16#3B#,
      16#4D#,
      16#AE#,
      16#2A#,
      16#F5#,
      16#B0#,
      16#C8#,
      16#EB#,
      16#BB#,
      16#3C#,
      16#83#,
      16#53#,
      16#99#,
      16#61#,
      16#17#,
      16#2B#,
      16#04#,
      16#7E#,
      16#BA#,
      16#77#,
      16#D6#,
      16#26#,
      16#E1#,
      16#69#,
      16#14#,
      16#63#,
      16#55#,
      16#21#,
      16#0C#,
      16#7D#];

   function Sub_Byte (B : Octet) return Octet
   is (S_Box (B));

   function Inv_Sub_Byte (B : Octet) return Octet
   is (Inv_S_Box (B));

   function Spec_Xtime (B : Octet) return Octet
   is (if (B and 16#80#) /= 0
       then (Octet (Shift_Left (Unsigned_8 (B), 1))) xor 16#1B#
       else (Octet (Shift_Left (Unsigned_8 (B), 1))));

   function Mix_Col_Byte (A, B, C, D : Octet; Row : Natural) return Octet
   is (case Row is
         when 0      => Spec_Xtime (A) xor (Spec_Xtime (B) xor B) xor C xor D,
         when 1      => A xor Spec_Xtime (B) xor (Spec_Xtime (C) xor C) xor D,
         when 2      => A xor B xor Spec_Xtime (C) xor (Spec_Xtime (D) xor D),
         when 3      => (Spec_Xtime (A) xor A) xor B xor C xor Spec_Xtime (D),
         when others => 0);

   ---------------------------------------------------------------------
   --  GF(2^8) helpers — `xtime` doubles a byte modulo the AES
   --  reduction polynomial 0x11B (FIPS 197 §4.2). HACL\* uses
   --  Spec.GaloisField directly; the result is the same bit string.
   ---------------------------------------------------------------------

   function Xtime (B : Octet) return Octet
   is (if (B and 16#80#) /= 0
       then (Octet (Shift_Left (Unsigned_8 (B), 1))) xor 16#1B#
       else (Octet (Shift_Left (Unsigned_8 (B), 1))));

   --  GF(2^8) multiplication. Used in Inv_Mix_Columns where the
   --  column matrix has entries 0x09, 0x0B, 0x0D, 0x0E. We expand
   --  these as fixed XOR-of-Xtime chains rather than a generic loop
   --  to keep the body literal and obvious.

   function Mul02 (B : Octet) return Octet
   is (Xtime (B));

   function Mul04 (B : Octet) return Octet
   is (Xtime (Xtime (B)));

   function Mul08 (B : Octet) return Octet
   is (Xtime (Xtime (Xtime (B))));

   --  9 = 8 ⊕ 1
   function Mul09 (B : Octet) return Octet
   is (Mul08 (B) xor B);

   --  11 (0x0B) = 8 ⊕ 2 ⊕ 1
   function Mul0B (B : Octet) return Octet
   is (Mul08 (B) xor Mul02 (B) xor B);

   --  13 (0x0D) = 8 ⊕ 4 ⊕ 1
   function Mul0D (B : Octet) return Octet
   is (Mul08 (B) xor Mul04 (B) xor B);

   --  14 (0x0E) = 8 ⊕ 4 ⊕ 2
   function Mul0E (B : Octet) return Octet
   is (Mul08 (B) xor Mul04 (B) xor Mul02 (B));

   ---------------------------------------------------------------------
   --  Sub_Bytes / Inv_Sub_Bytes — HACL\* `subBytes` (line 67) and
   --  `inv_subBytes` (line 70).
   ---------------------------------------------------------------------

   function Sub_Bytes (S : Block_16) return Block_16 is
      Out_S : Block_16 := S;
   begin
      for I in Block_16'Range loop
         Out_S (I) := S_Box (S (I));
      end loop;
      return Out_S;
   end Sub_Bytes;

   function Inv_Sub_Bytes (S : Block_16) return Block_16 is
      Out_S : Block_16 := S;
   begin
      for I in Block_16'Range loop
         Out_S (I) := Inv_S_Box (S (I));
      end loop;
      return Out_S;
   end Inv_Sub_Bytes;

   ---------------------------------------------------------------------
   --  Shift_Rows / Inv_Shift_Rows — HACL\* `shiftRow` (line 73) +
   --  `shiftRows` (line 84) / `inv_shiftRows` (line 90). State is
   --  laid out so row r ∈ {0..3} occupies indices {r+1, r+5, r+9,
   --  r+13} in our 1-based convention (= zero-based {r, r+4, r+8,
   --  r+12} in HACL\*).
   --
   --  Forward shift-by-`shift`: row[c] := row[(c + shift) mod 4].
   --  Reverse: row[c] := row[(c - shift) mod 4] = row[(c + (4 -
   --  shift)) mod 4].
   ---------------------------------------------------------------------

   --  Internal helper — apply Shift_Row(i, shift) per HACL\* line 73.
   --
   --  Post: in row I (= state indices I+1, I+5, I+9, I+13), each
   --  output byte at column C in 0..3 reads from input column
   --  (C + Shift) mod 4 of the same row.  Other rows are unchanged.
   --  The "other rows unchanged" clause is expressed as: every
   --  output index whose row /= I keeps the input value.
   function Shift_Row
     (I : Natural; Shift : Natural; S : Block_16) return Block_16
   with
     Pre  => I in 1 .. 3 and then Shift in 1 .. 3,
     Post =>
       (for all C in 0 .. 3 =>
          Shift_Row'Result (I + 1 + 4 * C)
          = S (I + 1 + 4 * ((C + Shift) mod 4)))
       and then (for all J in Block_16'Range =>
                   (if (J - 1) mod 4 /= I then Shift_Row'Result (J) = S (J)));

   function Shift_Row
     (I : Natural; Shift : Natural; S : Block_16) return Block_16
   is
      Out_S : Block_16 := S;
      --  Read the four bytes of row I in shifted column order.
      Tmp0  : constant Octet := S (I + 1 + 4 * (Shift mod 4));
      Tmp1  : constant Octet := S (I + 1 + 4 * ((Shift + 1) mod 4));
      Tmp2  : constant Octet := S (I + 1 + 4 * ((Shift + 2) mod 4));
      Tmp3  : constant Octet := S (I + 1 + 4 * ((Shift + 3) mod 4));
   begin
      Out_S (I + 1) := Tmp0;
      Out_S (I + 1 + 4) := Tmp1;
      Out_S (I + 1 + 8) := Tmp2;
      Out_S (I + 1 + 12) := Tmp3;
      pragma Assert (Out_S (I + 1) = S (I + 1 + 4 * (Shift mod 4)));
      pragma Assert (Out_S (I + 1 + 4) = S (I + 1 + 4 * ((Shift + 1) mod 4)));
      pragma Assert (Out_S (I + 1 + 8) = S (I + 1 + 4 * ((Shift + 2) mod 4)));
      pragma Assert (Out_S (I + 1 + 12) = S (I + 1 + 4 * ((Shift + 3) mod 4)));
      return Out_S;
   end Shift_Row;

   function Shift_Rows (S : Block_16) return Block_16 is
      T1, T2, T : Block_16;
   begin
      T1 := Shift_Row (1, 1, S);
      --  T1: row 1 shifted, rows 0/2/3 still equal S.
      pragma
        Assert
          (for all C in 0 .. 3 =>
             T1 (1 + 1 + 4 * C) = S (1 + 1 + 4 * ((C + 1) mod 4)));
      pragma
        Assert
          (for all C in 0 .. 3 =>
             T1 (4 * C + 1) = S (4 * C + 1));      --  row 0 untouched
      pragma
        Assert
          (for all C in 0 .. 3 =>
             T1 (4 * C + 3) = S (4 * C + 3));      --  row 2 untouched
      pragma
        Assert
          (for all C in 0 .. 3 =>
             T1 (4 * C + 4) = S (4 * C + 4));      --  row 3 untouched

      T2 := Shift_Row (2, 2, T1);
      --  T2: row 2 shifted relative to T1 (which has row 2 = S row 2).
      pragma
        Assert
          (for all C in 0 .. 3 =>
             T2 (4 * C + 1) = S (4 * C + 1));      --  row 0 untouched
      pragma
        Assert
          (for all C in 0 .. 3 =>
             T2 (1 + 1 + 4 * C) = S (1 + 1 + 4 * ((C + 1) mod 4)));
      pragma
        Assert
          (for all C in 0 .. 3 =>
             T2 (2 + 1 + 4 * C) = S (2 + 1 + 4 * ((C + 2) mod 4)));
      pragma
        Assert
          (for all C in 0 .. 3 =>
             T2 (4 * C + 4) = S (4 * C + 4));      --  row 3 untouched

      T := Shift_Row (3, 3, T2);

      --  Stage the unified Post expression by separately asserting
      --  each row, then conjoining.  The single quantifier over both
      --  C and R confuses the prover; per-row quantifiers do not.
      pragma
        Assert
          (for all C in 0 .. 3 =>
             T (4 * C + 1) = S (4 * ((C + 0) mod 4) + 0 + 1));  --  row 0
      pragma
        Assert
          (for all C in 0 .. 3 =>
             T (4 * C + 2)
             = S (4 * ((C + 1) mod 4) + 1 + 1));               --  row 1
      pragma
        Assert
          (for all C in 0 .. 3 =>
             T (4 * C + 3)
             = S (4 * ((C + 2) mod 4) + 2 + 1));               --  row 2
      pragma
        Assert
          (for all C in 0 .. 3 =>
             T (4 * C + 4)
             = S (4 * ((C + 3) mod 4) + 3 + 1));               --  row 3

      --  Chain the four per-row asserts into the unified
      --  for-all-C-and-R form.  SPARK's SMT backend does not
      --  combine universal quantifiers from separate hypotheses
      --  by default, so we manually instantiate at each (C, R).
      for C in 0 .. 3 loop
         pragma Assert (T (4 * C + 0 + 1) = S (4 * ((C + 0) mod 4) + 0 + 1));
         pragma Assert (T (4 * C + 1 + 1) = S (4 * ((C + 1) mod 4) + 1 + 1));
         pragma Assert (T (4 * C + 2 + 1) = S (4 * ((C + 2) mod 4) + 2 + 1));
         pragma Assert (T (4 * C + 3 + 1) = S (4 * ((C + 3) mod 4) + 3 + 1));
         pragma
           Assert
             (for all R in 0 .. 3 =>
                T (4 * C + R + 1) = S (4 * ((C + R) mod 4) + R + 1));
         pragma
           Loop_Invariant
             (for all C2 in 0 .. C =>
                (for all R in 0 .. 3 =>
                   T (4 * C2 + R + 1) = S (4 * ((C2 + R) mod 4) + R + 1)));
      end loop;

      pragma
        Assert
          (for all C in 0 .. 3 =>
             (for all R in 0 .. 3 =>
                T (4 * C + R + 1) = S (4 * ((C + R) mod 4) + R + 1)));
      return T;
   end Shift_Rows;

   function Inv_Shift_Rows (S : Block_16) return Block_16 is
      T : Block_16;
   begin
      T := Shift_Row (1, 3, S);
      T := Shift_Row (2, 2, T);
      T := Shift_Row (3, 1, T);
      return T;
   end Inv_Shift_Rows;

   ---------------------------------------------------------------------
   --  Mix_Columns / Inv_Mix_Columns — HACL\* `mixColumn` /
   --  `mixColumns` (lines 113-130) and the inverse counterparts
   --  (lines 132-149).
   --
   --  HACL\* `mix4 s0 s1 s2 s3 = 2*s0 + 3*s1 + s2 + s3`.
   --  Per FIPS 197 §5.1.3 the i-th output of column j is the i-th
   --  row of the {02 03 01 01} circulant matrix · column.
   ---------------------------------------------------------------------

   --  Mix4 (s0, s1, s2, s3) is the row-0 byte of the column matrix
   --  multiply per HACL\* `mix4` (Spec.AES.fst:113).  Other rows of
   --  the same column are obtained by rotating the inputs:
   --    row r of column = Mix4 (s_r, s_(r+1), s_(r+2), s_(r+3))
   --  Implemented as Mix_Col_Byte at row 0 — same value.
   function Mix4 (S0, S1, S2, S3 : Octet) return Octet
   is (Mix_Col_Byte (S0, S1, S2, S3, 0));

   --  Inv_Mix4 — HACL\* `inv_mix4` (line 101).
   --  14*s0 + 11*s1 + 13*s2 + 9*s3 (FIPS 197 §5.3.3).
   function Inv_Mix4 (S0, S1, S2, S3 : Octet) return Octet
   is (Mul0E (S0) xor Mul0B (S1) xor Mul0D (S2) xor Mul09 (S3));

   function Mix_Columns (S : Block_16) return Block_16 is
      Out_S          : Block_16 := S;
      S0, S1, S2, S3 : Octet;
   begin
      for Col in 0 .. 3 loop
         S0 := Out_S (4 * Col + 1);
         S1 := Out_S (4 * Col + 2);
         S2 := Out_S (4 * Col + 3);
         S3 := Out_S (4 * Col + 4);
         pragma Assert (S0 = S (4 * Col + 1));
         pragma Assert (S1 = S (4 * Col + 2));
         pragma Assert (S2 = S (4 * Col + 3));
         pragma Assert (S3 = S (4 * Col + 4));
         Out_S (4 * Col + 1) := Mix4 (S0, S1, S2, S3);
         Out_S (4 * Col + 2) := Mix4 (S1, S2, S3, S0);
         Out_S (4 * Col + 3) := Mix4 (S2, S3, S0, S1);
         Out_S (4 * Col + 4) := Mix4 (S3, S0, S1, S2);

         --  Match each Mix4 expression to the corresponding
         --  Mix_Col_Byte (s0, s1, s2, s3, R).  XOR is commutative,
         --  so Mix4 (a, b, c, d) (which is row 0 over (a, b, c, d))
         --  equals Mix_Col_Byte over (s0, s1, s2, s3) at the
         --  appropriate rotated row.
         pragma
           Assert (Mix4 (S0, S1, S2, S3) = Mix_Col_Byte (S0, S1, S2, S3, 0));
         pragma
           Assert (Mix4 (S1, S2, S3, S0) = Mix_Col_Byte (S0, S1, S2, S3, 1));
         pragma
           Assert (Mix4 (S2, S3, S0, S1) = Mix_Col_Byte (S0, S1, S2, S3, 2));
         pragma
           Assert (Mix4 (S3, S0, S1, S2) = Mix_Col_Byte (S0, S1, S2, S3, 3));

         pragma
           Loop_Invariant
             (for all K in 0 .. Col =>
                Out_S (4 * K + 1)
                = Mix_Col_Byte
                    (S (4 * K + 1),
                     S (4 * K + 2),
                     S (4 * K + 3),
                     S (4 * K + 4),
                     0)
                and then Out_S (4 * K + 2)
                         = Mix_Col_Byte
                             (S (4 * K + 1),
                              S (4 * K + 2),
                              S (4 * K + 3),
                              S (4 * K + 4),
                              1)
                and then Out_S (4 * K + 3)
                         = Mix_Col_Byte
                             (S (4 * K + 1),
                              S (4 * K + 2),
                              S (4 * K + 3),
                              S (4 * K + 4),
                              2)
                and then Out_S (4 * K + 4)
                         = Mix_Col_Byte
                             (S (4 * K + 1),
                              S (4 * K + 2),
                              S (4 * K + 3),
                              S (4 * K + 4),
                              3));
         pragma
           Loop_Invariant
             (for all K in Col + 1 .. 3 =>
                Out_S (4 * K + 1) = S (4 * K + 1)
                and then Out_S (4 * K + 2) = S (4 * K + 2)
                and then Out_S (4 * K + 3) = S (4 * K + 3)
                and then Out_S (4 * K + 4) = S (4 * K + 4));
      end loop;
      return Out_S;
   end Mix_Columns;

   function Inv_Mix_Columns (S : Block_16) return Block_16 is
      Out_S          : Block_16 := S;
      S0, S1, S2, S3 : Octet;
   begin
      for Col in 0 .. 3 loop
         S0 := Out_S (4 * Col + 1);
         S1 := Out_S (4 * Col + 2);
         S2 := Out_S (4 * Col + 3);
         S3 := Out_S (4 * Col + 4);
         Out_S (4 * Col + 1) := Inv_Mix4 (S0, S1, S2, S3);
         Out_S (4 * Col + 2) := Inv_Mix4 (S1, S2, S3, S0);
         Out_S (4 * Col + 3) := Inv_Mix4 (S2, S3, S0, S1);
         Out_S (4 * Col + 4) := Inv_Mix4 (S3, S0, S1, S2);
      end loop;
      return Out_S;
   end Inv_Mix_Columns;

   ---------------------------------------------------------------------
   --  Add_Round_Key — HACL\* `addRoundKey` (line 154).
   ---------------------------------------------------------------------

   function Add_Round_Key (Key : Block_16; State : Block_16) return Block_16 is
      Out_S : Block_16 := State;
   begin
      for I in Block_16'Range loop
         Out_S (I) := State (I) xor Key (I);
      end loop;
      return Out_S;
   end Add_Round_Key;

   ---------------------------------------------------------------------
   --  Round drivers — HACL\* aes_enc / aes_enc_last / aes_dec /
   --  aes_dec_last.
   ---------------------------------------------------------------------

   function Aes_Enc (Key : Block_16; State : Block_16) return Block_16 is
      T : Block_16 := State;
   begin
      T := Sub_Bytes (T);
      T := Shift_Rows (T);
      T := Mix_Columns (T);
      T := Add_Round_Key (Key, T);
      return T;
   end Aes_Enc;

   function Aes_Enc_Last (Key : Block_16; State : Block_16) return Block_16 is
      T : Block_16 := State;
   begin
      T := Sub_Bytes (T);
      T := Shift_Rows (T);
      T := Add_Round_Key (Key, T);
      return T;
   end Aes_Enc_Last;

   --  Aes_Dec — per FIPS 197 §5.3 InvCipher (direct form).  The
   --  middle decryption rounds are InvSubBytes → InvShiftRows →
   --  AddRoundKey → InvMixColumns, with round keys consumed in
   --  reverse order of the encryption schedule.  HACL\*'s `aes_dec`
   --  (Spec.AES.fst:170) describes the *EquivalentInvCipher* variant
   --  that requires an inv-mixed dec-key-expansion (`aes_dec_key_
   --  expansion`, line 289); we choose the direct form so the
   --  public Aes128.Decrypt_Block / Aes256.Decrypt_Block can take
   --  the same round-key array produced by Expand_Key.  Both
   --  variants compute the inverse of Cipher; FIPS 197 §5.3 proves
   --  the equivalence.
   function Aes_Dec (Key : Block_16; State : Block_16) return Block_16 is
      T : Block_16 := State;
   begin
      T := Inv_Sub_Bytes (T);
      T := Inv_Shift_Rows (T);
      T := Add_Round_Key (Key, T);
      T := Inv_Mix_Columns (T);
      return T;
   end Aes_Dec;

   function Aes_Dec_Last (Key : Block_16; State : Block_16) return Block_16 is
      T : Block_16 := State;
   begin
      T := Inv_Sub_Bytes (T);
      T := Inv_Shift_Rows (T);
      T := Add_Round_Key (Key, T);
      return T;
   end Aes_Dec_Last;

   ---------------------------------------------------------------------
   --  Slice helpers — extract the 16-byte round key at index R from
   --  the expanded key array.  R is the round number (0..Nr).
   ---------------------------------------------------------------------

   function Round_Key (Xkey : Octet_Array; Round : Natural) return Block_16
   with
     Pre =>
       Xkey'First = 1
       and then Round <= 14
       and then Round * 16 + 16 <= Xkey'Length;

   function Round_Key (Xkey : Octet_Array; Round : Natural) return Block_16 is
      Out_K : Block_16;
   begin
      for I in Block_16'Range loop
         Out_K (I) := Xkey (Round * 16 + I);
      end loop;
      return Out_K;
   end Round_Key;

   ---------------------------------------------------------------------
   --  Encrypt / Decrypt — HACL\* `aes_encrypt_block` (Spec.AES.fst:306)
   --  and `aes_decrypt_block` (line 319), specialised to AES128 (10
   --  rounds) and AES256 (14 rounds).
   ---------------------------------------------------------------------

   function Aes128_Encrypt_Block
     (Input : Block_16; Xkey : Aes128_Xkey) return Block_16
   is
      State : Block_16 := Input;
   begin
      State := Add_Round_Key (Round_Key (Xkey, 0), State);
      for R in 1 .. 9 loop
         State := Aes_Enc (Round_Key (Xkey, R), State);
      end loop;
      State := Aes_Enc_Last (Round_Key (Xkey, 10), State);
      return State;
   end Aes128_Encrypt_Block;

   function Aes128_Decrypt_Block
     (Input : Block_16; Xkey : Aes128_Xkey) return Block_16
   is
      State : Block_16 := Input;
   begin
      --  Decrypt iterates round keys in reverse order; per HACL\*
      --  `aes_dec_rounds` (line 316) and `aes_decrypt_block`
      --  (line 319) the per-round op is `aes_dec` (the *direct*
      --  inverse cipher form, FIPS 197 §5.3 / Figure 12).
      State := Add_Round_Key (Round_Key (Xkey, 10), State);
      for R in reverse 1 .. 9 loop
         State := Aes_Dec (Round_Key (Xkey, R), State);
      end loop;
      State := Aes_Dec_Last (Round_Key (Xkey, 0), State);
      return State;
   end Aes128_Decrypt_Block;

   function Aes256_Encrypt_Block
     (Input : Block_16; Xkey : Aes256_Xkey) return Block_16
   is
      State : Block_16 := Input;
   begin
      State := Add_Round_Key (Round_Key (Xkey, 0), State);
      for R in 1 .. 13 loop
         State := Aes_Enc (Round_Key (Xkey, R), State);
      end loop;
      State := Aes_Enc_Last (Round_Key (Xkey, 14), State);
      return State;
   end Aes256_Encrypt_Block;

   function Aes256_Decrypt_Block
     (Input : Block_16; Xkey : Aes256_Xkey) return Block_16
   is
      State : Block_16 := Input;
   begin
      State := Add_Round_Key (Round_Key (Xkey, 14), State);
      for R in reverse 1 .. 13 loop
         State := Aes_Dec (Round_Key (Xkey, R), State);
      end loop;
      State := Aes_Dec_Last (Round_Key (Xkey, 0), State);
      return State;
   end Aes256_Decrypt_Block;

   ---------------------------------------------------------------------
   --  Key expansion.  We mirror the *result* of HACL\*'s
   --  aes128_key_expansion / aes256_key_expansion (Spec.AES.fst:250 /
   --  263) — the FIPS 197 §5.2 KeyExpansion algorithm.  HACL\*'s
   --  formulation routes through `aes_keygen_assist` /
   --  `key_expansion_step` because that lines up with the AES-NI
   --  AESKEYGENASSIST instruction's data shape; FIPS 197 expresses
   --  the same expansion as a per-word recurrence.  We use the
   --  per-word form here — it is shorter, more obviously matches
   --  FIPS 197, and produces the same byte sequence (cross-checked
   --  against FIPS 197 §A.1 / §A.3 and §C.* worked examples in
   --  tls_core_tests scenarios 31 and 34).
   --
   --  Justification: HACL\* spec line 250-261 expansion = byte-exact
   --  to FIPS 197 §A.1 round-key tables = byte-exact to the §C.1
   --  reference ciphertext via Aes128_Encrypt_Block. We test the
   --  composition (Expand_Key + Encrypt_Block) against the §C.1 /
   --  §C.3 vectors; if any byte of the expansion were off, the
   --  ciphertext would not match.
   ---------------------------------------------------------------------

   --  Rcon[1..10] — FIPS 197 §5.2.  Same table as in Aes_Core.
   --  Index 0 is unused (HACL spec line 191 uses 0x8d there as a
   --  base-of-recursion — never indexed in the expansion path).
   Rcon : constant array (1 .. 10) of Octet :=
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

   function Aes128_Key_Expansion (Key : Aes128_Key) return Aes128_Xkey is
      Out_K                      : Aes128_Xkey := [others => 0];
      Temp0, Temp1, Temp2, Temp3 : Octet;
      Tmp_T                      : Octet;
   begin
      --  Words 0..3 = original key.
      for I in 1 .. 16 loop
         Out_K (I) := Key (I);
      end loop;
      --  Word index I in 4..43 — each word is 4 bytes.
      for I in 4 .. 43 loop
         Temp0 := Out_K (4 * (I - 1) + 1);
         Temp1 := Out_K (4 * (I - 1) + 2);
         Temp2 := Out_K (4 * (I - 1) + 3);
         Temp3 := Out_K (4 * (I - 1) + 4);
         if I mod 4 = 0 then
            --  RotWord: cyclic shift left by 1 byte.
            Tmp_T := Temp0;
            Temp0 := Temp1;
            Temp1 := Temp2;
            Temp2 := Temp3;
            Temp3 := Tmp_T;
            --  SubWord: byte-wise S-box.
            Temp0 := S_Box (Temp0);
            Temp1 := S_Box (Temp1);
            Temp2 := S_Box (Temp2);
            Temp3 := S_Box (Temp3);
            --  XOR Rcon[i/4] into the high byte.
            Temp0 := Temp0 xor Rcon (I / 4);
         end if;
         Out_K (4 * I + 1) := Out_K (4 * (I - 4) + 1) xor Temp0;
         Out_K (4 * I + 2) := Out_K (4 * (I - 4) + 2) xor Temp1;
         Out_K (4 * I + 3) := Out_K (4 * (I - 4) + 3) xor Temp2;
         Out_K (4 * I + 4) := Out_K (4 * (I - 4) + 4) xor Temp3;
      end loop;
      return Out_K;
   end Aes128_Key_Expansion;

   function Aes256_Key_Expansion (Key : Aes256_Key) return Aes256_Xkey is
      Out_K                      : Aes256_Xkey := [others => 0];
      Temp0, Temp1, Temp2, Temp3 : Octet;
      Tmp_T                      : Octet;
   begin
      for I in 1 .. 32 loop
         Out_K (I) := Key (I);
      end loop;
      --  Nk = 8, Nr = 14.  Word index I in 8..59.
      for I in 8 .. 59 loop
         Temp0 := Out_K (4 * (I - 1) + 1);
         Temp1 := Out_K (4 * (I - 1) + 2);
         Temp2 := Out_K (4 * (I - 1) + 3);
         Temp3 := Out_K (4 * (I - 1) + 4);
         if I mod 8 = 0 then
            Tmp_T := Temp0;
            Temp0 := Temp1;
            Temp1 := Temp2;
            Temp2 := Temp3;
            Temp3 := Tmp_T;
            Temp0 := S_Box (Temp0);
            Temp1 := S_Box (Temp1);
            Temp2 := S_Box (Temp2);
            Temp3 := S_Box (Temp3);
            Temp0 := Temp0 xor Rcon (I / 8);
         elsif I mod 8 = 4 then
            Temp0 := S_Box (Temp0);
            Temp1 := S_Box (Temp1);
            Temp2 := S_Box (Temp2);
            Temp3 := S_Box (Temp3);
         end if;
         Out_K (4 * I + 1) := Out_K (4 * (I - 8) + 1) xor Temp0;
         Out_K (4 * I + 2) := Out_K (4 * (I - 8) + 2) xor Temp1;
         Out_K (4 * I + 3) := Out_K (4 * (I - 8) + 3) xor Temp2;
         Out_K (4 * I + 4) := Out_K (4 * (I - 8) + 4) xor Temp3;
      end loop;
      return Out_K;
   end Aes256_Key_Expansion;

end Tls_Core.Aes_Spec;
