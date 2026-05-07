with Interfaces;
with Tls_Core_Config;

package body Tls_Core.Aes_Core
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;
   use type Tls_Core.Octet;

   ---------------------------------------------------------------------
   --  S-box (FIPS 197 §5.1.1, Figure 7).
   ---------------------------------------------------------------------

   S_Box : constant array (Octet) of Octet :=
     (16#63#, 16#7C#, 16#77#, 16#7B#, 16#F2#, 16#6B#, 16#6F#, 16#C5#,
      16#30#, 16#01#, 16#67#, 16#2B#, 16#FE#, 16#D7#, 16#AB#, 16#76#,
      16#CA#, 16#82#, 16#C9#, 16#7D#, 16#FA#, 16#59#, 16#47#, 16#F0#,
      16#AD#, 16#D4#, 16#A2#, 16#AF#, 16#9C#, 16#A4#, 16#72#, 16#C0#,
      16#B7#, 16#FD#, 16#93#, 16#26#, 16#36#, 16#3F#, 16#F7#, 16#CC#,
      16#34#, 16#A5#, 16#E5#, 16#F1#, 16#71#, 16#D8#, 16#31#, 16#15#,
      16#04#, 16#C7#, 16#23#, 16#C3#, 16#18#, 16#96#, 16#05#, 16#9A#,
      16#07#, 16#12#, 16#80#, 16#E2#, 16#EB#, 16#27#, 16#B2#, 16#75#,
      16#09#, 16#83#, 16#2C#, 16#1A#, 16#1B#, 16#6E#, 16#5A#, 16#A0#,
      16#52#, 16#3B#, 16#D6#, 16#B3#, 16#29#, 16#E3#, 16#2F#, 16#84#,
      16#53#, 16#D1#, 16#00#, 16#ED#, 16#20#, 16#FC#, 16#B1#, 16#5B#,
      16#6A#, 16#CB#, 16#BE#, 16#39#, 16#4A#, 16#4C#, 16#58#, 16#CF#,
      16#D0#, 16#EF#, 16#AA#, 16#FB#, 16#43#, 16#4D#, 16#33#, 16#85#,
      16#45#, 16#F9#, 16#02#, 16#7F#, 16#50#, 16#3C#, 16#9F#, 16#A8#,
      16#51#, 16#A3#, 16#40#, 16#8F#, 16#92#, 16#9D#, 16#38#, 16#F5#,
      16#BC#, 16#B6#, 16#DA#, 16#21#, 16#10#, 16#FF#, 16#F3#, 16#D2#,
      16#CD#, 16#0C#, 16#13#, 16#EC#, 16#5F#, 16#97#, 16#44#, 16#17#,
      16#C4#, 16#A7#, 16#7E#, 16#3D#, 16#64#, 16#5D#, 16#19#, 16#73#,
      16#60#, 16#81#, 16#4F#, 16#DC#, 16#22#, 16#2A#, 16#90#, 16#88#,
      16#46#, 16#EE#, 16#B8#, 16#14#, 16#DE#, 16#5E#, 16#0B#, 16#DB#,
      16#E0#, 16#32#, 16#3A#, 16#0A#, 16#49#, 16#06#, 16#24#, 16#5C#,
      16#C2#, 16#D3#, 16#AC#, 16#62#, 16#91#, 16#95#, 16#E4#, 16#79#,
      16#E7#, 16#C8#, 16#37#, 16#6D#, 16#8D#, 16#D5#, 16#4E#, 16#A9#,
      16#6C#, 16#56#, 16#F4#, 16#EA#, 16#65#, 16#7A#, 16#AE#, 16#08#,
      16#BA#, 16#78#, 16#25#, 16#2E#, 16#1C#, 16#A6#, 16#B4#, 16#C6#,
      16#E8#, 16#DD#, 16#74#, 16#1F#, 16#4B#, 16#BD#, 16#8B#, 16#8A#,
      16#70#, 16#3E#, 16#B5#, 16#66#, 16#48#, 16#03#, 16#F6#, 16#0E#,
      16#61#, 16#35#, 16#57#, 16#B9#, 16#86#, 16#C1#, 16#1D#, 16#9E#,
      16#E1#, 16#F8#, 16#98#, 16#11#, 16#69#, 16#D9#, 16#8E#, 16#94#,
      16#9B#, 16#1E#, 16#87#, 16#E9#, 16#CE#, 16#55#, 16#28#, 16#DF#,
      16#8C#, 16#A1#, 16#89#, 16#0D#, 16#BF#, 16#E6#, 16#42#, 16#68#,
      16#41#, 16#99#, 16#2D#, 16#0F#, 16#B0#, 16#54#, 16#BB#, 16#16#);

   function Sub_Byte (B : Octet) return Octet is (S_Box (B));

   function Xtime (B : Octet) return Octet
   is
     (if (B and 16#80#) /= 0
        then (Octet (Shift_Left (Unsigned_8 (B), 1))) xor 16#1B#
        else (Octet (Shift_Left (Unsigned_8 (B), 1))));

   ---------------------------------------------------------------------
   --  Sub_Bytes
   ---------------------------------------------------------------------

   procedure Sub_Bytes (S : in out Block) is
   begin
      for I in 1 .. 16 loop
         S (I) := S_Box (S (I));
      end loop;
   end Sub_Bytes;

   ---------------------------------------------------------------------
   --  Shift_Rows — rows in column-major state layout:
   --     row 0 lives at indices 1, 5, 9, 13   (no shift)
   --     row 1 lives at indices 2, 6, 10, 14  (shift left 1)
   --     row 2 lives at indices 3, 7, 11, 15  (shift left 2)
   --     row 3 lives at indices 4, 8, 12, 16  (shift left 3 = right 1)
   ---------------------------------------------------------------------

   procedure Shift_Rows (S : in out Block) is
      T : Octet;
   begin
      --  Row 1: rotate left 1.
      T := S (2);
      S (2)  := S (6);
      S (6)  := S (10);
      S (10) := S (14);
      S (14) := T;
      --  Row 2: rotate left 2.
      T := S (3);
      S (3)  := S (11);
      S (11) := T;
      T := S (7);
      S (7)  := S (15);
      S (15) := T;
      --  Row 3: rotate left 3 = right 1.
      T := S (16);
      S (16) := S (12);
      S (12) := S (8);
      S (8)  := S (4);
      S (4)  := T;
   end Shift_Rows;

   ---------------------------------------------------------------------
   --  Mix_Columns — per FIPS 197 §5.1.3 column matrix multiply.
   ---------------------------------------------------------------------

   procedure Mix_Columns (S : in out Block) is
      A, B, C, D, T : Octet;
   begin
      for Col in 0 .. 3 loop
         A := S (4 * Col + 1);
         B := S (4 * Col + 2);
         C := S (4 * Col + 3);
         D := S (4 * Col + 4);
         T := A xor B xor C xor D;
         S (4 * Col + 1) := S (4 * Col + 1) xor T xor Xtime (A xor B);
         S (4 * Col + 2) := S (4 * Col + 2) xor T xor Xtime (B xor C);
         S (4 * Col + 3) := S (4 * Col + 3) xor T xor Xtime (C xor D);
         S (4 * Col + 4) := S (4 * Col + 4) xor T xor Xtime (D xor A);
      end loop;
   end Mix_Columns;

   ---------------------------------------------------------------------
   --  Add_Round_Key
   ---------------------------------------------------------------------

   procedure Add_Round_Key
     (S     : in out Block;
      RK    : Octet_Array;
      Round : Natural)
   is
   begin
      for I in 1 .. 16 loop
         S (I) := S (I) xor RK (Round * 16 + I);
      end loop;
   end Add_Round_Key;

   ---------------------------------------------------------------------
   --  Full_Round + Final_Round — composed entries that the
   --  per-AES-variant Encrypt_Block calls.
   ---------------------------------------------------------------------

   ---------------------------------------------------------------------
   --  T-tables (FIPS 197 round transformation as 4 lookup tables).
   --
   --  Each table maps an input byte to a 32-bit word that pre-applies
   --  SubBytes ∘ ShiftRows ∘ MixColumns to one column of the state.
   --  XORing the four T-table outputs at column j of every round
   --  produces the output column. Elaboration-time computed: the
   --  body's loop runs once at program start and the resulting
   --  constants live in .rodata.
   --
   --  Memory cost: 4 × 256 × 4 bytes = 4 KB. Opt out via
   --  Tls_Core_Config.T_Tables_Enabled = False — Full_Round then
   --  uses the byte-by-byte path (Sub_Bytes / Shift_Rows /
   --  Mix_Columns) which has no extra memory cost.
   --
   --  The tables encode SubBytes ∘ ShiftRows ∘ MixColumns relative
   --  to a column-major state layout (index 0 of T0 is the column-
   --  major byte that ends up in row 0 of the output column, etc.).
   ---------------------------------------------------------------------

   type Tab32 is array (Octet) of Unsigned_32;

   function Pack32 (B0, B1, B2, B3 : Octet) return Unsigned_32
   is
     (Shift_Left (Unsigned_32 (B0), 24)
      or Shift_Left (Unsigned_32 (B1), 16)
      or Shift_Left (Unsigned_32 (B2),  8)
      or            Unsigned_32 (B3));

   function Compute_T0 return Tab32 is
      T  : Tab32 := (others => 0);
      S  : Octet;
      S2 : Octet;
      S3 : Octet;
   begin
      for I in Octet'Range loop
         S  := S_Box (I);
         S2 := Xtime (S);
         S3 := S2 xor S;
         --  Column [S2, S, S, S3] — row 0 multiplier is 02 in MixColumns.
         T (I) := Pack32 (S2, S, S, S3);
      end loop;
      return T;
   end Compute_T0;

   function Compute_T1 return Tab32 is
      T  : Tab32 := (others => 0);
      S  : Octet;
      S2 : Octet;
      S3 : Octet;
   begin
      for I in Octet'Range loop
         S  := S_Box (I);
         S2 := Xtime (S);
         S3 := S2 xor S;
         T (I) := Pack32 (S3, S2, S, S);
      end loop;
      return T;
   end Compute_T1;

   function Compute_T2 return Tab32 is
      T  : Tab32 := (others => 0);
      S  : Octet;
      S2 : Octet;
      S3 : Octet;
   begin
      for I in Octet'Range loop
         S  := S_Box (I);
         S2 := Xtime (S);
         S3 := S2 xor S;
         T (I) := Pack32 (S, S3, S2, S);
      end loop;
      return T;
   end Compute_T2;

   function Compute_T3 return Tab32 is
      T  : Tab32 := (others => 0);
      S  : Octet;
      S2 : Octet;
      S3 : Octet;
   begin
      for I in Octet'Range loop
         S  := S_Box (I);
         S2 := Xtime (S);
         S3 := S2 xor S;
         T (I) := Pack32 (S, S, S3, S2);
      end loop;
      return T;
   end Compute_T3;

   T0 : constant Tab32 := Compute_T0;
   T1 : constant Tab32 := Compute_T1;
   T2 : constant Tab32 := Compute_T2;
   T3 : constant Tab32 := Compute_T3;

   procedure Full_Round_T_Tables
     (S     : in out Block;
      RK    : Octet_Array;
      Round : Natural)
   with Pre  => RK'First = 1
                and then Round * 16 + 16 <= RK'Length;
   procedure Full_Round_T_Tables
     (S     : in out Block;
      RK    : Octet_Array;
      Round : Natural)
   is
      C0, C1, C2, C3 : Unsigned_32;
      RK_Off : constant Natural := Round * 16;
   begin
      --  Each output column = T0[s_row0_byte] XOR T1[s_row1_byte]
      --  XOR T2[s_row2_byte] XOR T3[s_row3_byte] XOR round_key_col.
      --  In column-major state at indices 4j+1..4j+4, ShiftRows means
      --  row 0 stays at column j, row 1 comes from column j+1, row 2
      --  from j+2, row 3 from j+3 (mod 4).
      C0 := T0 (S (1)) xor T1 (S (6))  xor T2 (S (11)) xor T3 (S (16));
      C1 := T0 (S (5)) xor T1 (S (10)) xor T2 (S (15)) xor T3 (S (4));
      C2 := T0 (S (9)) xor T1 (S (14)) xor T2 (S (3))  xor T3 (S (8));
      C3 := T0 (S (13)) xor T1 (S (2))  xor T2 (S (7))  xor T3 (S (12));

      --  XOR with the 4 round-key columns and write into S.
      C0 := C0 xor Pack32 (RK (RK_Off + 1),  RK (RK_Off + 2),
                           RK (RK_Off + 3),  RK (RK_Off + 4));
      C1 := C1 xor Pack32 (RK (RK_Off + 5),  RK (RK_Off + 6),
                           RK (RK_Off + 7),  RK (RK_Off + 8));
      C2 := C2 xor Pack32 (RK (RK_Off + 9),  RK (RK_Off + 10),
                           RK (RK_Off + 11), RK (RK_Off + 12));
      C3 := C3 xor Pack32 (RK (RK_Off + 13), RK (RK_Off + 14),
                           RK (RK_Off + 15), RK (RK_Off + 16));

      S (1)  := Octet (Shift_Right (C0, 24) and 16#FF#);
      S (2)  := Octet (Shift_Right (C0, 16) and 16#FF#);
      S (3)  := Octet (Shift_Right (C0,  8) and 16#FF#);
      S (4)  := Octet (C0 and 16#FF#);
      S (5)  := Octet (Shift_Right (C1, 24) and 16#FF#);
      S (6)  := Octet (Shift_Right (C1, 16) and 16#FF#);
      S (7)  := Octet (Shift_Right (C1,  8) and 16#FF#);
      S (8)  := Octet (C1 and 16#FF#);
      S (9)  := Octet (Shift_Right (C2, 24) and 16#FF#);
      S (10) := Octet (Shift_Right (C2, 16) and 16#FF#);
      S (11) := Octet (Shift_Right (C2,  8) and 16#FF#);
      S (12) := Octet (C2 and 16#FF#);
      S (13) := Octet (Shift_Right (C3, 24) and 16#FF#);
      S (14) := Octet (Shift_Right (C3, 16) and 16#FF#);
      S (15) := Octet (Shift_Right (C3,  8) and 16#FF#);
      S (16) := Octet (C3 and 16#FF#);
   end Full_Round_T_Tables;

   procedure Full_Round
     (S     : in out Block;
      RK    : Octet_Array;
      Round : Natural)
   is
   begin
      if Tls_Core_Config.T_Tables_Enabled then
         Full_Round_T_Tables (S, RK, Round);
      else
         Sub_Bytes (S);
         Shift_Rows (S);
         Mix_Columns (S);
         Add_Round_Key (S, RK, Round);
      end if;
   end Full_Round;

   procedure Final_Round
     (S     : in out Block;
      RK    : Octet_Array;
      Round : Natural)
   is
   begin
      Sub_Bytes (S);
      Shift_Rows (S);
      Add_Round_Key (S, RK, Round);
   end Final_Round;

end Tls_Core.Aes_Core;
