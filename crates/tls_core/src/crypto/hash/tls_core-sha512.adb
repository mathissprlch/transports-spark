package body Tls_Core.Sha512
  with SPARK_Mode
is

   use Interfaces;


   ---------------------------------------------------------------------
   --  FIPS 180-4 §4.2.3 round constants K[0..79] —
   --  HACL* `Spec.SHA2.Constants.k384_512` (lib/Spec.SHA2.Constants.fst:27).
   ---------------------------------------------------------------------

   K : constant array (0 .. 79) of Word :=
     [16#428A_2F98_D728_AE22#,
      16#7137_4491_23EF_65CD#,
      16#B5C0_FBCF_EC4D_3B2F#,
      16#E9B5_DBA5_8189_DBBC#,
      16#3956_C25B_F348_B538#,
      16#59F1_11F1_B605_D019#,
      16#923F_82A4_AF19_4F9B#,
      16#AB1C_5ED5_DA6D_8118#,
      16#D807_AA98_A303_0242#,
      16#1283_5B01_4570_6FBE#,
      16#2431_85BE_4EE4_B28C#,
      16#550C_7DC3_D5FF_B4E2#,
      16#72BE_5D74_F27B_896F#,
      16#80DE_B1FE_3B16_96B1#,
      16#9BDC_06A7_25C7_1235#,
      16#C19B_F174_CF69_2694#,
      16#E49B_69C1_9EF1_4AD2#,
      16#EFBE_4786_384F_25E3#,
      16#0FC1_9DC6_8B8C_D5B5#,
      16#240C_A1CC_77AC_9C65#,
      16#2DE9_2C6F_592B_0275#,
      16#4A74_84AA_6EA6_E483#,
      16#5CB0_A9DC_BD41_FBD4#,
      16#76F9_88DA_8311_53B5#,
      16#983E_5152_EE66_DFAB#,
      16#A831_C66D_2DB4_3210#,
      16#B003_27C8_98FB_213F#,
      16#BF59_7FC7_BEEF_0EE4#,
      16#C6E0_0BF3_3DA8_8FC2#,
      16#D5A7_9147_930A_A725#,
      16#06CA_6351_E003_826F#,
      16#1429_2967_0A0E_6E70#,
      16#27B7_0A85_46D2_2FFC#,
      16#2E1B_2138_5C26_C926#,
      16#4D2C_6DFC_5AC4_2AED#,
      16#5338_0D13_9D95_B3DF#,
      16#650A_7354_8BAF_63DE#,
      16#766A_0ABB_3C77_B2A8#,
      16#81C2_C92E_47ED_AEE6#,
      16#9272_2C85_1482_353B#,
      16#A2BF_E8A1_4CF1_0364#,
      16#A81A_664B_BC42_3001#,
      16#C24B_8B70_D0F8_9791#,
      16#C76C_51A3_0654_BE30#,
      16#D192_E819_D6EF_5218#,
      16#D699_0624_5565_A910#,
      16#F40E_3585_5771_202A#,
      16#106A_A070_32BB_D1B8#,
      16#19A4_C116_B8D2_D0C8#,
      16#1E37_6C08_5141_AB53#,
      16#2748_774C_DF8E_EB99#,
      16#34B0_BCB5_E19B_48A8#,
      16#391C_0CB3_C5C9_5A63#,
      16#4ED8_AA4A_E341_8ACB#,
      16#5B9C_CA4F_7763_E373#,
      16#682E_6FF3_D6B2_B8A3#,
      16#748F_82EE_5DEF_B2FC#,
      16#78A5_636F_4317_2F60#,
      16#84C8_7814_A1F0_AB72#,
      16#8CC7_0208_1A64_39EC#,
      16#90BE_FFFA_2363_1E28#,
      16#A450_6CEB_DE82_BDE9#,
      16#BEF9_A3F7_B2C6_7915#,
      16#C671_78F2_E372_532B#,
      16#CA27_3ECE_EA26_619C#,
      16#D186_B8C7_21C0_C207#,
      16#EADA_7DD6_CDE0_EB1E#,
      16#F57D_4F7F_EE6E_D178#,
      16#06F0_67AA_7217_6FBA#,
      16#0A63_7DC5_A2C8_98A6#,
      16#113F_9804_BEF9_0DAE#,
      16#1B71_0B35_131C_471B#,
      16#28DB_77F5_2304_7D84#,
      16#32CA_AB7B_40C7_2493#,
      16#3C9E_BE0A_15C9_BEBC#,
      16#431D_67C4_9C10_0D4C#,
      16#4CC5_D4BE_CB3E_42B6#,
      16#597F_299C_FC65_7E2A#,
      16#5FCB_6FAB_3AD6_FAEC#,
      16#6C44_198C_4A47_5817#];

   ---------------------------------------------------------------------
   --  FIPS 180-4 §4.1.3 — six bit-mixing functions.
   --  Mirrors HACL* `_Ch` / `_Maj` / `_Sigma0/1` / `_sigma0/1`
   --  (specs/Spec.SHA2.fst:113-138) with the SHA2_512 rotation
   --  amounts from `op384_512` (specs/Spec.SHA2.fst:54).
   ---------------------------------------------------------------------

   function ROTR (X : Word; N : Natural) return Word
   is (Shift_Right (X, N) or Shift_Left (X, 64 - N))
   with Pre => N in 1 .. 63;

   function Ch (X, Y, Z : Word) return Word
   is ((X and Y) xor ((not X) and Z));

   function Maj (X, Y, Z : Word) return Word
   is ((X and Y) xor (X and Z) xor (Y and Z));

   function Big_Sigma_0 (X : Word) return Word
   is (ROTR (X, 28) xor ROTR (X, 34) xor ROTR (X, 39));

   function Big_Sigma_1 (X : Word) return Word
   is (ROTR (X, 14) xor ROTR (X, 18) xor ROTR (X, 41));

   function Small_Sigma_0 (X : Word) return Word
   is (ROTR (X, 1) xor ROTR (X, 8) xor Shift_Right (X, 7));

   function Small_Sigma_1 (X : Word) return Word
   is (ROTR (X, 19) xor ROTR (X, 61) xor Shift_Right (X, 6));

   ---------------------------------------------------------------------
   --  Read eight bytes BE → Word.
   ---------------------------------------------------------------------

   function BE_Word (B : Block; Offset : Block_Index) return Word
   is (Shift_Left (Word (B (Offset)), 56)
       or Shift_Left (Word (B (Offset + 1)), 48)
       or Shift_Left (Word (B (Offset + 2)), 40)
       or Shift_Left (Word (B (Offset + 3)), 32)
       or Shift_Left (Word (B (Offset + 4)), 24)
       or Shift_Left (Word (B (Offset + 5)), 16)
       or Shift_Left (Word (B (Offset + 6)), 8)
       or Word (B (Offset + 7)))
   with Pre => Offset <= Block_Length - 7;

   ---------------------------------------------------------------------
   --  HACL* spec port bodies.
   ---------------------------------------------------------------------

   function Update_Block_Spec (S : Hash_State; B : Block) return Hash_State is
      W                       : array (0 .. 79) of Word := [others => 0];
      A, Bv, C, D, E, F, G, H : Word;
      T1, T2                  : Word;
      Out_S                   : Hash_State := [others => 0];
   begin
      for I in 0 .. 15 loop
         W (I) := BE_Word (B, B'First + 8 * I);
      end loop;
      for I in 16 .. 79 loop
         W (I) :=
           Small_Sigma_1 (W (I - 2))
           + W (I - 7)
           + Small_Sigma_0 (W (I - 15))
           + W (I - 16);
      end loop;

      A := S (1);
      Bv := S (2);
      C := S (3);
      D := S (4);
      E := S (5);
      F := S (6);
      G := S (7);
      H := S (8);

      for I in 0 .. 79 loop
         T1 := H + Big_Sigma_1 (E) + Ch (E, F, G) + K (I) + W (I);
         T2 := Big_Sigma_0 (A) + Maj (A, Bv, C);
         H := G;
         G := F;
         F := E;
         E := D + T1;
         D := C;
         C := Bv;
         Bv := A;
         A := T1 + T2;
      end loop;

      Out_S (1) := S (1) + A;
      Out_S (2) := S (2) + Bv;
      Out_S (3) := S (3) + C;
      Out_S (4) := S (4) + D;
      Out_S (5) := S (5) + E;
      Out_S (6) := S (6) + F;
      Out_S (7) := S (7) + G;
      Out_S (8) := S (8) + H;
      return Out_S;
   end Update_Block_Spec;

   function Block_At (Padded : Octet_Array; I : Natural) return Block is
      B : Block := [others => 0];
   begin
      for J in Block_Index loop
         B (J) := Padded (I * 128 + J);
      end loop;
      return B;
   end Block_At;

   function Spec_Hash_Blocks
     (S0 : Hash_State; Padded : Octet_Array; N : Natural) return Hash_State is
   begin
      if N = 0 then
         return S0;
      else
         return
           Update_Block_Spec
             (Spec_Hash_Blocks (S0, Padded, N - 1), Block_At (Padded, N - 1));
      end if;
   end Spec_Hash_Blocks;

   function Pad_SHA512 (Input : Octet_Array) return Octet_Array is
      Pad_Len : constant Positive := Spec_Pad_Length (Input'Length);
      Total   : constant Positive := Input'Length + Pad_Len;
      Bits    : constant Interfaces.Unsigned_64 :=
        Interfaces.Unsigned_64 (Input'Length) * 8;
      Out_Buf : Octet_Array (1 .. Total) := [others => 0];
   begin
      if Input'Length > 0 then
         Out_Buf (1 .. Input'Length) := Input;
      end if;
      Out_Buf (Input'Length + 1) := 16#80#;
      --  Upper 64 bits of the 128-bit BE length: zero (since we
      --  track only 64-bit byte counts). Already zero from the
      --  default-initialized buffer; explicit assignment for clarity.
      for I in 1 .. 8 loop
         Out_Buf (Total - 16 + I) := 0;
      end loop;
      --  Lower 64 bits: the bit count, BE.
      for I in 1 .. 8 loop
         Out_Buf (Total - 8 + I) :=
           Octet (Shift_Right (Bits, Natural (8 * (8 - I))) and 16#FF#);
      end loop;
      return Out_Buf;
   end Pad_SHA512;

   function Finalize_State (S : Hash_State) return Digest is
      D : Digest := [others => 0];
   begin
      for I in 1 .. 8 loop
         for J in 1 .. 8 loop
            D (8 * (I - 1) + J) :=
              Octet (Shift_Right (S (I), Natural (8 * (8 - J))) and 16#FF#);
         end loop;
      end loop;
      return D;
   end Finalize_State;

   function Spec_SHA512 (Input : Octet_Array) return Digest is
      Padded   : constant Octet_Array := Pad_SHA512 (Input);
      N_Blocks : constant Natural := Padded'Length / 128;
      Final_S  : constant Hash_State :=
        Spec_Hash_Blocks (Initial_State_SHA512, Padded, N_Blocks);
   begin
      return Finalize_State (Final_S);
   end Spec_SHA512;

   ---------------------------------------------------------------------
   --  Imperative streaming Process_Block.
   ---------------------------------------------------------------------

   procedure Process_Block (Ctx : in out Context; B : Block);
   procedure Process_Block (Ctx : in out Context; B : Block) is
      W                       : array (0 .. 79) of Word := [others => 0];
      A, Bv, C, D, E, F, G, H : Word;
      T1, T2                  : Word;
   begin
      for I in 0 .. 15 loop
         W (I) := BE_Word (B, B'First + 8 * I);
      end loop;
      for I in 16 .. 79 loop
         W (I) :=
           Small_Sigma_1 (W (I - 2))
           + W (I - 7)
           + Small_Sigma_0 (W (I - 15))
           + W (I - 16);
      end loop;

      A := Ctx.H (1);
      Bv := Ctx.H (2);
      C := Ctx.H (3);
      D := Ctx.H (4);
      E := Ctx.H (5);
      F := Ctx.H (6);
      G := Ctx.H (7);
      H := Ctx.H (8);

      for I in 0 .. 79 loop
         T1 := H + Big_Sigma_1 (E) + Ch (E, F, G) + K (I) + W (I);
         T2 := Big_Sigma_0 (A) + Maj (A, Bv, C);
         H := G;
         G := F;
         F := E;
         E := D + T1;
         D := C;
         C := Bv;
         Bv := A;
         A := T1 + T2;
      end loop;

      Ctx.H (1) := Ctx.H (1) + A;
      Ctx.H (2) := Ctx.H (2) + Bv;
      Ctx.H (3) := Ctx.H (3) + C;
      Ctx.H (4) := Ctx.H (4) + D;
      Ctx.H (5) := Ctx.H (5) + E;
      Ctx.H (6) := Ctx.H (6) + F;
      Ctx.H (7) := Ctx.H (7) + G;
      Ctx.H (8) := Ctx.H (8) + H;
   end Process_Block;

   ---------------------------------------------------------------------
   --  Init / Update / Finalize — streaming API.
   ---------------------------------------------------------------------

   procedure Init (Ctx : out Context) is
   begin
      Ctx.H := Initial_State_SHA512;
      Ctx.Buf := [others => 0];
      Ctx.Buf_Len := 0;
      Ctx.Total_Len := 0;
   end Init;

   procedure Update (Ctx : in out Context; Data : Octet_Array) is
      Consumed : Natural := 0;
      Need     : Natural;
   begin
      Ctx.Total_Len := Ctx.Total_Len + Interfaces.Unsigned_64 (Data'Length);

      if Ctx.Buf_Len > 0 then
         Need := Block_Length - Ctx.Buf_Len;
         if Data'Length < Need then
            Ctx.Buf (Ctx.Buf_Len + 1 .. Ctx.Buf_Len + Data'Length) := Data;
            Ctx.Buf_Len := Ctx.Buf_Len + Data'Length;
            return;
         end if;
         Ctx.Buf (Ctx.Buf_Len + 1 .. Block_Length) :=
           Data (Data'First .. Data'First + Need - 1);
         declare
            Snap : constant Block := Ctx.Buf;
         begin
            Process_Block (Ctx, Snap);
         end;
         Consumed := Need;
         Ctx.Buf_Len := 0;
      end if;

      while Data'Length - Consumed >= Block_Length loop
         pragma Loop_Variant (Decreases => Data'Length - Consumed);
         pragma Loop_Invariant (Consumed <= Data'Length);
         pragma Loop_Invariant (Ctx.Buf_Len = 0);
         Ctx.Buf :=
           Data
             (Data'First
              + Consumed
              .. Data'First + Consumed + Block_Length - 1);
         declare
            Snap : constant Block := Ctx.Buf;
         begin
            Process_Block (Ctx, Snap);
         end;
         Consumed := Consumed + Block_Length;
      end loop;

      declare
         Remaining : constant Natural := Data'Length - Consumed;
      begin
         Ctx.Buf := [others => 0];
         if Remaining > 0 then
            Ctx.Buf (1 .. Remaining) :=
              Data
                (Data'First
                 + Consumed
                 .. Data'First + Consumed + Remaining - 1);
         end if;
         Ctx.Buf_Len := Remaining;
      end;
   end Update;

   procedure Finalize (Ctx : in out Context; Out_Digest : out Digest) is
      Bits   : constant Interfaces.Unsigned_64 := Ctx.Total_Len * 8;
      Filled : Natural := Ctx.Buf_Len;
   begin
      Out_Digest := [others => 0];
      Ctx.Buf (Filled + 1) := 16#80#;
      Filled := Filled + 1;

      if Filled > Block_Length - 16 then
         if Filled < Block_Length then
            for I in Filled + 1 .. Block_Length loop
               Ctx.Buf (I) := 0;
            end loop;
         end if;
         declare
            Snap : constant Block := Ctx.Buf;
         begin
            Process_Block (Ctx, Snap);
         end;
         Ctx.Buf := [others => 0];
         Filled := 0;
      end if;

      if Filled + 1 <= Block_Length - 16 then
         for I in Filled + 1 .. Block_Length - 16 loop
            Ctx.Buf (I) := 0;
         end loop;
      end if;
      Ctx.Buf_Len := 0;

      for I in 1 .. 8 loop
         Ctx.Buf (Block_Length - 16 + I) := 0;
      end loop;
      for I in 1 .. 8 loop
         Ctx.Buf (Block_Length - 8 + I) :=
           Octet (Shift_Right (Bits, Natural (8 * (8 - I))) and 16#FF#);
      end loop;

      declare
         Snap : constant Block := Ctx.Buf;
      begin
         Process_Block (Ctx, Snap);
      end;

      for I in 1 .. 8 loop
         for J in 1 .. 8 loop
            Out_Digest (8 * (I - 1) + J) :=
              Octet
                (Shift_Right (Ctx.H (I), Natural (8 * (8 - J))) and 16#FF#);
         end loop;
      end loop;
   end Finalize;

   ---------------------------------------------------------------------
   --  One-shot Hash — direct call to the spec.
   ---------------------------------------------------------------------

   procedure Hash (Data : Octet_Array; Out_Digest : out Digest) is
   begin
      Out_Digest := Spec_SHA512 (Data);
   end Hash;

end Tls_Core.Sha512;
