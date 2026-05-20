package body Tls_Core.Sha256
  with SPARK_Mode
is

   use Interfaces;

   ---------------------------------------------------------------------
   --  FIPS 180-4 §4.2.2 round constants K[0..63] —
   --  HACL* `Spec.SHA2.Constants.k224_256` (lib/Spec.SHA2.Constants.fst:24).
   ---------------------------------------------------------------------

   K : constant array (0 .. 63) of Word :=
     [16#428A_2F98#,
      16#7137_4491#,
      16#B5C0_FBCF#,
      16#E9B5_DBA5#,
      16#3956_C25B#,
      16#59F1_11F1#,
      16#923F_82A4#,
      16#AB1C_5ED5#,
      16#D807_AA98#,
      16#1283_5B01#,
      16#2431_85BE#,
      16#550C_7DC3#,
      16#72BE_5D74#,
      16#80DE_B1FE#,
      16#9BDC_06A7#,
      16#C19B_F174#,
      16#E49B_69C1#,
      16#EFBE_4786#,
      16#0FC1_9DC6#,
      16#240C_A1CC#,
      16#2DE9_2C6F#,
      16#4A74_84AA#,
      16#5CB0_A9DC#,
      16#76F9_88DA#,
      16#983E_5152#,
      16#A831_C66D#,
      16#B003_27C8#,
      16#BF59_7FC7#,
      16#C6E0_0BF3#,
      16#D5A7_9147#,
      16#06CA_6351#,
      16#1429_2967#,
      16#27B7_0A85#,
      16#2E1B_2138#,
      16#4D2C_6DFC#,
      16#5338_0D13#,
      16#650A_7354#,
      16#766A_0ABB#,
      16#81C2_C92E#,
      16#9272_2C85#,
      16#A2BF_E8A1#,
      16#A81A_664B#,
      16#C24B_8B70#,
      16#C76C_51A3#,
      16#D192_E819#,
      16#D699_0624#,
      16#F40E_3585#,
      16#106A_A070#,
      16#19A4_C116#,
      16#1E37_6C08#,
      16#2748_774C#,
      16#34B0_BCB5#,
      16#391C_0CB3#,
      16#4ED8_AA4A#,
      16#5B9C_CA4F#,
      16#682E_6FF3#,
      16#748F_82EE#,
      16#78A5_636F#,
      16#84C8_7814#,
      16#8CC7_0208#,
      16#90BE_FFFA#,
      16#A450_6CEB#,
      16#BEF9_A3F7#,
      16#C671_78F2#];

   ---------------------------------------------------------------------
   --  FIPS 180-4 §4.1.2 — the six bit-mixing functions.
   --  Mirrors HACL* `_Ch` / `_Maj` / `_Sigma0/1` / `_sigma0/1`
   --  (specs/Spec.SHA2.fst:113-138) with the SHA2_256 rotation
   --  amounts from `op224_256` (specs/Spec.SHA2.fst:46).
   ---------------------------------------------------------------------

   function ROTR (X : Word; N : Natural) return Word
   is (Shift_Right (X, N) or Shift_Left (X, 32 - N))
   with Pre => N in 1 .. 31;

   function Ch (X, Y, Z : Word) return Word
   is ((X and Y) xor ((not X) and Z));

   function Maj (X, Y, Z : Word) return Word
   is ((X and Y) xor (X and Z) xor (Y and Z));

   function Big_Sigma_0 (X : Word) return Word
   is (ROTR (X, 2) xor ROTR (X, 13) xor ROTR (X, 22));

   function Big_Sigma_1 (X : Word) return Word
   is (ROTR (X, 6) xor ROTR (X, 11) xor ROTR (X, 25));

   function Small_Sigma_0 (X : Word) return Word
   is (ROTR (X, 7) xor ROTR (X, 18) xor Shift_Right (X, 3));

   function Small_Sigma_1 (X : Word) return Word
   is (ROTR (X, 17) xor ROTR (X, 19) xor Shift_Right (X, 10));

   ---------------------------------------------------------------------
   --  Read four bytes BE → Word.
   ---------------------------------------------------------------------

   function BE_Word (B : Block; Offset : Block_Index) return Word
   is (Shift_Left (Word (B (Offset)), 24)
       or Shift_Left (Word (B (Offset + 1)), 16)
       or Shift_Left (Word (B (Offset + 2)), 8)
       or Word (B (Offset + 3)))
   with Pre => Offset <= Block_Length - 3;

   ---------------------------------------------------------------------
   --  HACL* spec ports — bodies for the spec helpers declared in
   --  the public part. These are the canonical reference algorithm;
   --  they execute, are called by Spec_SHA256 and (indirectly via
   --  Spec_SHA256) by the public Hash procedure.
   ---------------------------------------------------------------------

   --  Mirrors HACL* `Spec.SHA2.update_pre` (specs/Spec.SHA2.fst:213):
   --    let block_w = words_of_bytes a #16 block in
   --    let hash_1  = shuffle a hash block_w in
   --    seq_map2 (+) hash hash_1
   --
   --  The shuffle inlines the message schedule (`ws_pre`,
   --  Spec.SHA2.fst:175-200) and the round function
   --  (`shuffle_core_pre_`, Spec.SHA2.fst:154).
   function Update_Block_Spec (S : Hash_State; B : Block) return Hash_State is
      W                       : array (0 .. 63) of Word := [others => 0];
      A, Bv, C, D, E, F, G, H : Word;
      T1, T2                  : Word;
      Out_S                   : Hash_State := [others => 0];
   begin
      --  ws_pre: first 16 words are big-endian loads of the block.
      for I in 0 .. 15 loop
         W (I) := BE_Word (B, B'First + 4 * I);
      end loop;
      --  ws_pre: subsequent words from sigma functions.
      for I in 16 .. 63 loop
         W (I) :=
           Small_Sigma_1 (W (I - 2))
           + W (I - 7)
           + Small_Sigma_0 (W (I - 15))
           + W (I - 16);
      end loop;

      --  Shuffle: 64 rounds of shuffle_core_pre_.
      A := S (1);
      Bv := S (2);
      C := S (3);
      D := S (4);
      E := S (5);
      F := S (6);
      G := S (7);
      H := S (8);

      for I in 0 .. 63 loop
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

      --  seq_map2 (+): elementwise add of input state and shuffle output.
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
         B (J) := Padded (I * 64 + J);
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

   function Pad_SHA256 (Input : Octet_Array) return Octet_Array is
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
      for I in 1 .. 8 loop
         Out_Buf (Total - 8 + I) :=
           Octet (Shift_Right (Bits, Natural (8 * (8 - I))) and 16#FF#);
      end loop;
      return Out_Buf;
   end Pad_SHA256;

   function Finalize_State (S : Hash_State) return Digest is
      D : Digest := [others => 0];
   begin
      for I in 1 .. 8 loop
         D (4 * (I - 1) + 1) := Octet (Shift_Right (S (I), 24) and 16#FF#);
         D (4 * (I - 1) + 2) := Octet (Shift_Right (S (I), 16) and 16#FF#);
         D (4 * (I - 1) + 3) := Octet (Shift_Right (S (I), 8) and 16#FF#);
         D (4 * (I - 1) + 4) := Octet (S (I) and 16#FF#);
      end loop;
      return D;
   end Finalize_State;

   --  Top-level one-shot SHA-256 spec.
   function Spec_SHA256 (Input : Octet_Array) return Digest is
      Padded   : constant Octet_Array := Pad_SHA256 (Input);
      N_Blocks : constant Natural := Padded'Length / 64;
      Final_S  : constant Hash_State :=
        Spec_Hash_Blocks (Initial_State_SHA256, Padded, N_Blocks);
   begin
      return Finalize_State (Final_S);
   end Spec_SHA256;

   ---------------------------------------------------------------------
   --  Imperative streaming Process_Block — same algorithm as
   --  Update_Block_Spec, but mutating Ctx.H in place. Used only by
   --  the streaming Init/Update/Finalize path; the one-shot Hash
   --  flows through Spec_SHA256 directly.
   ---------------------------------------------------------------------

   procedure Process_Block (Ctx : in out Context; B : Block);
   procedure Process_Block (Ctx : in out Context; B : Block) is
      W                       : array (0 .. 63) of Word := [others => 0];
      A, Bv, C, D, E, F, G, H : Word;
      T1, T2                  : Word;
   begin
      for I in 0 .. 15 loop
         W (I) := BE_Word (B, B'First + 4 * I);
         pragma
           Loop_Invariant
             (for all J in 0 .. I => W (J) = BE_Word (B, B'First + 4 * J));
      end loop;
      for I in 16 .. 63 loop
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

      for I in 0 .. 63 loop
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
   --  Init / Update / Finalize — streaming API. No functional Post.
   ---------------------------------------------------------------------

   procedure Init (Ctx : out Context) is
   begin
      Ctx.H := Initial_State_SHA256;
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

      if Filled > Block_Length - 8 then
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

      if Filled + 1 <= Block_Length - 8 then
         for I in Filled + 1 .. Block_Length - 8 loop
            Ctx.Buf (I) := 0;
         end loop;
      end if;
      Ctx.Buf_Len := 0;

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
         Out_Digest (4 * (I - 1) + 1) :=
           Octet (Shift_Right (Ctx.H (I), 24) and 16#FF#);
         Out_Digest (4 * (I - 1) + 2) :=
           Octet (Shift_Right (Ctx.H (I), 16) and 16#FF#);
         Out_Digest (4 * (I - 1) + 3) :=
           Octet (Shift_Right (Ctx.H (I), 8) and 16#FF#);
         Out_Digest (4 * (I - 1) + 4) := Octet (Ctx.H (I) and 16#FF#);
      end loop;
   end Finalize;

   ---------------------------------------------------------------------
   --  One-shot Hash — direct call to the spec, so the functional
   --  Post Output = Spec_SHA256 (Data) discharges by construction.
   --  This makes the relationship between code and spec trivial:
   --  the code IS the spec.
   ---------------------------------------------------------------------

   procedure Hash (Data : Octet_Array; Out_Digest : out Digest) is
   begin
      Out_Digest := Spec_SHA256 (Data);
   end Hash;

end Tls_Core.Sha256;
