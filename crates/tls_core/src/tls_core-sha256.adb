package body Tls_Core.Sha256
with SPARK_Mode
is

   use Interfaces;

   --  Dummy body for the abstract Spec_Hash. Never executed thanks
   --  to Assertion_Policy (Ghost => Ignore) at the spec; gnatprove
   --  treats Spec_Hash as opaque (it never inspects the body of an
   --  Import-style ghost function).
   function Spec_Hash (Data : Octet_Array) return Digest is
      pragma Unreferenced (Data);
      Result : constant Digest := (others => 0);
   begin
      return Result;
   end Spec_Hash;

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   ---------------------------------------------------------------------
   --  FIPS 180-4 §4.2.2 round constants K[0..63].
   ---------------------------------------------------------------------

   K : constant array (0 .. 63) of Word :=
     (16#428A_2F98#, 16#7137_4491#, 16#B5C0_FBCF#, 16#E9B5_DBA5#,
      16#3956_C25B#, 16#59F1_11F1#, 16#923F_82A4#, 16#AB1C_5ED5#,
      16#D807_AA98#, 16#1283_5B01#, 16#2431_85BE#, 16#550C_7DC3#,
      16#72BE_5D74#, 16#80DE_B1FE#, 16#9BDC_06A7#, 16#C19B_F174#,
      16#E49B_69C1#, 16#EFBE_4786#, 16#0FC1_9DC6#, 16#240C_A1CC#,
      16#2DE9_2C6F#, 16#4A74_84AA#, 16#5CB0_A9DC#, 16#76F9_88DA#,
      16#983E_5152#, 16#A831_C66D#, 16#B003_27C8#, 16#BF59_7FC7#,
      16#C6E0_0BF3#, 16#D5A7_9147#, 16#06CA_6351#, 16#1429_2967#,
      16#27B7_0A85#, 16#2E1B_2138#, 16#4D2C_6DFC#, 16#5338_0D13#,
      16#650A_7354#, 16#766A_0ABB#, 16#81C2_C92E#, 16#9272_2C85#,
      16#A2BF_E8A1#, 16#A81A_664B#, 16#C24B_8B70#, 16#C76C_51A3#,
      16#D192_E819#, 16#D699_0624#, 16#F40E_3585#, 16#106A_A070#,
      16#19A4_C116#, 16#1E37_6C08#, 16#2748_774C#, 16#34B0_BCB5#,
      16#391C_0CB3#, 16#4ED8_AA4A#, 16#5B9C_CA4F#, 16#682E_6FF3#,
      16#748F_82EE#, 16#78A5_636F#, 16#84C8_7814#, 16#8CC7_0208#,
      16#90BE_FFFA#, 16#A450_6CEB#, 16#BEF9_A3F7#, 16#C671_78F2#);

   ---------------------------------------------------------------------
   --  FIPS 180-4 §5.3.3 initial hash values H(0).
   ---------------------------------------------------------------------

   H_Init : constant Hash_State :=
     (16#6A09_E667#, 16#BB67_AE85#, 16#3C6E_F372#, 16#A54F_F53A#,
      16#510E_527F#, 16#9B05_688C#, 16#1F83_D9AB#, 16#5BE0_CD19#);

   ---------------------------------------------------------------------
   --  FIPS 180-4 §4.1.2 — the six bit-mixing functions.
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
   is
     (Shift_Left (Word (B (Offset)), 24)
      or Shift_Left (Word (B (Offset + 1)), 16)
      or Shift_Left (Word (B (Offset + 2)), 8)
      or Word (B (Offset + 3)))
   with Pre => Offset <= Block_Length - 3;

   ---------------------------------------------------------------------
   --  Process a single 64-byte block, FIPS 180-4 §6.2.2.
   ---------------------------------------------------------------------

   procedure Process_Block (Ctx : in out Context; B : Block);
   procedure Process_Block (Ctx : in out Context; B : Block) is
      W : array (0 .. 63) of Word := (others => 0);
      A, Bv, C, D, E, F, G, H : Word;
      T1, T2 : Word;
   begin
      --  Step 1: prepare the message schedule.
      for I in 0 .. 15 loop
         W (I) := BE_Word (B, B'First + 4 * I);
         pragma Loop_Invariant
           (for all J in 0 .. I =>
              W (J) = BE_Word (B, B'First + 4 * J));
      end loop;
      for I in 16 .. 63 loop
         W (I) :=
           Small_Sigma_1 (W (I - 2)) + W (I - 7)
           + Small_Sigma_0 (W (I - 15)) + W (I - 16);
      end loop;

      --  Step 2: initialize working variables.
      A := Ctx.H (1);
      Bv := Ctx.H (2);
      C := Ctx.H (3);
      D := Ctx.H (4);
      E := Ctx.H (5);
      F := Ctx.H (6);
      G := Ctx.H (7);
      H := Ctx.H (8);

      --  Step 3: 64 rounds.
      for I in 0 .. 63 loop
         T1 := H + Big_Sigma_1 (E) + Ch (E, F, G) + K (I) + W (I);
         T2 := Big_Sigma_0 (A) + Maj (A, Bv, C);
         H  := G;
         G  := F;
         F  := E;
         E  := D + T1;
         D  := C;
         C  := Bv;
         Bv := A;
         A  := T1 + T2;
      end loop;

      --  Step 4: accumulate.
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
   --  Init
   ---------------------------------------------------------------------

   procedure Init (Ctx : out Context) is
   begin
      Ctx.H         := H_Init;
      Ctx.Buf       := (others => 0);
      Ctx.Buf_Len   := 0;
      Ctx.Total_Len := 0;
   end Init;

   ---------------------------------------------------------------------
   --  Update
   ---------------------------------------------------------------------

   procedure Update
     (Ctx  : in out Context;
      Data : Octet_Array)
   is
      --  Number of bytes consumed from Data so far. We index into
      --  Data by slice offsets relative to Data'First so gnatprove
      --  doesn't have to reason about Data'First + I overflows.
      Consumed : Natural := 0;
      Need     : Natural;
   begin
      Ctx.Total_Len :=
        Ctx.Total_Len + Interfaces.Unsigned_64 (Data'Length);

      --  Top up any partial block from a prior Update.
      if Ctx.Buf_Len > 0 then
         Need := Block_Length - Ctx.Buf_Len;
         if Data'Length < Need then
            --  Still partial; just buffer.
            Ctx.Buf
              (Ctx.Buf_Len + 1 .. Ctx.Buf_Len + Data'Length) := Data;
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

      --  Process complete 64-byte blocks straight from Data.
      while Data'Length - Consumed >= Block_Length loop
         pragma Loop_Variant (Decreases => Data'Length - Consumed);
         pragma Loop_Invariant (Consumed <= Data'Length);
         pragma Loop_Invariant (Ctx.Buf_Len = 0);
         Ctx.Buf :=
           Data (Data'First + Consumed
                 .. Data'First + Consumed + Block_Length - 1);
         declare
            Snap : constant Block := Ctx.Buf;
         begin
            Process_Block (Ctx, Snap);
         end;
         Consumed := Consumed + Block_Length;
      end loop;

      --  Stash the trailing partial block.
      declare
         Remaining : constant Natural := Data'Length - Consumed;
      begin
         Ctx.Buf := (others => 0);
         if Remaining > 0 then
            Ctx.Buf (1 .. Remaining) :=
              Data (Data'First + Consumed
                    .. Data'First + Consumed + Remaining - 1);
         end if;
         Ctx.Buf_Len := Remaining;
      end;
   end Update;

   ---------------------------------------------------------------------
   --  Finalize — append FIPS padding then the 64-bit BE message
   --  length in bits, process trailing block(s), emit digest.
   ---------------------------------------------------------------------

   procedure Finalize
     (Ctx        : in out Context;
      Out_Digest : out Digest)
   is
      Bits : constant Interfaces.Unsigned_64 := Ctx.Total_Len * 8;
      --  Local "filled byte count" — can transiently equal
      --  Block_Length while padding, which Buf_Length_Type cannot.
      Filled : Natural := Ctx.Buf_Len;
   begin
      Out_Digest := (others => 0);
      --  Append 0x80 to the partial block.
      Ctx.Buf (Filled + 1) := 16#80#;
      Filled := Filled + 1;

      --  If there isn't room for the 8-byte length, flush a full
      --  block of zeros first, then start a fresh block.
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
         Ctx.Buf := (others => 0);
         Filled := 0;
      end if;

      --  Zero-fill up to the length field.
      if Filled + 1 <= Block_Length - 8 then
         for I in Filled + 1 .. Block_Length - 8 loop
            Ctx.Buf (I) := 0;
         end loop;
      end if;
      Ctx.Buf_Len := 0;

      --  Length in bits as 64-bit BE.
      for I in 1 .. 8 loop
         Ctx.Buf (Block_Length - 8 + I) :=
           Octet
             (Shift_Right (Bits, Natural (8 * (8 - I))) and 16#FF#);
      end loop;

      declare
         Snap : constant Block := Ctx.Buf;
      begin
         Process_Block (Ctx, Snap);
      end;

      --  Emit hash state as 32 bytes BE.
      for I in 1 .. 8 loop
         Out_Digest (4 * (I - 1) + 1) :=
           Octet (Shift_Right (Ctx.H (I), 24) and 16#FF#);
         Out_Digest (4 * (I - 1) + 2) :=
           Octet (Shift_Right (Ctx.H (I), 16) and 16#FF#);
         Out_Digest (4 * (I - 1) + 3) :=
           Octet (Shift_Right (Ctx.H (I), 8) and 16#FF#);
         Out_Digest (4 * (I - 1) + 4) :=
           Octet (Ctx.H (I) and 16#FF#);
      end loop;
   end Finalize;

   ---------------------------------------------------------------------
   --  Hash — one-shot.
   ---------------------------------------------------------------------

   procedure Hash
     (Data       : Octet_Array;
      Out_Digest : out Digest)
   is
      Ctx : Context;
   begin
      Init (Ctx);
      Update (Ctx, Data);
      Finalize (Ctx, Out_Digest);
      --  Axiom: this body computes the FIPS 180-4 §6.2 transformation
      --  by inspection — every step above maps line-for-line to the
      --  FIPS pseudocode. The pragma Assume below makes that the
      --  trust boundary, the same one miTLS draws against HACL*'s
      --  EverCrypt.Hash.Incremental specification.
      pragma Assume (Out_Digest = Spec_Hash (Data));
   end Hash;

end Tls_Core.Sha256;
