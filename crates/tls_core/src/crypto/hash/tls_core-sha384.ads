--  Tls_Core.Sha384 — SHA-384 in pure SPARK.
--
--  Source: FIPS 180-4 §6.5 — SHA-384 is SHA-512 with the IVs from
--  §5.3.4 and the digest truncated to the first 384 bits (48 bytes
--  = the first six 64-bit words of the hash state).
--
--  HACL* spec porting (docs/conventions.md §0c): the public one-shot Hash
--  procedure carries `Output = Spec_SHA384 (Data)`. Spec_SHA384 is
--  a SPARK port of HACL*'s `Spec.SHA2.fst` for SHA2_384:
--
--    https://github.com/hacl-star/hacl-star/blob/main/specs/Spec.SHA2.fst
--
--  Mirrored constructs match the SHA-512 port (commit ce6cdaf); the
--  only differences are the initial state `h384`
--  (lib/Spec.SHA2.Constants.fst:80) and the truncation in
--  `Spec.Agile.Hash.finish_md` (specs/Spec.Agile.Hash.fst:54),
--  which slices the first 6 words = 48 bytes from the 8-word state.
--
--  Test vector: FIPS 180-4 §C.2:
--    SHA-384("abc") =
--      CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED163
--      1A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7
--
--  Used by the TLS 1.3 cipher suite TLS_AES_256_GCM_SHA384
--  (RFC 8446 §B.4) for the HKDF transcript hash.

with Interfaces;

package Tls_Core.Sha384
  with SPARK_Mode
is

   use type Interfaces.Unsigned_64;

   subtype Word is Interfaces.Unsigned_64;

   Block_Length : constant := 128;   --  Same as SHA-512.
   Hash_Length  : constant := 48;    --  384 bits.

   subtype Block_Index is Positive range 1 .. Block_Length;
   subtype Hash_Index is Positive range 1 .. Hash_Length;

   subtype Block is Octet_Array (Block_Index);
   subtype Digest is Octet_Array (Hash_Index);

   ---------------------------------------------------------------------
   --  HACL* Spec.SHA2 port — SHA-384 differs from SHA-512 only in
   --  the initial state and the digest truncation.
   ---------------------------------------------------------------------

   type Hash_State is array (1 .. 8) of Word;

   --  Mirrors `Spec.SHA2.Constants.h384` (lib/Spec.SHA2.Constants.fst:80).
   Initial_State_SHA384 : constant Hash_State :=
     [16#CBBB_9D5D_C105_9ED8#,
      16#629A_292A_367C_D507#,
      16#9159_015A_3070_DD17#,
      16#152F_ECD8_F70E_5939#,
      16#6733_2667_FFC0_0B31#,
      16#8EB4_4A87_6858_1511#,
      16#DB0C_2E0D_64F9_8FA7#,
      16#47B5_481D_BEFA_4FA4#];

   --  Same MD padding scheme as SHA-512 (128-byte block, 16-byte
   --  length field) — Spec.Hash.MD.pad (specs/Spec.Hash.MD.fst:30-44).
   function Spec_Pad_Length (N : Natural) return Positive
   is (((239 - (N mod 128)) mod 128) + 17)
   with
     Pre  => N <= Natural'Last - 17 - 128,
     Post =>
       Spec_Pad_Length'Result in 17 .. 144
       and then (N + Spec_Pad_Length'Result) mod 128 = 0;

   ---------------------------------------------------------------------
   --  SHA-512 family bit-mixing primitives + K table (expression
   --  functions so gnatprove inlines for UF congruence — same chacha20
   --  task #107 pattern, applied to SHA-384/512).
   ---------------------------------------------------------------------

   function ROTR (X : Word; N : Natural) return Word
   is (Interfaces.Shift_Right (X, N) or Interfaces.Shift_Left (X, 64 - N))
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
   is (ROTR (X, 1) xor ROTR (X, 8) xor Interfaces.Shift_Right (X, 7));

   function Small_Sigma_1 (X : Word) return Word
   is (ROTR (X, 19) xor ROTR (X, 61) xor Interfaces.Shift_Right (X, 6));

   function BE_Word (B : Block; Offset : Block_Index) return Word
   is (Interfaces.Shift_Left (Word (B (Offset)), 56)
       or Interfaces.Shift_Left (Word (B (Offset + 1)), 48)
       or Interfaces.Shift_Left (Word (B (Offset + 2)), 40)
       or Interfaces.Shift_Left (Word (B (Offset + 3)), 32)
       or Interfaces.Shift_Left (Word (B (Offset + 4)), 24)
       or Interfaces.Shift_Left (Word (B (Offset + 5)), 16)
       or Interfaces.Shift_Left (Word (B (Offset + 6)), 8)
       or Word (B (Offset + 7)))
   with Pre => Offset <= Block_Length - 7;

   K : constant array (0 .. 79) of Word :=
     [16#428A_2F98_D728_AE22#, 16#7137_4491_23EF_65CD#,
      16#B5C0_FBCF_EC4D_3B2F#, 16#E9B5_DBA5_8189_DBBC#,
      16#3956_C25B_F348_B538#, 16#59F1_11F1_B605_D019#,
      16#923F_82A4_AF19_4F9B#, 16#AB1C_5ED5_DA6D_8118#,
      16#D807_AA98_A303_0242#, 16#1283_5B01_4570_6FBE#,
      16#2431_85BE_4EE4_B28C#, 16#550C_7DC3_D5FF_B4E2#,
      16#72BE_5D74_F27B_896F#, 16#80DE_B1FE_3B16_96B1#,
      16#9BDC_06A7_25C7_1235#, 16#C19B_F174_CF69_2694#,
      16#E49B_69C1_9EF1_4AD2#, 16#EFBE_4786_384F_25E3#,
      16#0FC1_9DC6_8B8C_D5B5#, 16#240C_A1CC_77AC_9C65#,
      16#2DE9_2C6F_592B_0275#, 16#4A74_84AA_6EA6_E483#,
      16#5CB0_A9DC_BD41_FBD4#, 16#76F9_88DA_8311_53B5#,
      16#983E_5152_EE66_DFAB#, 16#A831_C66D_2DB4_3210#,
      16#B003_27C8_98FB_213F#, 16#BF59_7FC7_BEEF_0EE4#,
      16#C6E0_0BF3_3DA8_8FC2#, 16#D5A7_9147_930A_A725#,
      16#06CA_6351_E003_826F#, 16#1429_2967_0A0E_6E70#,
      16#27B7_0A85_46D2_2FFC#, 16#2E1B_2138_5C26_C926#,
      16#4D2C_6DFC_5AC4_2AED#, 16#5338_0D13_9D95_B3DF#,
      16#650A_7354_8BAF_63DE#, 16#766A_0ABB_3C77_B2A8#,
      16#81C2_C92E_47ED_AEE6#, 16#9272_2C85_1482_353B#,
      16#A2BF_E8A1_4CF1_0364#, 16#A81A_664B_BC42_3001#,
      16#C24B_8B70_D0F8_9791#, 16#C76C_51A3_0654_BE30#,
      16#D192_E819_D6EF_5218#, 16#D699_0624_5565_A910#,
      16#F40E_3585_5771_202A#, 16#106A_A070_32BB_D1B8#,
      16#19A4_C116_B8D2_D0C8#, 16#1E37_6C08_5141_AB53#,
      16#2748_774C_DF8E_EB99#, 16#34B0_BCB5_E19B_48A8#,
      16#391C_0CB3_C5C9_5A63#, 16#4ED8_AA4A_E341_8ACB#,
      16#5B9C_CA4F_7763_E373#, 16#682E_6FF3_D6B2_B8A3#,
      16#748F_82EE_5DEF_B2FC#, 16#78A5_636F_4317_2F60#,
      16#84C8_7814_A1F0_AB72#, 16#8CC7_0208_1A64_39EC#,
      16#90BE_FFFA_2363_1E28#, 16#A450_6CEB_DE82_BDE9#,
      16#BEF9_A3F7_B2C6_7915#, 16#C671_78F2_E372_532B#,
      16#CA27_3ECE_EA26_619C#, 16#D186_B8C7_21C0_C207#,
      16#EADA_7DD6_CDE0_EB1E#, 16#F57D_4F7F_EE6E_D178#,
      16#06F0_67AA_7217_6FBA#, 16#0A63_7DC5_A2C8_98A6#,
      16#113F_9804_BEF9_0DAE#, 16#1B71_0B35_131C_471B#,
      16#28DB_77F5_2304_7D84#, 16#32CA_AB7B_40C7_2493#,
      16#3C9E_BE0A_15C9_BEBC#, 16#431D_67C4_9C10_0D4C#,
      16#4CC5_D4BE_CB3E_42B6#, 16#597F_299C_FC65_7E2A#,
      16#5FCB_6FAB_3AD6_FAEC#, 16#6C44_198C_4A47_5817#];

   --  Recursive message schedule (HACL* ws_pre with 80 words).
   function Spec_W_SHA384 (B : Block; I : Natural) return Word
   is
     (if I <= 15
      then BE_Word (B, 1 + 8 * I)
      else Small_Sigma_1 (Spec_W_SHA384 (B, I - 2))
           + Spec_W_SHA384 (B, I - 7)
           + Small_Sigma_0 (Spec_W_SHA384 (B, I - 15))
           + Spec_W_SHA384 (B, I - 16))
   with
     Pre                => I <= 79,
     Subprogram_Variant => (Decreases => I);

   --  T1/T2 split into helpers — see Tls_Core.Sha256 for rationale.
   function Round_T1
     (S : Hash_State; W_I, K_I : Word) return Word
   is (S (8) + Big_Sigma_1 (S (5)) + Ch (S (5), S (6), S (7)) + K_I + W_I);

   function Round_T2 (S : Hash_State) return Word
   is (Big_Sigma_0 (S (1)) + Maj (S (1), S (2), S (3)));

   function One_Round_SHA384
     (S : Hash_State; W_I, K_I : Word) return Hash_State
   is ([1 => Round_T1 (S, W_I, K_I) + Round_T2 (S),
        2 => S (1),
        3 => S (2),
        4 => S (3),
        5 => S (4) + Round_T1 (S, W_I, K_I),
        6 => S (5),
        7 => S (6),
        8 => S (7)]);

   function Spec_Shuffle_SHA384
     (S : Hash_State; B : Block; N : Natural) return Hash_State
   is
     (if N = 0
      then S
      else One_Round_SHA384
             (Spec_Shuffle_SHA384 (S, B, N - 1),
              Spec_W_SHA384 (B, N - 1),
              K (N - 1)))
   with
     Pre                => N <= 80,
     Subprogram_Variant => (Decreases => N);

   --  Same compression function as SHA-512 (Spec.SHA2.fst:213).
   --  Expression function — gnatprove inlines for congruence threading.
   function Update_Block_Spec (S : Hash_State; B : Block) return Hash_State
   is ([for I in 1 .. 8 => S (I) + Spec_Shuffle_SHA384 (S, B, 80) (I)]);

   --  Expression function so gnatprove inlines for congruence threading.
   function Block_At (Padded : Octet_Array; I : Natural) return Block
   is ([for J in Block_Index => Padded (I * 128 + J)])
   with
     Pre =>
       Padded'First = 1
       and then I <= (Natural'Last - 128) / 128
       and then I * 128 + 128 <= Padded'Length;

   function Spec_Hash_Blocks
     (S0 : Hash_State; Padded : Octet_Array; N : Natural) return Hash_State
   is
     (if N = 0 then S0
      else Update_Block_Spec
             (Spec_Hash_Blocks (S0, Padded, N - 1),
              Block_At (Padded, N - 1)))
   with
     Pre                =>
       Padded'First = 1
       and then N <= Natural'Last / 128
       and then N * 128 <= Padded'Length,
     Subprogram_Variant => (Decreases => N);

   --  I-th byte of Pad_SHA384 (Input), defined pointwise.
   --  Expression function so gnatprove inlines for congruence threading.
   --  Length field is 16 bytes; high 8 always zero since we cap message
   --  length at 2^61 bytes (FIPS 180-4 §5.1.2).
   function Spec_Pad_Byte_SHA384
     (Input : Octet_Array; I : Positive) return Octet
   is
     (if I <= Input'Length then Input (I)
      elsif I = Input'Length + 1 then 16#80#
      elsif I <= Input'Length + Spec_Pad_Length (Input'Length) - 8 then 0
      else Octet
             (Interfaces.Shift_Right
                (Interfaces.Unsigned_64 (Input'Length) * 8,
                 Natural
                   (8
                    * (Input'Length + Spec_Pad_Length (Input'Length) - I)))
              and 16#FF#))
   with
     Pre =>
       Input'First = 1
       and then Input'Length <= Natural'Last - 17 - 128
       and then I in 1 .. Input'Length + Spec_Pad_Length (Input'Length);

   --  Iterated-aggregate expression function — congruence-friendly.
   function Pad_SHA384 (Input : Octet_Array) return Octet_Array
   is
     ([for I in 1 .. Input'Length + Spec_Pad_Length (Input'Length) =>
         Spec_Pad_Byte_SHA384 (Input, I)])
   with
     Pre  =>
       Input'First = 1 and then Input'Length <= Natural'Last - 17 - 128,
     Post =>
       Pad_SHA384'Result'First = 1
       and then Pad_SHA384'Result'Length
                = Input'Length + Spec_Pad_Length (Input'Length)
       and then Pad_SHA384'Result'Length mod 128 = 0;

   --  I-th BE byte of the finalized digest (first 6 64-bit words emitted).
   function Spec_Finalize_Byte_SHA384
     (S : Hash_State; I : Positive) return Octet
   is
     (Octet
        (Interfaces.Shift_Right
           (S (((I - 1) / 8) + 1),
            Natural (8 * (7 - ((I - 1) mod 8))))
         and 16#FF#))
   with Pre => I in 1 .. 48;

   --  Emit hash state truncated to the first 6 words = 48 bytes.
   --  Mirrors `Spec.Agile.Hash.finish_md` for SHA2_384
   --  (specs/Spec.Agile.Hash.fst:54), which slices `hashw 0..hash_word_length`
   --  with hash_word_length 6 for SHA-384.
   function Finalize_State (S : Hash_State) return Digest
   is ([for I in 1 .. 48 => Spec_Finalize_Byte_SHA384 (S, I)]);

   --  One-shot SHA-384. Expression function so gnatprove inlines it
   --  for proof — congruence on equal inputs follows from substitution
   --  through the composition rather than UF axioms (mirror of
   --  Spec_SHA256 / Spec_Rounds pattern; chacha20 task #107).
   function Spec_SHA384 (Input : Octet_Array) return Digest
   is
     (Finalize_State
        (Spec_Hash_Blocks
           (Initial_State_SHA384,
            Pad_SHA384 (Input),
            (Input'Length + Spec_Pad_Length (Input'Length)) / 128)))
   with Pre => Input'First = 1 and then Input'Length <= Natural'Last - 17 - 128;

   ---------------------------------------------------------------------
   --  Streaming API
   ---------------------------------------------------------------------

   type Context is private;

   procedure Init (Ctx : out Context)
   with Post => Total_Length (Ctx) = 0;

   procedure Update (Ctx : in out Context; Data : Octet_Array)
   with
     Pre  =>
       Total_Length (Ctx)
       <= Interfaces.Unsigned_64'Last - Interfaces.Unsigned_64 (Data'Length)
       and then Data'Last < Integer'Last - Block_Length,
     Post =>
       Total_Length (Ctx)
       = Total_Length (Ctx'Old) + Interfaces.Unsigned_64 (Data'Length);

   procedure Finalize (Ctx : in out Context; Out_Digest : out Digest);

   --  Functional correctness: Out_Digest = Spec_SHA384 (Data).
   procedure Hash (Data : Octet_Array; Out_Digest : out Digest)
   with
     Pre  =>
       Interfaces.Unsigned_64 (Data'Length) <= Interfaces.Unsigned_64'Last / 8
       and then Data'Last < Integer'Last - Block_Length
       and then Data'Length <= Natural'Last - 17 - 128,
     Post => Out_Digest = Spec_SHA384 (Data);

   function Total_Length (Ctx : Context) return Interfaces.Unsigned_64
   with Ghost;

private

   subtype Buf_Length_Type is Natural range 0 .. Block_Length - 1;

   type Context is record
      H         : Hash_State;
      Buf       : Block := [others => 0];
      Buf_Len   : Buf_Length_Type := 0;
      Total_Len : Interfaces.Unsigned_64 := 0;
   end record;

   function Total_Length (Ctx : Context) return Interfaces.Unsigned_64
   is (Ctx.Total_Len);

end Tls_Core.Sha384;
