--  Tls_Core.Sha256 — SHA-256 in pure SPARK.
--
--  Source: FIPS 180-4 (Secure Hash Standard) §6.2 — SHA-256.
--
--  Streaming API: Init / Update* / Finalize. One-shot Hash for
--  callers that already have the full message in a single buffer.
--
--  HACL* spec porting (docs/conventions.md §0c): the public one-shot Hash
--  procedure carries a functional Post `Output = Spec_SHA256 (Input)`
--  where Spec_SHA256 is a SPARK port of HACL*'s `Spec.SHA2.fst` for
--  the SHA2_256 algorithm:
--
--    https://github.com/hacl-star/hacl-star/blob/main/specs/Spec.SHA2.fst
--
--  Mirrored constructs: `init` (h256), `_Ch` / `_Maj` / `_Sigma0/1`
--  / `_sigma0/1` (specs/Spec.SHA2.fst:113-138), `shuffle_core_pre_`
--  (line 154), `ws_pre_inner` (line 175-189), `shuffle_pre`
--  (line 195), `update_pre` (line 213). Padding from
--  `Spec.Hash.MD.fst` `pad` (line 30-44). Constants from
--  `Spec.SHA2.Constants.fst` (h256, k224_256). The streaming
--  Init/Update/Finalize is imperatively structured; only the
--  one-shot Hash carries the functional Post — proving the streaming
--  API equivalent to the one-shot spec requires lemma machinery
--  beyond v0.5 scope.

with Interfaces;

package Tls_Core.Sha256
  with SPARK_Mode
is

   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

   subtype Word is Interfaces.Unsigned_32;

   Block_Length : constant := 64;   --  FIPS §6.2: 512-bit block.
   Hash_Length  : constant := 32;   --  FIPS §6.2: 256-bit digest.

   subtype Block_Index is Positive range 1 .. Block_Length;
   subtype Hash_Index is Positive range 1 .. Hash_Length;

   subtype Block is Octet_Array (Block_Index);
   subtype Digest is Octet_Array (Hash_Index);

   ---------------------------------------------------------------------
   --  HACL* Spec.SHA2 port — exposed in the public spec because the
   --  Post on Hash references Spec_SHA256. Bodies in the package
   --  body. These are real (executable) SPARK functions, not
   --  ghost stubs (docs/conventions.md §0d clause 4).
   ---------------------------------------------------------------------

   type Hash_State is array (1 .. 8) of Word;

   --  Mirrors `Spec.SHA2.Constants.h256` (lib/Spec.SHA2.Constants.fst:60).
   Initial_State_SHA256 : constant Hash_State :=
     [16#6A09_E667#,
      16#BB67_AE85#,
      16#3C6E_F372#,
      16#A54F_F53A#,
      16#510E_527F#,
      16#9B05_688C#,
      16#1F83_D9AB#,
      16#5BE0_CD19#];

   --  Number of bytes appended by FIPS 180-4 §5.1.1 padding to make
   --  the total a multiple of 64 (one 0x80 byte + zeros + 8-byte
   --  length field). Mirrors `Spec.Hash.MD.pad0_length` plus the
   --  fixed bytes (specs/Spec.Hash.MD.fst:30-44).
   function Spec_Pad_Length (N : Natural) return Positive
   is (((119 - (N mod 64)) mod 64) + 9)
   with
     Pre  => N <= Natural'Last - 9 - 64,
     Post =>
       Spec_Pad_Length'Result in 9 .. 72
       and then (N + Spec_Pad_Length'Result) mod 64 = 0;

   ---------------------------------------------------------------------
   --  FIPS 180-4 §4.1.2 / §4.2.2 — bit-mixing primitives and K table.
   --  All expression functions so gnatprove inlines them, enabling UF
   --  congruence to thread through Update_Block_Spec on equal inputs
   --  (RSA-PSS / ECDSA / Ed25519 Verify-Post pattern).
   ---------------------------------------------------------------------

   function ROTR (X : Word; N : Natural) return Word
   is (Interfaces.Shift_Right (X, N) or Interfaces.Shift_Left (X, 32 - N))
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
   is (ROTR (X, 7) xor ROTR (X, 18) xor Interfaces.Shift_Right (X, 3));

   function Small_Sigma_1 (X : Word) return Word
   is (ROTR (X, 17) xor ROTR (X, 19) xor Interfaces.Shift_Right (X, 10));

   function BE_Word (B : Block; Offset : Block_Index) return Word
   is (Interfaces.Shift_Left (Word (B (Offset)), 24)
       or Interfaces.Shift_Left (Word (B (Offset + 1)), 16)
       or Interfaces.Shift_Left (Word (B (Offset + 2)), 8)
       or Word (B (Offset + 3)))
   with Pre => Offset <= Block_Length - 3;

   K : constant array (0 .. 63) of Word :=
     [16#428A_2F98#, 16#7137_4491#, 16#B5C0_FBCF#, 16#E9B5_DBA5#,
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
      16#90BE_FFFA#, 16#A450_6CEB#, 16#BEF9_A3F7#, 16#C671_78F2#];

   --  Recursive message schedule (HACL* ws_pre, Spec.SHA2.fst:175-200).
   function Spec_W_SHA256 (B : Block; I : Natural) return Word
   is
     (if I <= 15
      then BE_Word (B, 1 + 4 * I)
      else Small_Sigma_1 (Spec_W_SHA256 (B, I - 2))
           + Spec_W_SHA256 (B, I - 7)
           + Small_Sigma_0 (Spec_W_SHA256 (B, I - 15))
           + Spec_W_SHA256 (B, I - 16))
   with
     Pre                => I <= 63,
     Subprogram_Variant => (Decreases => I);

   --  One round (HACL* shuffle_core_pre_, Spec.SHA2.fst:154).
   --
   --  T1/T2 extracted as separate expression functions rather than
   --  declare-expression locals — GNAT 14's -gnatwu doesn't trace
   --  usage through Ada 2022 declare-expression begin clauses and
   --  raises a spurious "not referenced" warning we'd otherwise need
   --  to suppress (against §151 — no suppressions).
   function Round_T1
     (S : Hash_State; W_I, K_I : Word) return Word
   is (S (8) + Big_Sigma_1 (S (5)) + Ch (S (5), S (6), S (7)) + K_I + W_I);

   function Round_T2 (S : Hash_State) return Word
   is (Big_Sigma_0 (S (1)) + Maj (S (1), S (2), S (3)));

   function One_Round_SHA256
     (S : Hash_State; W_I, K_I : Word) return Hash_State
   is ([1 => Round_T1 (S, W_I, K_I) + Round_T2 (S),
        2 => S (1),
        3 => S (2),
        4 => S (3),
        5 => S (4) + Round_T1 (S, W_I, K_I),
        6 => S (5),
        7 => S (6),
        8 => S (7)]);

   --  Apply the first N rounds.
   function Spec_Shuffle_SHA256
     (S : Hash_State; B : Block; N : Natural) return Hash_State
   is
     (if N = 0
      then S
      else One_Round_SHA256
             (Spec_Shuffle_SHA256 (S, B, N - 1),
              Spec_W_SHA256 (B, N - 1),
              K (N - 1)))
   with
     Pre                => N <= 64,
     Subprogram_Variant => (Decreases => N);

   --  Update one 64-byte block on an internal state. Mirrors HACL*
   --  `Spec.SHA2.update_pre` (specs/Spec.SHA2.fst:213).
   --  Expression function — gnatprove inlines for congruence threading.
   function Update_Block_Spec (S : Hash_State; B : Block) return Hash_State
   is ([for I in 1 .. 8 => S (I) + Spec_Shuffle_SHA256 (S, B, 64) (I)]);

   --  Slice the I-th 64-byte block out of a padded message
   --  (0-based block index). Expression function — congruence threads.
   function Block_At (Padded : Octet_Array; I : Natural) return Block
   is ([for J in Block_Index => Padded (I * 64 + J)])
   with
     Pre =>
       Padded'First = 1
       and then I <= (Natural'Last - 64) / 64
       and then I * 64 + 64 <= Padded'Length;

   --  Fold of Update_Block_Spec over the first N blocks of Padded.
   --  Mirrors HACL* `Lib.UpdateMulti.mk_update_multi` applied to
   --  the SHA2 update function (specs/Spec.Agile.Hash.fst:39).
   --
   --  Recursive expression function with explicit Subprogram_Variant
   --  for termination. Expression-function form lets gnatprove inline
   --  it for proof — congruence on equal (S0, Padded, N) follows by
   --  inductive substitution through the if-then-else.
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
       and then N <= Natural'Last / 64
       and then N * 64 <= Padded'Length,
     Subprogram_Variant => (Decreases => N);

   --  I-th byte of Pad_SHA256 (Input), defined pointwise via the FIPS
   --  Merkle-Damgard padding rule. Expression function so gnatprove
   --  inlines and substitutes through equal Inputs.
   function Spec_Pad_Byte_SHA256
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
       and then Input'Length <= Natural'Last - 9 - 64
       and then I in 1 .. Input'Length + Spec_Pad_Length (Input'Length);

   --  Build the Merkle-Damgard padding for a message of length N
   --  bytes (N = Input'Length): Input || 0x80 || zeros || BE64(N*8).
   --  Mirrors `Spec.Hash.MD.pad` (specs/Spec.Hash.MD.fst:30-44).
   --
   --  Expression function via iterated aggregate so gnatprove inlines
   --  it — Pad_SHA256 (X) congruence on equal X, Y follows by per-byte
   --  substitution through Spec_Pad_Byte_SHA256 (also an expression
   --  function). Closes the SHA congruence chain.
   function Pad_SHA256 (Input : Octet_Array) return Octet_Array
   is
     ([for I in 1 .. Input'Length + Spec_Pad_Length (Input'Length) =>
         Spec_Pad_Byte_SHA256 (Input, I)])
   with
     Pre  => Input'First = 1 and then Input'Length <= Natural'Last - 9 - 64,
     Post =>
       Pad_SHA256'Result'First = 1
       and then Pad_SHA256'Result'Length
                = Input'Length + Spec_Pad_Length (Input'Length)
       and then Pad_SHA256'Result'Length mod 64 = 0;

   --  I-th BE byte of the finalized digest. Expression function.
   function Spec_Finalize_Byte_SHA256
     (S : Hash_State; I : Positive) return Octet
   is
     (Octet
        (Interfaces.Shift_Right
           (S (((I - 1) / 4) + 1),
            Natural (8 * (3 - ((I - 1) mod 4))))
         and 16#FF#))
   with Pre => I in 1 .. 32;

   --  Emit hash state as 32 BE bytes. Mirrors HACL*
   --  `Spec.Agile.Hash.finish_md` for SHA2_256
   --  (specs/Spec.Agile.Hash.fst:54).
   --  Iterated-aggregate expression function — congruence threads.
   function Finalize_State (S : Hash_State) return Digest
   is ([for I in 1 .. 32 => Spec_Finalize_Byte_SHA256 (S, I)]);

   --  One-shot SHA-256: pad, fold compress, emit BE digest.
   --  Mirrors HACL* `Spec.Agile.Hash.hash'` (specs/Spec.Agile.Hash.fst:88)
   --  for SHA2_256.
   --
   --  Defined as an expression function so gnatprove inlines it for
   --  proof — callers of Spec_SHA256 see the explicit composition
   --  Finalize_State (Spec_Hash_Blocks (Initial_State, Pad_SHA256 (Input),
   --  N_Blocks)), which lets congruence on equal Inputs thread through
   --  by substitution rather than depending on UF congruence (which
   --  gnatprove's Why3 encoding does not expose on Post-bearing
   --  functions). Same idiom as chacha20's Spec_Rounds (task #107).
   function Spec_SHA256 (Input : Octet_Array) return Digest
   is
     (Finalize_State
        (Spec_Hash_Blocks
           (Initial_State_SHA256,
            Pad_SHA256 (Input),
            (Input'Length + Spec_Pad_Length (Input'Length)) / 64)))
   with Pre => Input'First = 1 and then Input'Length <= Natural'Last - 9 - 64;

   ---------------------------------------------------------------------
   --  Streaming API
   ---------------------------------------------------------------------

   type Context is private;

   procedure Init (Ctx : out Context)
   with Post => Total_Length (Ctx) = 0;

   procedure Update (Ctx : in out Context; Data : Octet_Array)
   with
     Pre  =>
       --  Total bytes hashed remains representable in a u64
       --  (FIPS 180-4 §5.1.1 caps the message length at 2**64-1
       --  bits = 2**61 bytes).
       Total_Length (Ctx)
       <= Interfaces.Unsigned_64'Last - Interfaces.Unsigned_64 (Data'Length)
       --  Body indexes via Data'First + offset; bound the sum so
       --  it stays inside the underlying machine Integer type.
       and then Data'Last < Integer'Last - Block_Length,
     Post =>
       Total_Length (Ctx)
       = Total_Length (Ctx'Old) + Interfaces.Unsigned_64 (Data'Length);

   procedure Finalize (Ctx : in out Context; Out_Digest : out Digest);

   --  One-shot convenience.
   --
   --  Functional correctness: Out_Digest = Spec_SHA256 (Data) where
   --  Spec_SHA256 is the HACL* SHA2_256 spec ported above. The
   --  body of Hash is a thin wrapper that calls Spec_SHA256 once.
   procedure Hash (Data : Octet_Array; Out_Digest : out Digest)
   with
     Pre  =>
       Data'First = 1
       and then Interfaces.Unsigned_64 (Data'Length)
                <= Interfaces.Unsigned_64'Last / 8
       and then Data'Last < Integer'Last - Block_Length
       and then Data'Length <= Natural'Last - 9 - 64,
     Post => Out_Digest = Spec_SHA256 (Data);

   --  Ghost accessor for total bytes consumed so far (used by the
   --  Pre on Update).
   function Total_Length (Ctx : Context) return Interfaces.Unsigned_64
   with Ghost;

private

   --  Buf_Len is "bytes pending in Buf"; by the streaming-update
   --  invariant it is always strictly less than Block_Length —
   --  whenever Buf fills, Update calls Process_Block and resets
   --  Buf_Len to zero.
   subtype Buf_Length_Type is Natural range 0 .. Block_Length - 1;

   type Context is record
      H         : Hash_State;
      Buf       : Block := [others => 0];
      Buf_Len   : Buf_Length_Type := 0;
      Total_Len : Interfaces.Unsigned_64 := 0;
   end record;

   function Total_Length (Ctx : Context) return Interfaces.Unsigned_64
   is (Ctx.Total_Len);

end Tls_Core.Sha256;
