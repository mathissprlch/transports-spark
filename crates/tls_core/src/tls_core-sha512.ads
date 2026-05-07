--  Tls_Core.Sha512 — SHA-512 in pure SPARK.
--
--  Source: FIPS 180-4 (Secure Hash Standard) §6.4 — SHA-512.
--
--  Same overall shape as Tls_Core.Sha256 (Init / Update / Finalize
--  + one-shot Hash) but with 64-bit words, 80 rounds, 128-byte
--  blocks, and 64-byte digests. Different rotation amounts in the
--  six bit-mixing functions (FIPS §4.1.3) and a different
--  round-constant table (§4.2.3).
--
--  HACL* spec porting (CLAUDE.md §0c): the public one-shot Hash
--  procedure carries `Output = Spec_SHA512 (Data)`. Spec_SHA512 is
--  a SPARK port of HACL*'s `Spec.SHA2.fst` for SHA2_512:
--
--    https://github.com/hacl-star/hacl-star/blob/main/specs/Spec.SHA2.fst
--
--  Mirrored constructs match the SHA-256 port; the only differences
--  are word width (U32 -> U64), block size (64 -> 128), round count
--  (64 -> 80), the rotation-amount table `op384_512`
--  (specs/Spec.SHA2.fst:54), constants `h512` / `k384_512`
--  (lib/Spec.SHA2.Constants.fst:96/27), and the length-field width
--  (8 bytes -> 16 bytes) in the Merkle-Damgard padding.
--
--  Test vectors: FIPS 180-4 §C ("abc", empty string, the 448-bit
--  string). Tls_Core.Ed25519 needs SHA-512 for signature verification
--  per RFC 8032 §5.1.7.

with Interfaces;

package Tls_Core.Sha512
with SPARK_Mode
is

   use type Interfaces.Unsigned_64;

   subtype Word is Interfaces.Unsigned_64;

   Block_Length : constant := 128;   --  FIPS §6.4: 1024-bit block.
   Hash_Length  : constant := 64;    --  FIPS §6.4: 512-bit digest.

   subtype Block_Index is Positive range 1 .. Block_Length;
   subtype Hash_Index  is Positive range 1 .. Hash_Length;

   subtype Block  is Octet_Array (Block_Index);
   subtype Digest is Octet_Array (Hash_Index);

   ---------------------------------------------------------------------
   --  HACL* Spec.SHA2 port — exposed in the public spec because the
   --  Post on Hash references Spec_SHA512.
   ---------------------------------------------------------------------

   type Hash_State is array (1 .. 8) of Word;

   --  Mirrors `Spec.SHA2.Constants.h512` (lib/Spec.SHA2.Constants.fst:96).
   Initial_State_SHA512 : constant Hash_State :=
     (16#6A09_E667_F3BC_C908#, 16#BB67_AE85_84CA_A73B#,
      16#3C6E_F372_FE94_F82B#, 16#A54F_F53A_5F1D_36F1#,
      16#510E_527F_ADE6_82D1#, 16#9B05_688C_2B3E_6C1F#,
      16#1F83_D9AB_FB41_BD6B#, 16#5BE0_CD19_137E_2179#);

   --  Number of bytes appended by FIPS 180-4 §5.1.2 padding: one
   --  0x80 byte + zeros + 16-byte length field, total a multiple
   --  of 128. Mirrors `Spec.Hash.MD.pad0_length` plus the fixed
   --  bytes (specs/Spec.Hash.MD.fst:30-44, with len_length 16
   --  for SHA-512).
   function Spec_Pad_Length (N : Natural) return Positive
   is (((239 - (N mod 128)) mod 128) + 17)
   with Pre  => N <= Natural'Last - 17 - 128,
        Post => Spec_Pad_Length'Result in 17 .. 144
                and then (N + Spec_Pad_Length'Result) mod 128 = 0;

   --  Update one 128-byte block on an internal state. Mirrors HACL*
   --  `Spec.SHA2.update_pre` (specs/Spec.SHA2.fst:213) for SHA2_512.
   function Update_Block_Spec
     (S : Hash_State;
      B : Block) return Hash_State;

   --  Slice the I-th 128-byte block (0-based).
   function Block_At
     (Padded : Octet_Array;
      I      : Natural) return Block
   with
     Pre => Padded'First = 1
            and then I <= (Natural'Last - 128) / 128
            and then I * 128 + 128 <= Padded'Length;

   --  Fold of Update_Block_Spec over the first N blocks. Mirrors
   --  HACL* `Lib.UpdateMulti.mk_update_multi` for SHA2_512
   --  (specs/Spec.Agile.Hash.fst:39).
   function Spec_Hash_Blocks
     (S0     : Hash_State;
      Padded : Octet_Array;
      N      : Natural) return Hash_State
   with
     Pre => Padded'First = 1
            and then N <= Natural'Last / 128
            and then N * 128 <= Padded'Length,
     Subprogram_Variant => (Decreases => N);

   --  Build the Merkle-Damgard padding for a SHA-512 message of
   --  length N bytes. Mirrors `Spec.Hash.MD.pad`
   --  (specs/Spec.Hash.MD.fst:30-44). The length field is 128 bits
   --  big-endian; we track only 64 bits (an Interfaces.Unsigned_64),
   --  so the upper 64 bits are always zero.
   function Pad_SHA512 (Input : Octet_Array) return Octet_Array
   with
     Pre  => Input'First = 1
             and then Input'Length <= Natural'Last - 17 - 128,
     Post => Pad_SHA512'Result'First = 1
             and then Pad_SHA512'Result'Length
                       = Input'Length + Spec_Pad_Length (Input'Length)
             and then Pad_SHA512'Result'Length mod 128 = 0;

   --  Emit hash state as 64 BE bytes. Mirrors HACL*
   --  `Spec.Agile.Hash.finish_md` for SHA2_512
   --  (specs/Spec.Agile.Hash.fst:54).
   function Finalize_State (S : Hash_State) return Digest;

   --  One-shot SHA-512: pad, fold compress, emit BE digest.
   --  Mirrors HACL* `Spec.Agile.Hash.hash'` (specs/Spec.Agile.Hash.fst:88)
   --  for SHA2_512.
   function Spec_SHA512 (Input : Octet_Array) return Digest
   with
     Pre => Input'First = 1
            and then Input'Length <= Natural'Last - 17 - 128;

   ---------------------------------------------------------------------
   --  Streaming API
   ---------------------------------------------------------------------

   type Context is private;

   procedure Init (Ctx : out Context)
   with
     Post => Total_Length (Ctx) = 0;

   procedure Update
     (Ctx  : in out Context;
      Data : Octet_Array)
   with
     Pre =>
       Total_Length (Ctx) <= Interfaces.Unsigned_64'Last
                              - Interfaces.Unsigned_64 (Data'Length)
       and then Data'Last < Integer'Last - Block_Length,
     Post =>
       Total_Length (Ctx)
         = Total_Length (Ctx'Old)
           + Interfaces.Unsigned_64 (Data'Length);

   procedure Finalize
     (Ctx        : in out Context;
      Out_Digest : out Digest);

   --  Functional correctness: Out_Digest = Spec_SHA512 (Data).
   procedure Hash
     (Data       : Octet_Array;
      Out_Digest : out Digest)
   with
     Pre  => Data'First = 1
             and then Interfaces.Unsigned_64 (Data'Length)
                      <= Interfaces.Unsigned_64'Last / 8
             and then Data'Last < Integer'Last - Block_Length
             and then Data'Length <= Natural'Last - 17 - 128,
     Post => Out_Digest = Spec_SHA512 (Data);

   function Total_Length (Ctx : Context) return Interfaces.Unsigned_64
   with Ghost;

private

   subtype Buf_Length_Type is Natural range 0 .. Block_Length - 1;

   type Context is record
      H         : Hash_State;
      Buf       : Block := (others => 0);
      Buf_Len   : Buf_Length_Type := 0;
      Total_Len : Interfaces.Unsigned_64 := 0;
   end record;

   function Total_Length (Ctx : Context) return Interfaces.Unsigned_64
   is (Ctx.Total_Len);

end Tls_Core.Sha512;
