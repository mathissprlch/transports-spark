--  Tls_Core.Sha384 — SHA-384 in pure SPARK.
--
--  Source: FIPS 180-4 §6.5 — SHA-384 is SHA-512 with the IVs from
--  §5.3.4 and the digest truncated to the first 384 bits (48 bytes
--  = the first six 64-bit words of the hash state).
--
--  HACL* spec porting (CLAUDE.md §0c): the public one-shot Hash
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
   subtype Hash_Index  is Positive range 1 .. Hash_Length;

   subtype Block  is Octet_Array (Block_Index);
   subtype Digest is Octet_Array (Hash_Index);

   ---------------------------------------------------------------------
   --  HACL* Spec.SHA2 port — SHA-384 differs from SHA-512 only in
   --  the initial state and the digest truncation.
   ---------------------------------------------------------------------

   type Hash_State is array (1 .. 8) of Word;

   --  Mirrors `Spec.SHA2.Constants.h384` (lib/Spec.SHA2.Constants.fst:80).
   Initial_State_SHA384 : constant Hash_State :=
     (16#CBBB_9D5D_C105_9ED8#, 16#629A_292A_367C_D507#,
      16#9159_015A_3070_DD17#, 16#152F_ECD8_F70E_5939#,
      16#6733_2667_FFC0_0B31#, 16#8EB4_4A87_6858_1511#,
      16#DB0C_2E0D_64F9_8FA7#, 16#47B5_481D_BEFA_4FA4#);

   --  Same MD padding scheme as SHA-512 (128-byte block, 16-byte
   --  length field) — Spec.Hash.MD.pad (specs/Spec.Hash.MD.fst:30-44).
   function Spec_Pad_Length (N : Natural) return Positive
   is (((239 - (N mod 128)) mod 128) + 17)
   with Pre  => N <= Natural'Last - 17 - 128,
        Post => Spec_Pad_Length'Result in 17 .. 144
                and then (N + Spec_Pad_Length'Result) mod 128 = 0;

   --  Same compression function as SHA-512 (Spec.SHA2.fst:213).
   function Update_Block_Spec
     (S : Hash_State;
      B : Block) return Hash_State;

   function Block_At
     (Padded : Octet_Array;
      I      : Natural) return Block
   with
     Pre => Padded'First = 1
            and then I <= (Natural'Last - 128) / 128
            and then I * 128 + 128 <= Padded'Length;

   function Spec_Hash_Blocks
     (S0     : Hash_State;
      Padded : Octet_Array;
      N      : Natural) return Hash_State
   with
     Pre => Padded'First = 1
            and then N <= Natural'Last / 128
            and then N * 128 <= Padded'Length,
     Subprogram_Variant => (Decreases => N);

   function Pad_SHA384 (Input : Octet_Array) return Octet_Array
   with
     Pre  => Input'First = 1
             and then Input'Length <= Natural'Last - 17 - 128,
     Post => Pad_SHA384'Result'First = 1
             and then Pad_SHA384'Result'Length
                       = Input'Length + Spec_Pad_Length (Input'Length)
             and then Pad_SHA384'Result'Length mod 128 = 0;

   --  Emit hash state truncated to the first 6 words = 48 bytes.
   --  Mirrors `Spec.Agile.Hash.finish_md` for SHA2_384
   --  (specs/Spec.Agile.Hash.fst:54), which slices `hashw 0..hash_word_length`
   --  with hash_word_length 6 for SHA-384.
   function Finalize_State (S : Hash_State) return Digest;

   --  One-shot SHA-384.
   function Spec_SHA384 (Input : Octet_Array) return Digest
   with
     Pre => Input'First = 1
            and then Input'Length <= Natural'Last - 17 - 128;

   ---------------------------------------------------------------------
   --  Streaming API
   ---------------------------------------------------------------------

   type Context is private;

   procedure Init (Ctx : out Context)
   with Post => Total_Length (Ctx) = 0;

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

   --  Functional correctness: Out_Digest = Spec_SHA384 (Data).
   procedure Hash
     (Data       : Octet_Array;
      Out_Digest : out Digest)
   with
     Pre  => Data'First = 1
             and then Interfaces.Unsigned_64 (Data'Length)
                      <= Interfaces.Unsigned_64'Last / 8
             and then Data'Last < Integer'Last - Block_Length
             and then Data'Length <= Natural'Last - 17 - 128,
     Post => Out_Digest = Spec_SHA384 (Data);

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

end Tls_Core.Sha384;
