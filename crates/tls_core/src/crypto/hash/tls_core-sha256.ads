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

   use type Interfaces.Unsigned_64;

   subtype Word is Interfaces.Unsigned_32;

   Block_Length : constant := 64;   --  FIPS §6.2: 512-bit block.
   Hash_Length  : constant := 32;   --  FIPS §6.2: 256-bit digest.

   subtype Block_Index is Positive range 1 .. Block_Length;
   subtype Hash_Index  is Positive range 1 .. Hash_Length;

   subtype Block  is Octet_Array (Block_Index);
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
     (16#6A09_E667#, 16#BB67_AE85#, 16#3C6E_F372#, 16#A54F_F53A#,
      16#510E_527F#, 16#9B05_688C#, 16#1F83_D9AB#, 16#5BE0_CD19#);

   --  Number of bytes appended by FIPS 180-4 §5.1.1 padding to make
   --  the total a multiple of 64 (one 0x80 byte + zeros + 8-byte
   --  length field). Mirrors `Spec.Hash.MD.pad0_length` plus the
   --  fixed bytes (specs/Spec.Hash.MD.fst:30-44).
   function Spec_Pad_Length (N : Natural) return Positive
   is (((119 - (N mod 64)) mod 64) + 9)
   with Pre  => N <= Natural'Last - 9 - 64,
        Post => Spec_Pad_Length'Result in 9 .. 72
                and then (N + Spec_Pad_Length'Result) mod 64 = 0;

   --  Update one 64-byte block on an internal state. Mirrors HACL*
   --  `Spec.SHA2.update_pre` (specs/Spec.SHA2.fst:213).
   function Update_Block_Spec
     (S : Hash_State;
      B : Block) return Hash_State;

   --  Slice the I-th 64-byte block out of a padded message
   --  (0-based block index).
   function Block_At
     (Padded : Octet_Array;
      I      : Natural) return Block
   with
     Pre  => Padded'First = 1
             and then I <= (Natural'Last - 64) / 64
             and then I * 64 + 64 <= Padded'Length;

   --  Fold of Update_Block_Spec over the first N blocks of Padded.
   --  Mirrors HACL* `Lib.UpdateMulti.mk_update_multi` applied to
   --  the SHA2 update function (specs/Spec.Agile.Hash.fst:39).
   function Spec_Hash_Blocks
     (S0     : Hash_State;
      Padded : Octet_Array;
      N      : Natural) return Hash_State
   with
     Pre => Padded'First = 1
            and then N <= Natural'Last / 64
            and then N * 64 <= Padded'Length,
     Subprogram_Variant => (Decreases => N);

   --  Build the Merkle-Damgard padding for a message of length N
   --  bytes (N = Input'Length): Input || 0x80 || zeros || BE64(N*8).
   --  Mirrors `Spec.Hash.MD.pad` (specs/Spec.Hash.MD.fst:30-44).
   function Pad_SHA256 (Input : Octet_Array) return Octet_Array
   with
     Pre  => Input'First = 1
             and then Input'Length <= Natural'Last - 9 - 64,
     Post => Pad_SHA256'Result'First = 1
             and then Pad_SHA256'Result'Length
                       = Input'Length + Spec_Pad_Length (Input'Length)
             and then Pad_SHA256'Result'Length mod 64 = 0;

   --  Emit hash state as 32 BE bytes. Mirrors HACL*
   --  `Spec.Agile.Hash.finish_md` for SHA2_256
   --  (specs/Spec.Agile.Hash.fst:54).
   function Finalize_State (S : Hash_State) return Digest;

   --  One-shot SHA-256: pad, fold compress, emit BE digest.
   --  Mirrors HACL* `Spec.Agile.Hash.hash'` (specs/Spec.Agile.Hash.fst:88)
   --  for SHA2_256.
   function Spec_SHA256 (Input : Octet_Array) return Digest
   with
     Pre => Input'First = 1
            and then Input'Length <= Natural'Last - 9 - 64;

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
       --  Total bytes hashed remains representable in a u64
       --  (FIPS 180-4 §5.1.1 caps the message length at 2**64-1
       --  bits = 2**61 bytes).
       Total_Length (Ctx) <= Interfaces.Unsigned_64'Last
                              - Interfaces.Unsigned_64 (Data'Length)
       --  Body indexes via Data'First + offset; bound the sum so
       --  it stays inside the underlying machine Integer type.
       and then Data'Last < Integer'Last - Block_Length,
     Post =>
       Total_Length (Ctx)
         = Total_Length (Ctx'Old)
           + Interfaces.Unsigned_64 (Data'Length);

   procedure Finalize
     (Ctx        : in out Context;
      Out_Digest : out Digest);

   --  One-shot convenience.
   --
   --  Functional correctness: Out_Digest = Spec_SHA256 (Data) where
   --  Spec_SHA256 is the HACL* SHA2_256 spec ported above. The
   --  body of Hash is a thin wrapper that calls Spec_SHA256 once.
   procedure Hash
     (Data       : Octet_Array;
      Out_Digest : out Digest)
   with
     Pre  => Data'First = 1
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
      Buf       : Block := (others => 0);
      Buf_Len   : Buf_Length_Type := 0;
      Total_Len : Interfaces.Unsigned_64 := 0;
   end record;

   function Total_Length (Ctx : Context) return Interfaces.Unsigned_64
   is (Ctx.Total_Len);

end Tls_Core.Sha256;
