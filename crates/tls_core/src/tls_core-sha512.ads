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
--  Test vectors: FIPS 180-4 §C ("abc", empty string, the
--  448-bit string).
--
--  This implementation is the FIPS pseudocode by inspection;
--  Tls_Core.Ed25519 (slice to follow) needs SHA-512 for
--  signature verification per RFC 8032 §5.1.7.

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

   --  No functional Post: SHA-512's mathematical content (FIPS 180-4
   --  §6.4) is not formalized inside this crate. Test vectors from
   --  FIPS 180-4 §C.3 in tls_core_tests are the functional check.
   procedure Hash
     (Data       : Octet_Array;
      Out_Digest : out Digest)
   with
     Pre => Interfaces.Unsigned_64 (Data'Length)
            <= Interfaces.Unsigned_64'Last / 8
            and then Data'Last < Integer'Last - Block_Length;

   function Total_Length (Ctx : Context) return Interfaces.Unsigned_64
   with Ghost;

private

   type Hash_State is array (1 .. 8) of Word;

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
