--  Tls_Core.Sha384 — SHA-384 in pure SPARK.
--
--  Source: FIPS 180-4 §6.5 — SHA-384 is SHA-512 with the IVs from
--  §5.3.4 and the digest truncated to the first 384 bits (48 bytes
--  = the first six 64-bit words of the hash state).
--
--  Test vector: FIPS 180-4 §C.2 (also widely available):
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

   --  No functional Post: SHA-384's mathematical content is not
   --  formalized inside this crate. Test vectors from FIPS 180-4
   --  §C.2 in tls_core_tests are the functional check.
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

end Tls_Core.Sha384;
