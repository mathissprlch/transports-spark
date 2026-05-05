--  Tls_Core.Sha256 — SHA-256 in pure SPARK.
--
--  Source: FIPS 180-4 (Secure Hash Standard) §6.2 — SHA-256.
--
--  Streaming API: Init / Update* / Finalize. One-shot Hash for
--  callers that already have the full message in a single buffer.
--  Functional correctness is "by inspection equal to the FIPS
--  pseudocode" — see the body for the Σ/σ/Ch/Maj definitions
--  matching FIPS 180-4 §4.1.2 and the round-constant table from
--  §4.2.2. Test vectors in tls_core_tests cover FIPS 180-4
--  Appendix B (empty string, "abc", and the 448-bit string).
--
--  miTLS reference (project-everest/mitls-fstar):
--    miTLS itself does not implement SHA-256 in F\*; it imports
--    HACL\*'s `Hash.Definitions.Spec.SHA2_256` (a pure functional
--    spec) and `EverCrypt.Hash.Incremental` (the optimized
--    implementation). For our pure-Ada path we re-implement the
--    FIPS pseudocode directly; the spec/implementation separation
--    HACL\* maintains is what licenses miTLS' upper layers to
--    treat SHA-256 as opaque.

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
                              - Interfaces.Unsigned_64 (Data'Length),
     Post =>
       Total_Length (Ctx)
         = Total_Length (Ctx'Old)
           + Interfaces.Unsigned_64 (Data'Length);

   procedure Finalize
     (Ctx        : in out Context;
      Out_Digest : out Digest);

   --  One-shot convenience.
   procedure Hash
     (Data       : Octet_Array;
      Out_Digest : out Digest)
   with
     Pre => Interfaces.Unsigned_64 (Data'Length)
            <= Interfaces.Unsigned_64'Last / 8;

   --  Ghost accessor for total bytes consumed so far (used by the
   --  Pre on Update).
   function Total_Length (Ctx : Context) return Interfaces.Unsigned_64
   with Ghost;

private

   type Hash_State is array (1 .. 8) of Word;

   type Context is record
      H         : Hash_State;
      Buf       : Block := (others => 0);
      Buf_Len   : Natural := 0;
      Total_Len : Interfaces.Unsigned_64 := 0;
   end record;

   function Total_Length (Ctx : Context) return Interfaces.Unsigned_64
   is (Ctx.Total_Len);

end Tls_Core.Sha256;
