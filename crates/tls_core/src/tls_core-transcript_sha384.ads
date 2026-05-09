with Interfaces;
with Tls_Core.Sha384;

package Tls_Core.Transcript_Sha384
with SPARK_Mode
is

   use type Interfaces.Unsigned_64;

   type Accumulator is private;

   procedure Init (T : out Accumulator);

   procedure Append
     (T       : in out Accumulator;
      Message : Octet_Array)
   with Pre =>
       Tls_Core.Sha384.Total_Length (Inner (T))
         <= Interfaces.Unsigned_64'Last
            - Interfaces.Unsigned_64 (Message'Length)
       and then Message'Last < Integer'Last - Tls_Core.Sha384.Block_Length;

   procedure Snapshot
     (T          : Accumulator;
      Out_Digest : out Tls_Core.Sha384.Digest);

   function Inner (T : Accumulator) return Tls_Core.Sha384.Context
   with Ghost;

private

   type Accumulator is record
      Ctx : Tls_Core.Sha384.Context;
   end record;

   function Inner (T : Accumulator) return Tls_Core.Sha384.Context
   is (T.Ctx);

end Tls_Core.Transcript_Sha384;
