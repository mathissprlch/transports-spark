package body Tls_Core.Transcript
with SPARK_Mode
is

   procedure Init (T : out Accumulator) is
   begin
      Tls_Core.Sha256.Init (T.Ctx);
   end Init;

   procedure Append
     (T       : in out Accumulator;
      Message : Octet_Array)
   is
   begin
      Tls_Core.Sha256.Update (T.Ctx, Message);
   end Append;

   procedure Snapshot
     (T          : Accumulator;
      Out_Digest : out Tls_Core.Sha256.Digest)
   is
      --  Finalize works on a context, but we want to preserve T.
      --  Copy into a local first, then finalize the copy.
      Local : Tls_Core.Sha256.Context := T.Ctx;
   begin
      Tls_Core.Sha256.Finalize (Local, Out_Digest);
   end Snapshot;

end Tls_Core.Transcript;
