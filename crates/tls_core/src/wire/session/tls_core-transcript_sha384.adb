package body Tls_Core.Transcript_Sha384
  with SPARK_Mode
is

   procedure Init (T : out Accumulator) is
   begin
      Tls_Core.Sha384.Init (T.Ctx);
   end Init;

   procedure Append (T : in out Accumulator; Message : Octet_Array) is
   begin
      Tls_Core.Sha384.Update (T.Ctx, Message);
   end Append;

   procedure Snapshot
     (T : Accumulator; Out_Digest : out Tls_Core.Sha384.Digest)
   is
      Local : Tls_Core.Sha384.Context := T.Ctx;
   begin
      Tls_Core.Sha384.Finalize (Local, Out_Digest);
   end Snapshot;

end Tls_Core.Transcript_Sha384;
