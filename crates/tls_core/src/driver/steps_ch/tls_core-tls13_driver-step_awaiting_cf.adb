with Tls_Core.Aead_Channel;
with Tls_Core.Key_Sched;
with Tls_Core.Tls13_Driver.Helpers; use Tls_Core.Tls13_Driver.Helpers;

package body Tls_Core.Tls13_Driver.Step_Awaiting_Cf
  with SPARK_Mode
is

   procedure Handle
     (D        : in out Driver;
      In_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is
      pragma Unreferenced (Out_Buf, Out_Last);
      Pt_Buf     : Octet_Array (1 .. 1024) := [others => 0];
      Pt_Last    : Natural;
      Inner_Type : Octet;
      OK         : Boolean;
   begin
      Out_Buf := [others => 0];
      Out_Last := 0;

      Tls_Core.Aead_Channel.Receive
        (D.Hs_In_Dir, In_Bytes, Pt_Buf, Pt_Last, Inner_Type, OK);
      if not OK
        or else Inner_Type /= Tls_Core.Aead_Channel.Inner_Type_Handshake
        or else Pt_Last /= 4 + Tls_Core.Key_Sched.Hash_Len (D.Suite)
        or else Pt_Buf (1) /= Hs_Type_Finished
      then
         D.Cur_State := Failed;
         return;
      end if;

      declare
         Diff : Octet := 0;
      begin
         for I in 1 .. Tls_Core.Key_Sched.Hash_Len (D.Suite) loop
            Diff := Diff or (Pt_Buf (4 + I) xor D.Expected_Cf (I));
         end loop;
         if Diff /= 0 then
            D.Cur_State := Failed;
            return;
         end if;
      end;

      Tls_Core.Key_Sched.Transcript_Append
        (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Pt_Buf (1 .. Pt_Last));

      if D.Master_Set then
         declare
            Th_After_Cf : Tls_Core.Key_Sched.Max_Digest;
         begin
            Tls_Core.Key_Sched.Transcript_Snapshot
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_Cf);
            Tls_Core.Key_Sched.Derive_Resumption_Master_Secret
              (Suite             => D.Suite,
               Master_Secret     => D.Master_Sec,
               Th_After_Cf       => Th_After_Cf,
               Resumption_Secret => D.Res_Master_Sec);
            D.Res_Master_Set := True;
         end;
      end if;

      D.Cur_State := Done;
   end Handle;

end Tls_Core.Tls13_Driver.Step_Awaiting_Cf;
