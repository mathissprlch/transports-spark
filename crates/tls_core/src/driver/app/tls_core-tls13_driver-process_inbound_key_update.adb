separate (Tls_Core.Tls13_Driver)
procedure Process_Inbound_Key_Update
  (D            : Driver;
   In_Plaintext : Octet_Array;
   In_Dir       : in out Tls_Core.Aead_Channel.Direction;
   Recv_Secret  : in out Tls_Core.Key_Sched.Max_Secret;
   Want_Reply   : out Boolean;
   OK           : out Boolean)
is
   pragma Unreferenced (D);
   Request_Update : Octet;
   Decode_OK      : Boolean;
   Next_Secret    : Tls_Core.Key_Sched.Max_Secret := [others => 0];
begin
   Want_Reply := False;
   OK := False;
   Tls_Core.Key_Update.Decode (In_Plaintext, Request_Update, Decode_OK);
   if not Decode_OK then
      return;
   end if;

   --  Rotate the peer-side decrypt key per §7.2.
   Tls_Core.Key_Update.Derive_Next_Sha256
     (Recv_Secret (1 .. 32), Next_Secret (1 .. 32));
   Recv_Secret := Next_Secret;
   Tls_Core.Aead_Channel.Rotate_Sha256 (In_Dir, Recv_Secret (1 .. 32));

   Want_Reply := Request_Update = Tls_Core.Key_Update.Update_Requested;
   OK := True;
end Process_Inbound_Key_Update;
