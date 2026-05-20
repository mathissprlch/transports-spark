separate (Tls_Core.Tls13_Driver)
procedure Send_Key_Update
  (D              : Driver;
   Out_Dir        : in out Tls_Core.Aead_Channel.Direction;
   Send_Secret    : in out Tls_Core.Key_Sched.Max_Secret;
   Request_Update : Octet;
   Out_Buf        : out Octet_Array;
   Out_Last       : out Natural)
is
   pragma Unreferenced (D);
   Ku_Msg      : Octet_Array (1 .. Tls_Core.Key_Update.Wire_Size) :=
     [others => 0];
   Ku_Last     : Natural;
   Next_Secret : Tls_Core.Key_Sched.Max_Secret := [others => 0];
begin
   Out_Buf := [others => 0];
   Out_Last := 0;

   --  1. Build the KeyUpdate handshake message (5 bytes total).
   Tls_Core.Key_Update.Encode (Request_Update, Ku_Msg, Ku_Last);

   --  2. Encrypt under the current send key as one record. The
   --     inner content type is "handshake" (post-handshake
   --     messages keep the handshake content type per §4.6).
   Tls_Core.Aead_Channel.Send
     (Out_Dir,
      Ku_Msg (1 .. Ku_Last),
      Tls_Core.Aead_Channel.Inner_Type_Handshake,
      Out_Buf,
      Out_Last);

   --  3. Derive the next traffic secret per §7.2 and rotate the
   --     local send key + IV + sequence counter.
   Tls_Core.Key_Update.Derive_Next_Sha256
     (Send_Secret (1 .. 32), Next_Secret (1 .. 32));
   Send_Secret := Next_Secret;
   Tls_Core.Aead_Channel.Rotate_Sha256 (Out_Dir, Send_Secret (1 .. 32));
end Send_Key_Update;
