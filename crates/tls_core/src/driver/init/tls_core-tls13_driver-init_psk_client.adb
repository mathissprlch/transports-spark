separate (Tls_Core.Tls13_Driver)
procedure Init_Psk_Client
  (D            : out Driver;
   PSK          : Octet_Array;
   Psk_Identity : Octet_Array;
   Ecdhe_Priv   : Octet_Array)
is
   Priv_32 : Tls_Core.X25519.Bytes_32;
   Pub_32  : Tls_Core.X25519.Bytes_32;
begin
   D.My_Role := Client;
   D.Cur_State := Idle;
   Tls_Core.Transcript.Init (D.Hash_Ctx);
   Tls_Core.Transcript_Sha384.Init (D.Hash_Ctx_384);
   D.PSK := [others => 0];
   D.PSK := PSK;
   D.Identity := [others => 0];
   D.Identity_Len := Psk_Identity'Length;
   D.Identity (1 .. Psk_Identity'Length) := Psk_Identity;
   D.App_Set := False;
   Prime_Driver_Defaults (D);
   D.Hrr_Demand := False;
   D.Hrr_Sent := False;
   D.Hrr_Aware := False;
   D.Hrr_Seen := False;
   D.Hrr_Group := Tls_Core.Suites.Group_Secp256r1;
   D.Hrr_Cookie := [others => 0];
   D.Hrr_Cookie_Len := 0;
   D.Hrr_Ch1_Hash := [others => 0];
   Tls_Core.Handshake_Buffer.Init (D.Hs_In_Buf);

   Priv_32 := Ecdhe_Priv;
   Tls_Core.X25519.Derive_Public (Priv_32, Pub_32);
   D.My_Ecdhe_Priv := Priv_32;
   D.My_Ecdhe_Pub := Pub_32;
   D.Peer_Ecdhe_Pub := [others => 0];
   D.Ecdhe_Shared := [others => 0];
end Init_Psk_Client;
