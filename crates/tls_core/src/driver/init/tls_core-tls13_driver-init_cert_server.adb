separate (Tls_Core.Tls13_Driver)
procedure Init_Cert_Server
  (D                : out Driver;
   Cert_Chain_Bytes : Octet_Array;
   Chain_Spec       : Tls_Core.Cert_Chain.Chain;
   Sign_Priv_Key    : Octet_Array;
   Sig_Alg          : Tls_Core.Suites.U16;
   Ecdhe_Priv       : Octet_Array)
is
   Priv_32 : Tls_Core.X25519.Bytes_32;
   Pub_32  : Tls_Core.X25519.Bytes_32;
begin
   D.My_Role := Server;
   D.Cur_State := Awaiting_CH;
   Tls_Core.Transcript.Init (D.Hash_Ctx);
   Tls_Core.Transcript_Sha384.Init (D.Hash_Ctx_384);
   D.PSK := [others => 0];
   D.Identity := [others => 0];
   D.Identity_Len := 0;
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

   D.Mode := Cert_Mode;
   D.Cert_Chain_Bytes := [others => 0];
   D.Cert_Chain_Bytes (1 .. Cert_Chain_Bytes'Length) := Cert_Chain_Bytes;
   D.Cert_Chain_Len := Cert_Chain_Bytes'Length;
   D.Cert_Chain_Spec := Chain_Spec;
   D.Server_Sign_Priv := [others => 0];
   D.Server_Sign_Priv (1 .. 32) := Sign_Priv_Key;
   D.Sig_Alg := Sig_Alg;
end Init_Cert_Server;
