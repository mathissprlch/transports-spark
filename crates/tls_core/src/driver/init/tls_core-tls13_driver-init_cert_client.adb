separate (Tls_Core.Tls13_Driver)
procedure Init_Cert_Client
  (D                  : out Driver;
   Trust_Anchor_Bytes : Octet_Array;
   Trust_Spec         : Tls_Core.Cert_Chain.Trust_Store;
   Hostname           : Octet_Array;
   Ecdhe_Priv         : Octet_Array)
is
   Priv_32 : Tls_Core.X25519.Bytes_32;
   Pub_32  : Tls_Core.X25519.Bytes_32;
begin
   D.My_Role := Client;
   D.Cur_State := Idle;
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
   D.Trust_Anchor_Bytes := [others => 0];
   D.Trust_Anchor_Bytes (1 .. Trust_Anchor_Bytes'Length) := Trust_Anchor_Bytes;
   D.Trust_Anchor_Len := Trust_Anchor_Bytes'Length;
   D.Trust_Anchor_Spec := Trust_Spec;
   --  Hostname re-uses Sni_Hostname / Sni_Len.  An empty hostname
   --  means "skip hostname check" — only valid with a self-signed
   --  pinned trust anchor (e.g., test fixtures).
   D.Sni_Hostname := [others => 0];
   D.Sni_Len := Hostname'Length;
   if Hostname'Length > 0 then
      D.Sni_Hostname (1 .. Hostname'Length) := Hostname;
   end if;
end Init_Cert_Client;
