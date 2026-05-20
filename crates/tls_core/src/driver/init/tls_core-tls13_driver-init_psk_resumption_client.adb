separate (Tls_Core.Tls13_Driver)
procedure Init_Psk_Resumption_Client
  (D : out Driver; Slot : Tls_Core.Session_Cache.Slot)
is
   Derived_Psk : Tls_Core.Key_Sched.Max_Secret;
   Priv_32     : Tls_Core.X25519.Bytes_32;
   Pub_32      : Tls_Core.X25519.Bytes_32;
begin
   --  Compute the resumption-PSK on the spot.
   Tls_Core.Session_Ticket.Derive_Psk_From_Ticket_Sha256
     (Resumption_Secret => Slot.Resumption_Secret,
      Ticket_Nonce      => Slot.Ticket_Nonce (1 .. Slot.Ticket_Nonce_Len),
      Psk               => Derived_Psk (1 .. 32));

   --  Initialise as a regular PSK client (the existing PSK_KE
   --  path drives the handshake).
   D.My_Role := Client;
   D.Cur_State := Idle;
   Tls_Core.Transcript.Init (D.Hash_Ctx);
   Tls_Core.Transcript_Sha384.Init (D.Hash_Ctx_384);
   D.PSK := Derived_Psk (1 .. 32);
   D.Identity := (others => 0);
   D.Identity_Len := Slot.Ticket_Len;
   D.Identity (1 .. Slot.Ticket_Len) := Slot.Ticket (1 .. Slot.Ticket_Len);
   D.Is_Resumption := True;  --  use "res binder" label
   D.App_Set := False;
   Prime_Driver_Defaults (D);
   D.Hrr_Demand := False;
   D.Hrr_Sent := False;
   D.Hrr_Aware := False;
   D.Hrr_Seen := False;
   D.Hrr_Group := Tls_Core.Suites.Group_Secp256r1;
   D.Hrr_Cookie := (others => 0);
   D.Hrr_Cookie_Len := 0;
   D.Hrr_Ch1_Hash := (others => 0);
   Tls_Core.Handshake_Buffer.Init (D.Hs_In_Buf);

   --  Resumption is psk_dhe_ke (mode 3) — needs a fresh X25519
   --  ephemeral.  Use a deterministic-but-non-zero scalar derived
   --  from the resumption_secret so peers compute a real shared.
   --  RFC 8446 §4.2.11.2: resumption-PSK + ECDHE; key_share is
   --  mandatory in CH.  (Production callers should layer a CSPRNG
   --  here; v0.5 derives from the unique-per-session resumption
   --  secret so each session has a distinct ephemeral.)
   Priv_32 := Slot.Resumption_Secret;
   --  RFC 7748 §5: the X25519.Derive_Public clamps the scalar.
   Tls_Core.X25519.Derive_Public (Priv_32, Pub_32);
   D.My_Ecdhe_Priv := Priv_32;
   D.My_Ecdhe_Pub := Pub_32;
   D.Peer_Ecdhe_Pub := (others => 0);
   D.Ecdhe_Shared := (others => 0);
end Init_Psk_Resumption_Client;
