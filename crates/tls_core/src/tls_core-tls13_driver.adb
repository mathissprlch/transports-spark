with Tls_Core.Cert;
with Tls_Core.Cert_Verify;
with Tls_Core.Channel;
with Tls_Core.Ecdsa_P256;
with Tls_Core.Hello;
with Tls_Core.Hkdf;
with Tls_Core.Hkdf_Sha256;
with Tls_Core.Hmac_Sha256;
with Tls_Core.Psk_Binder;
with Tls_Core.Session_Cache;
with Tls_Core.Session_Ticket;
with Tls_Core.Tls13_Driver.Helpers;
with Tls_Core.Tls13_Driver.Step_Awaiting_Cf;
with Tls_Core.Tls13_Driver.Step_Awaiting_Ch;
with Tls_Core.Tls13_Driver.Step_Awaiting_Sf;
with Tls_Core.Tls13_Driver.Step_Idle;
with Tls_Core.X25519;

package body Tls_Core.Tls13_Driver
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;

   use Helpers;

   procedure Init_Psk_Server
     (D            : out Driver;
      PSK          : Octet_Array;
      Psk_Identity : Octet_Array;
      Ecdhe_Priv   : Octet_Array)
   is
      Priv_32 : Tls_Core.X25519.Bytes_32;
      Pub_32  : Tls_Core.X25519.Bytes_32;
   begin
      D.My_Role := Server;
      D.Cur_State := Awaiting_CH;
      Tls_Core.Transcript.Init (D.Hash_Ctx);
      D.PSK := (others => 0);
      D.PSK := PSK;
      D.Identity := (others => 0);
      D.Identity_Len := Psk_Identity'Length;
      D.Identity (1 .. Psk_Identity'Length) := Psk_Identity;
      D.App_Set := False;
      Prime_Driver_Defaults (D);
      D.Hrr_Demand    := False;
      D.Hrr_Sent      := False;
      D.Hrr_Aware     := False;
      D.Hrr_Seen      := False;
      D.Hrr_Group     := Tls_Core.Suites.Group_Secp256r1;
      D.Hrr_Cookie    := (others => 0);
      D.Hrr_Cookie_Len := 0;
      D.Hrr_Ch1_Hash  := (others => 0);
      Tls_Core.Handshake_Buffer.Init (D.Hs_In_Buf);

      --  Derive ephemeral X25519 public key from caller-supplied
      --  private scalar. RFC 7748 §6.1: pub = X25519(priv, base_u=9).
      Priv_32 := Ecdhe_Priv;
      Tls_Core.X25519.Derive_Public (Priv_32, Pub_32);
      D.My_Ecdhe_Priv := Priv_32;
      D.My_Ecdhe_Pub  := Pub_32;
      D.Peer_Ecdhe_Pub := (others => 0);
      D.Ecdhe_Shared := (others => 0);
   end Init_Psk_Server;

   ---------------------------------------------------------------------
   --  Init_Cert_Server — RFC 8446 §4.4.2 / §4.4.3 cert-mode foundation.
   --  Mirrors Init_Psk_Server's record-init shape; flips D.Mode to
   --  Cert_Mode and pre-populates the cert-chain / sign-key fields.
   --  The Step branches that emit / parse Cert + CertVerify are
   --  wired in follow-up D-4-B / D-4-C commits; this commit lands
   --  the surface so callers can construct a cert-mode driver and
   --  the foundation is testable.
   ---------------------------------------------------------------------

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
      D.PSK := (others => 0);
      D.Identity := (others => 0);
      D.Identity_Len := 0;
      D.App_Set := False;
      Prime_Driver_Defaults (D);
      D.Hrr_Demand    := False;
      D.Hrr_Sent      := False;
      D.Hrr_Aware     := False;
      D.Hrr_Seen      := False;
      D.Hrr_Group     := Tls_Core.Suites.Group_Secp256r1;
      D.Hrr_Cookie    := (others => 0);
      D.Hrr_Cookie_Len := 0;
      D.Hrr_Ch1_Hash  := (others => 0);
      Tls_Core.Handshake_Buffer.Init (D.Hs_In_Buf);

      Priv_32 := Ecdhe_Priv;
      Tls_Core.X25519.Derive_Public (Priv_32, Pub_32);
      D.My_Ecdhe_Priv := Priv_32;
      D.My_Ecdhe_Pub  := Pub_32;
      D.Peer_Ecdhe_Pub := (others => 0);
      D.Ecdhe_Shared := (others => 0);

      D.Mode := Cert_Mode;
      D.Cert_Chain_Bytes := (others => 0);
      D.Cert_Chain_Bytes (1 .. Cert_Chain_Bytes'Length) := Cert_Chain_Bytes;
      D.Cert_Chain_Len := Cert_Chain_Bytes'Length;
      D.Cert_Chain_Spec := Chain_Spec;
      D.Server_Sign_Priv := (others => 0);
      D.Server_Sign_Priv (1 .. 32) := Sign_Priv_Key;
      D.Sig_Alg := Sig_Alg;
   end Init_Cert_Server;

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
      D.PSK := (others => 0);
      D.PSK := PSK;
      D.Identity := (others => 0);
      D.Identity_Len := Psk_Identity'Length;
      D.Identity (1 .. Psk_Identity'Length) := Psk_Identity;
      D.App_Set := False;
      Prime_Driver_Defaults (D);
      D.Hrr_Demand    := False;
      D.Hrr_Sent      := False;
      D.Hrr_Aware     := False;
      D.Hrr_Seen      := False;
      D.Hrr_Group     := Tls_Core.Suites.Group_Secp256r1;
      D.Hrr_Cookie    := (others => 0);
      D.Hrr_Cookie_Len := 0;
      D.Hrr_Ch1_Hash  := (others => 0);
      Tls_Core.Handshake_Buffer.Init (D.Hs_In_Buf);

      Priv_32 := Ecdhe_Priv;
      Tls_Core.X25519.Derive_Public (Priv_32, Pub_32);
      D.My_Ecdhe_Priv := Priv_32;
      D.My_Ecdhe_Pub  := Pub_32;
      D.Peer_Ecdhe_Pub := (others => 0);
      D.Ecdhe_Shared := (others => 0);
   end Init_Psk_Client;

   ---------------------------------------------------------------------
   --  Init_Cert_Client — RFC 8446 §4.4.2 / §4.4.3 cert-mode foundation
   --  on the client side.  Same shape as Init_Psk_Client; flips
   --  D.Mode to Cert_Mode and pre-populates the trust-anchor bytes /
   --  spec for Cert_Chain.Authenticate_Server.
   ---------------------------------------------------------------------

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
      D.PSK := (others => 0);
      D.Identity := (others => 0);
      D.Identity_Len := 0;
      D.App_Set := False;
      Prime_Driver_Defaults (D);
      D.Hrr_Demand    := False;
      D.Hrr_Sent      := False;
      D.Hrr_Aware     := False;
      D.Hrr_Seen      := False;
      D.Hrr_Group     := Tls_Core.Suites.Group_Secp256r1;
      D.Hrr_Cookie    := (others => 0);
      D.Hrr_Cookie_Len := 0;
      D.Hrr_Ch1_Hash  := (others => 0);
      Tls_Core.Handshake_Buffer.Init (D.Hs_In_Buf);

      Priv_32 := Ecdhe_Priv;
      Tls_Core.X25519.Derive_Public (Priv_32, Pub_32);
      D.My_Ecdhe_Priv := Priv_32;
      D.My_Ecdhe_Pub  := Pub_32;
      D.Peer_Ecdhe_Pub := (others => 0);
      D.Ecdhe_Shared := (others => 0);

      D.Mode := Cert_Mode;
      D.Trust_Anchor_Bytes := (others => 0);
      D.Trust_Anchor_Bytes (1 .. Trust_Anchor_Bytes'Length) :=
        Trust_Anchor_Bytes;
      D.Trust_Anchor_Len := Trust_Anchor_Bytes'Length;
      D.Trust_Anchor_Spec := Trust_Spec;
      --  Hostname re-uses Sni_Hostname / Sni_Len.  An empty hostname
      --  means "skip hostname check" — only valid with a self-signed
      --  pinned trust anchor (e.g., test fixtures).
      D.Sni_Hostname := (others => 0);
      D.Sni_Len := Hostname'Length;
      if Hostname'Length > 0 then
         D.Sni_Hostname (1 .. Hostname'Length) := Hostname;
      end if;
   end Init_Cert_Client;

   ---------------------------------------------------------------------
   --  Init_Psk_Server_With_Hrr / Init_Psk_Client_Hrr_Aware
   --  (RFC 8446 §4.1.4 — HelloRetryRequest)
   ---------------------------------------------------------------------

   procedure Init_Psk_Server_With_Hrr
     (D                 : out Driver;
      PSK               : Octet_Array;
      Psk_Identity      : Octet_Array;
      Ecdhe_Priv        : Octet_Array;
      Demanded_Group    : Tls_Core.Suites.U16;
      Cookie            : Octet_Array)
   is
   begin
      Init_Psk_Server (D, PSK, Psk_Identity, Ecdhe_Priv);
      D.Hrr_Demand := True;
      D.Hrr_Sent   := False;
      D.Hrr_Group  := Demanded_Group;
      D.Hrr_Cookie := (others => 0);
      D.Hrr_Cookie_Len := Cookie'Length;
      if Cookie'Length > 0 then
         for I in 1 .. Cookie'Length loop
            pragma Loop_Invariant (I in 1 .. Cookie'Length);
            pragma Loop_Invariant
              (Cookie'Length <= Tls_Core.Hello_Retry.Max_Cookie_Length);
            D.Hrr_Cookie (I) := Cookie (Cookie'First + I - 1);
         end loop;
      end if;
   end Init_Psk_Server_With_Hrr;

   procedure Init_Psk_Client_Hrr_Aware
     (D            : out Driver;
      PSK          : Octet_Array;
      Psk_Identity : Octet_Array;
      Ecdhe_Priv   : Octet_Array)
   is
   begin
      Init_Psk_Client (D, PSK, Psk_Identity, Ecdhe_Priv);
      D.Hrr_Aware := True;
   end Init_Psk_Client_Hrr_Aware;

   --  Helpers (Fail_Plaintext, Fail_Encrypted, Build_Finished_Body,
   --  Encode_Hs_Message, Wrap_Tls_Plaintext, constants) moved to
   --  Tls_Core.Tls13_Driver.Helpers.

   ---------------------------------------------------------------------
   --  Step — server side, PSK_KE profile.
   ---------------------------------------------------------------------

   procedure Step
     (D         : in out Driver;
      In_Bytes  : Octet_Array;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   is
      Cur_State_Old : constant State := D.Cur_State;
   begin
      Out_Buf := (others => 0);
      Out_Last := 0;

      case D.Cur_State is
         when Idle =>
            Step_Idle.Handle (D, In_Bytes, Out_Buf, Out_Last);

         when Awaiting_Sf =>
            Step_Awaiting_Sf.Handle (D, In_Bytes, Out_Buf, Out_Last);

         when Awaiting_CH =>
            Step_Awaiting_Ch.Handle (D, In_Bytes, Out_Buf, Out_Last);

         when Awaiting_Cf =>
            Step_Awaiting_Cf.Handle (D, In_Bytes, Out_Buf, Out_Last);

         when Awaiting_Sh_Or_Hrr =>
            --  RFC 8446 §4.1.4 — client just sent CH1; server's first
            --  record is either a regular SH (proceed as Awaiting_Sf)
            --  or an HRR (rebuild transcript per §4.4.1, emit CH2).
            --
            --  Wall-hit: this branch only services the *HRR* case
            --  (random == Magic_Random). A server that honors CH1's
            --  key_share without HRR triggers the Failed transition
            --  here. Real production clients dispatch back into
            --  Awaiting_Sf in that situation; doing so cleanly
            --  requires factoring Awaiting_Sf's body into a helper
            --  that takes In_Bytes — left as v0.6 work since the
            --  HRR-aware client init is opt-in and pairs only with
            --  HRR-demanding servers in v0.5 tests. The non-HRR
            --  client init (Init_Psk_Client) doesn't enter this state.
            if D.My_Role /= Client then
               D.Cur_State := Failed;
               return;
            end if;
            declare
               --  Same parse shell as the start of Awaiting_Sf: read
               --  the SH-shaped TLSPlaintext record, but inspect the
               --  random field instead of decoding the body.
               Cursor : constant Natural := In_Bytes'First;
               Rec_Len : Natural;
               Rec_F, Rec_L : Natural;
               Random_Slice : Tls_Core.Octet_Array (1 .. 32) :=
                 (others => 0);
            begin
               if Cursor + 4 > In_Bytes'Last
                 or else In_Bytes (Cursor) /= Rec_Type_Handshake
               then
                  D.Cur_State := Failed;
                  return;
               end if;
               Rec_Len := Natural (In_Bytes (Cursor + 3)) * 256
                          + Natural (In_Bytes (Cursor + 4));
               Rec_F := Cursor + 5;
               Rec_L := Rec_F + Rec_Len - 1;
               if Rec_L > In_Bytes'Last
                 or else Rec_Len < 4
                 or else In_Bytes (Rec_F) /= Hs_Type_SH
               then
                  D.Cur_State := Failed;
                  return;
               end if;
               --  Random sits at offset 4 + 2 (handshake header +
               --  legacy_version) into the record's body.
               if Rec_F + 37 > In_Bytes'Last then
                  D.Cur_State := Failed;
                  return;
               end if;
               Random_Slice :=
                 In_Bytes (Rec_F + 6 .. Rec_F + 6 + 31);
               if not Tls_Core.Hello_Retry.Is_Hrr_Random (Random_Slice) then
                  --  Not an HRR: see wall-hit note above.
                  D.Cur_State := Failed;
                  return;
               end if;
               --  Decode the HRR body (the bytes after the 4-byte
               --  handshake header).
               declare
                  Hrr_Body_F : constant Natural := Rec_F + 4;
                  Hrr_Body_L : constant Natural := Rec_L;
                  Hrr_Cs     : Tls_Core.Suites.U16;
                  Hrr_Group  : Tls_Core.Suites.U16;
                  Hrr_Cookie : Tls_Core.Hello_Retry.Cookie_Bytes;
                  Hrr_Cookie_Length : Natural;
                  Hrr_OK     : Boolean;
                  use type Tls_Core.Suites.U16;
               begin
                  if Hrr_Body_L > In_Bytes'Last then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  Tls_Core.Hello_Retry.Decode_Hrr
                    (In_Bytes (Hrr_Body_F .. Hrr_Body_L),
                     Hrr_Cs, Hrr_Group,
                     Hrr_Cookie, Hrr_Cookie_Length,
                     Hrr_OK);
                  if not Hrr_OK then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  --  Validate echoed cipher suite (must be one we
                  --  offered) and remember it for later.
                  if not Tls_Core.Suites.Is_Supported_Suite (Hrr_Cs)
                    or else Hrr_Cs = Tls_Core.Suites.TLS_AES_256_GCM_SHA384
                  then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  D.Suite := Tls_Core.Suites.Suite_Of_Code (Hrr_Cs);
                  --  Save the demanded named-group + cookie for the CH2
                  --  emission that follows.
                  D.Hrr_Group := Hrr_Group;
                  D.Hrr_Cookie := Hrr_Cookie;
                  D.Hrr_Cookie_Len := Hrr_Cookie_Length;
                  D.Hrr_Seen := True;
               end;
               --  RFC 8446 §4.4.1 — rebuild transcript:
               --    new transcript = synthetic(CH1_hash) || HRR
               declare
                  Synthetic : Tls_Core.Octet_Array (1 .. 36) :=
                    (others => 0);
               begin
                  Tls_Core.Transcript.Snapshot
                    (D.Hash_Ctx, D.Hrr_Ch1_Hash);
                  Tls_Core.Hello_Retry.Build_Synthetic_Msg_Sha256
                    (D.Hrr_Ch1_Hash, Synthetic);
                  Tls_Core.Transcript.Init (D.Hash_Ctx);
                  Tls_Core.Transcript.Append (D.Hash_Ctx, Synthetic);
                  --  Append the HRR handshake message (NOT the wire
                  --  record envelope) to the transcript — same offsets
                  --  used during the magic check above, Rec_F .. Rec_L
                  --  brackets exactly the type+u24-len + body bytes.
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, In_Bytes (Rec_F .. Rec_L));
               end;
            end;

            --  Build CH2: same shape as CH1 (we don't carry actual
            --  ECDHE key_share in PSK_KE mode, so the cookie echo is
            --  the only HRR-specific addition). Encode_Client_Hello_Psk
            --  emits the standard PSK CH; we then patch in the cookie
            --  extension if non-empty before computing the binder.
            --
            --  v0.5 simplification: PSK_KE has no real key_share, so
            --  the named-group renegotiation is structural rather
            --  than cryptographic — the CH2 echoes back only the
            --  cookie and the binder is recomputed over the new
            --  truncated CH2. The transcript sees CH2 as a fresh CH
            --  message, and the synthetic+HRR prefix is already in
            --  place. End-to-end correctness is exercised by the
            --  loopback test scenario.
            declare
               Client_Random : constant Tls_Core.Hello.Random_Bytes :=
                 (others => 16#A2#);  --  distinct from CH1's 0xA1
               Ch_Body : Tls_Core.Octet_Array (1 .. 512) :=
                 (others => 0);
               Ch_Body_Last : Natural;
               T_Last  : Natural;
               Binder  : Tls_Core.Psk_Binder.Binder_Bytes;
               Ch_Hs   : Tls_Core.Octet_Array (1 .. 1024) :=
                 (others => 0);
               Ch_Hs_Last : Natural;
               Ch_Rec  : Tls_Core.Octet_Array (1 .. 1024) :=
                 (others => 0);
               Ch_Rec_Last : Natural;
            begin
               Tls_Core.Hello.Encode_Client_Hello_Psk_With_Cookie
                 (Client_Random,
                  D.Identity (1 .. D.Identity_Len),
                  D.My_Ecdhe_Pub,
                  D.Hrr_Cookie (1 .. D.Hrr_Cookie_Len),
                  D.Sni_Hostname (1 .. D.Sni_Len),
                  D.Alpn_Offers (1 .. D.Alpn_Offers_Len),
                  Ch_Body, Ch_Body_Last, T_Last);
               --  RFC 8446 §4.2.11.2 + §4.4.1: hash the truncated
               --  *handshake-formatted* CH (header + body), not the
               --  body alone.  See sister site at line ~397 for
               --  rationale.
               Ch_Hs := (others => 0);
               Ch_Hs (1) := Hs_Type_CH;
               Ch_Hs (2) := Octet ((Ch_Body_Last / 65536) mod 256);
               Ch_Hs (3) := Octet ((Ch_Body_Last / 256) mod 256);
               Ch_Hs (4) := Octet (Ch_Body_Last mod 256);
               Ch_Hs (5 .. 4 + T_Last) := Ch_Body (1 .. T_Last);
               Tls_Core.Psk_Binder.Compute
                 (PSK                    => D.PSK,
                  Truncated_Client_Hello => Ch_Hs (1 .. 4 + T_Last),
                  Out_Binder             => Binder,
                  Is_Resumption          => D.Is_Resumption);
               Ch_Body (T_Last + 4 .. T_Last + 35) := Binder;  -- offset by binders_total_len(2)+binder_len(1)+1
               Encode_Hs_Message
                 (Hs_Type_CH, Ch_Body (1 .. Ch_Body_Last),
                  Ch_Hs, Ch_Hs_Last);
               Tls_Core.Transcript.Append
                 (D.Hash_Ctx, Ch_Hs (1 .. Ch_Hs_Last));
               Wrap_Tls_Plaintext
                 (Ch_Hs (1 .. Ch_Hs_Last), Ch_Rec, Ch_Rec_Last);
               Out_Buf (1 .. Ch_Rec_Last) := Ch_Rec (1 .. Ch_Rec_Last);
               Out_Last := Ch_Rec_Last;
               D.Cur_State := Awaiting_Sf;
            end;

         when Awaiting_Ch_2 =>
            --  RFC 8446 §4.1.4 — server already emitted HRR; the
            --  client should now send CH2. We reuse the CH1 parse
            --  shell from Awaiting_CH (fixed shape) and additionally
            --  validate that the cookie extension echoes our HRR
            --  cookie byte-for-byte.
            if D.My_Role /= Server then
               D.Cur_State := Failed;
               return;
            end if;
            if In_Bytes'Length < 5
              or else In_Bytes (In_Bytes'First) /= Rec_Type_Handshake
            then
               D.Cur_State := Failed;
               return;
            end if;
            declare
               Rec_Len : constant Natural :=
                 Natural (In_Bytes (In_Bytes'First + 3)) * 256
                 + Natural (In_Bytes (In_Bytes'First + 4));
               Rec_F : constant Natural := In_Bytes'First + 5;
               Rec_L : constant Natural := Rec_F + Rec_Len - 1;
            begin
               if Rec_L > In_Bytes'Last
                 or else Rec_Len < 4
                 or else In_Bytes (Rec_F) /= Hs_Type_CH
               then
                  D.Cur_State := Failed;
                  return;
               end if;
               declare
                  Hs_Body_Len : constant Natural :=
                    Natural (In_Bytes (Rec_F + 1)) * 65536
                    + Natural (In_Bytes (Rec_F + 2)) * 256
                    + Natural (In_Bytes (Rec_F + 3));
                  Hs_Body_F : constant Natural := Rec_F + 4;
                  Hs_Body_L : constant Natural := Hs_Body_F + Hs_Body_Len - 1;
                  Random : Tls_Core.Hello.Random_Bytes;
                  Sid_F, Sid_L : Natural;
                  Suites_F, Suites_L : Natural;
                  Id_F, Id_L, Bf, Bl, T_Last : Natural;
                  Ks_F, Ks_L : Natural;
                  Decode_OK : Boolean;
               begin
                  if Hs_Body_L > Rec_L then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  Tls_Core.Hello.Decode_Client_Hello_Psk
                    (In_Bytes (Hs_Body_F .. Hs_Body_L),
                     Random,
                     Sid_F, Sid_L,
                     Suites_F, Suites_L,
                     Id_F, Id_L, Bf, Bl,
                     Ks_F, Ks_L, T_Last, Decode_OK);
                  if not Decode_OK then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  --  Capture legacy_session_id for SH echo (§4.1.3).
                  --  CH2 from a HRR rerun MUST carry the same
                  --  session_id as CH1; the field is part of the
                  --  CH→SH echo invariant.
                  if Sid_F > 0 and then Sid_L >= Sid_F
                    and then Sid_L - Sid_F + 1 <= 32
                  then
                     D.Session_Id_Echo_Len := Sid_L - Sid_F + 1;
                     D.Session_Id_Echo (1 .. D.Session_Id_Echo_Len) :=
                       In_Bytes (Sid_F .. Sid_L);
                  else
                     D.Session_Id_Echo_Len := 0;
                  end if;
                  --  Update peer pubkey + ECDHE shared from CH2's
                  --  fresh key_share. RFC 8446 §4.1.4: HRR rerun uses
                  --  the named-group the server demanded, which is
                  --  still x25519 in v0.5 (only group we accept).
                  declare
                     Peer_Pub : Tls_Core.X25519.Bytes_32;
                     Shared   : Tls_Core.X25519.Bytes_32;
                  begin
                     for I in 1 .. 32 loop
                        pragma Loop_Invariant (I in 1 .. 32);
                        Peer_Pub (I) := In_Bytes (Ks_F + I - 1);
                     end loop;
                     D.Peer_Ecdhe_Pub := Peer_Pub;
                     Tls_Core.X25519.Scalar_Mult
                       (D.My_Ecdhe_Priv, Peer_Pub, Shared);
                     D.Ecdhe_Shared := Shared;
                  end;
                  --  Verify PSK identity (same constant-time pattern
                  --  as Awaiting_CH).
                  declare
                     Identity_OK : Boolean := True;
                  begin
                     if Id_L - Id_F + 1 /= D.Identity_Len then
                        Identity_OK := False;
                     else
                        for I in 1 .. D.Identity_Len loop
                           pragma Loop_Invariant (I in 1 .. D.Identity_Len);
                           if In_Bytes (Id_F + I - 1) /= D.Identity (I) then
                              Identity_OK := False;
                           end if;
                        end loop;
                     end if;
                     if not Identity_OK then
                        D.Cur_State := Failed;
                        return;
                     end if;
                  end;
                  --  Verify PSK binder over CH2's truncated bytes.
                  --  RFC 8446 §4.2.11.2 + §4.4.1: hash the truncated
                  --  *handshake message* (Rec_F .. T_Last spans CH
                  --  type byte through last pre-binders body byte),
                  --  not the body alone.  Copy into a 'First=1
                  --  buffer for Compute's Pre.
                  declare
                     Computed : Tls_Core.Psk_Binder.Binder_Bytes;
                     Received : Tls_Core.Psk_Binder.Binder_Bytes;
                     Trunc_Len : constant Natural :=
                       T_Last - Rec_F + 1;
                     Hs_Trunc : Octet_Array (1 .. 16640) :=
                       (others => 0);
                  begin
                     if Trunc_Len > Hs_Trunc'Length then
                        D.Cur_State := Failed;
                        return;
                     end if;
                     Hs_Trunc (1 .. Trunc_Len) :=
                       In_Bytes (Rec_F .. T_Last);
                     Tls_Core.Psk_Binder.Compute
                       (D.PSK,
                        Hs_Trunc (1 .. Trunc_Len),
                        Computed);
                     for I in 1 .. 32 loop
                        pragma Loop_Invariant (I in 1 .. 32);
                        Received (I) := In_Bytes (Bf + I - 1);
                     end loop;
                     if not Tls_Core.Psk_Binder.Verify
                              (Computed, Received)
                     then
                        D.Cur_State := Failed;
                        return;
                     end if;
                  end;
                  --  Append CH2 handshake message (without record
                  --  envelope) to the transcript. After this:
                  --    transcript = synthetic(CH1) || HRR || CH2
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, In_Bytes (Rec_F .. Rec_L));
                  --  Cookie validation: walk CH2's extensions, find
                  --  cookie ext, compare to D.Hrr_Cookie. If we
                  --  emitted no cookie (Hrr_Cookie_Len = 0), no
                  --  cookie ext should appear.
                  --
                  --  CH body extensions block layout (Decode_*_Psk
                  --  consumed Random, Suites_F/L, Identity, Binder
                  --  but didn't surface the broader extensions
                  --  walker — for v0.5 we walk it here directly).
                  if D.Hrr_Cookie_Len > 0 then
                     declare
                        --  Step past legacy_version (2) + random (32)
                        --  + sid_len (1) + sid + cipher_suites
                        --  + compression in the CH body. Easier path:
                        --  start from Suites_L + 1 (immediately after
                        --  cipher_suites), then 1+1 compression, then
                        --  u16 ext-block length, then walk.
                        --  Suites_L is absolute index into In_Bytes.
                        Walk_P : Natural := Suites_L + 1;
                        Cookie_Ok : Boolean := False;
                     begin
                        --  legacy_compression_methods: u8 len + N
                        if Walk_P > In_Bytes'Last then
                           D.Cur_State := Failed;
                           return;
                        end if;
                        declare
                           Comp_Len : constant Natural :=
                             Natural (In_Bytes (Walk_P));
                        begin
                           Walk_P := Walk_P + 1 + Comp_Len;
                        end;
                        --  Extensions block u16 length
                        if Walk_P + 1 > In_Bytes'Last then
                           D.Cur_State := Failed;
                           return;
                        end if;
                        declare
                           Ext_Total_Len : constant Natural :=
                             Natural (In_Bytes (Walk_P)) * 256
                             + Natural (In_Bytes (Walk_P + 1));
                           Ext_Block_Start : constant Natural :=
                             Walk_P + 2;
                           Ext_Block_End : constant Natural :=
                             Ext_Block_Start + Ext_Total_Len;
                           Q : Natural := Ext_Block_Start;
                        begin
                           if Ext_Block_End - 1 > In_Bytes'Last then
                              D.Cur_State := Failed;
                              return;
                           end if;
                           while Q + 3 < Ext_Block_End loop
                              pragma Loop_Invariant
                                (Q in Ext_Block_Start .. Ext_Block_End);
                              declare
                                 T_Val : constant Natural :=
                                   Natural (In_Bytes (Q)) * 256
                                   + Natural (In_Bytes (Q + 1));
                                 L_Val : constant Natural :=
                                   Natural (In_Bytes (Q + 2)) * 256
                                   + Natural (In_Bytes (Q + 3));
                              begin
                                 if Q + 4 + L_Val - 1 >= Ext_Block_End then
                                    D.Cur_State := Failed;
                                    return;
                                 end if;
                                 if T_Val = 16#002C# then
                                    --  Cookie extension; body =
                                    --  u16 cookie_len + cookie_bytes.
                                    if L_Val < 2 then
                                       D.Cur_State := Failed;
                                       return;
                                    end if;
                                    declare
                                       Cookie_Data_Len : constant Natural :=
                                         Natural (In_Bytes (Q + 4)) * 256
                                         + Natural (In_Bytes (Q + 5));
                                    begin
                                       if Cookie_Data_Len /= L_Val - 2 then
                                          D.Cur_State := Failed;
                                          return;
                                       end if;
                                       if Tls_Core.Hello_Retry.Cookies_Equal
                                            (In_Bytes
                                               (Q + 6 ..
                                                Q + 6 + Cookie_Data_Len - 1),
                                             D.Hrr_Cookie,
                                             D.Hrr_Cookie_Len)
                                       then
                                          Cookie_Ok := True;
                                       end if;
                                    end;
                                 end if;
                                 Q := Q + 4 + L_Val;
                              end;
                           end loop;
                           if not Cookie_Ok then
                              D.Cur_State := Failed;
                              return;
                           end if;
                        end;
                     end;
                  end if;
               end;
            end;
            --  Cookie validated (or not required). Set Cur_State to
            --  Awaiting_CH and re-dispatch into the SH+EE+SF branch
            --  by treating CH2 as the canonical CH. Hrr_Sent is True
            --  so the HRR branch above won't re-fire.
            D.Cur_State := Awaiting_CH;
            --  We've already appended CH2 to the transcript and run
            --  binder/identity checks; the SH-build half of the
            --  Awaiting_CH path doesn't depend on In_Bytes (it reads
            --  from D.Suite + D.Hash_Ctx). To avoid a recursive Step
            --  call, fall through into the SH builder by re-raising
            --  the case-loop manually here. Implementation: build
            --  the SH+EE+SF flight inline using the same helpers.
            declare
               Sh_Body : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
               Sh_Body_Last : Natural;
               Sh_Hs_Msg : Tls_Core.Octet_Array (1 .. 512) := (others => 0);
               Sh_Hs_Last : Natural;
               Sh_Record : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
               Sh_Record_Last : Natural;
               Server_Random : constant Tls_Core.Hello.Random_Bytes :=
                 (others => 16#5E#);
               Zero32 : constant Octet_Array (1 .. 32) := (others => 0);
               Empty  : constant Octet_Array (1 .. 0)  := (others => 0);
               Derived_Label : constant Octet_Array (1 .. 7) :=
                 (16#64#, 16#65#, 16#72#, 16#69#, 16#76#, 16#65#, 16#64#);
               C_Hs_Label : constant Octet_Array (1 .. 12) :=
                 (16#63#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
                  16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
               S_Hs_Label : constant Octet_Array (1 .. 12) :=
                 (16#73#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
                  16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
               Early_Secret : Tls_Core.Key_Schedule.Secret;
               Derived_1    : Tls_Core.Key_Schedule.Secret;
               Hs_Secret    : Tls_Core.Key_Schedule.Secret;
               C_Hs_Sec     : Tls_Core.Key_Schedule.Secret;
               S_Hs_Sec     : Tls_Core.Key_Schedule.Secret;
               Th_After_SH  : Tls_Core.Sha256.Digest;
            begin
               Tls_Core.Hello.Encode_Server_Hello_Psk
                 (Server_Random,
                  D.Session_Id_Echo (1 .. D.Session_Id_Echo_Len),
                  Tls_Core.Suites.Code_Of_Suite (D.Suite),
                  D.My_Ecdhe_Pub,
                  Sh_Body, Sh_Body_Last);
               Encode_Hs_Message
                 (Hs_Type_SH, Sh_Body (1 .. Sh_Body_Last),
                  Sh_Hs_Msg, Sh_Hs_Last);
               Tls_Core.Transcript.Append
                 (D.Hash_Ctx, Sh_Hs_Msg (1 .. Sh_Hs_Last));
               Wrap_Tls_Plaintext
                 (Sh_Hs_Msg (1 .. Sh_Hs_Last), Sh_Record, Sh_Record_Last);
               Tls_Core.Key_Schedule.Extract
                 (Salt => Zero32, IKM => D.PSK, Out_PRK => Early_Secret);
               Tls_Core.Key_Schedule.Derive_Secret
                 (Secret_In  => Early_Secret,
                  Label      => Derived_Label,
                  Messages   => Empty,
                  Out_Secret => Derived_1);
               --  Mode 3: Handshake_Secret extract uses ECDHE_secret as IKM.
               Tls_Core.Key_Schedule.Extract
                 (Salt => Derived_1, IKM => D.Ecdhe_Shared,
                  Out_PRK => Hs_Secret);
               Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Th_After_SH);
               Hkdf_Expand_Label_Sha256
                 (Secret  => Hs_Secret,
                  Label   => C_Hs_Label,
                  Context => Th_After_SH,
                  Output  => C_Hs_Sec);
               Hkdf_Expand_Label_Sha256
                 (Secret  => Hs_Secret,
                  Label   => S_Hs_Label,
                  Context => Th_After_SH,
                  Output  => S_Hs_Sec);
               Tls_Core.Aead_Channel.Init_Sha256
                 (D.Hs_Out_Dir, D.Suite, S_Hs_Sec);
               Tls_Core.Aead_Channel.Init_Sha256
                 (D.Hs_In_Dir,  D.Suite, C_Hs_Sec);
               D.C_Hs_Sec := C_Hs_Sec;
               D.S_Hs_Sec := S_Hs_Sec;
               D.Hs_Secret := Hs_Secret;

               declare
                  Ee_Body : constant Octet_Array (1 .. 2) := (16#00#, 16#00#);
                  Ee_Hs   : Octet_Array (1 .. 6) := (others => 0);
                  Ee_Hs_Last : Natural;
                  Ee_Rec  : Octet_Array (1 .. 256) := (others => 0);
                  Ee_Rec_Last : Natural;
                  Th_After_EE : Tls_Core.Sha256.Digest;
                  Verify_Data : Tls_Core.Sha256.Digest;
                  Fin_Hs : Octet_Array (1 .. 4 + 32) := (others => 0);
                  Fin_Hs_Last : Natural;
                  Fin_Rec : Octet_Array (1 .. 256) := (others => 0);
                  Fin_Rec_Last : Natural;
                  Th_After_SF : Tls_Core.Sha256.Digest;
                  Empty_Hash  : Tls_Core.Sha256.Digest;
                  Empty_In    : constant Octet_Array (1 .. 0) :=
                    (others => 0);
                  Derived_2_Sec : Tls_Core.Key_Schedule.Secret;
                  Master_Secret : Tls_Core.Key_Schedule.Secret;
                  Zero_Secret   : constant Tls_Core.Key_Schedule.Secret :=
                    (others => 0);
                  Derived_Lab : constant Octet_Array (1 .. 7) :=
                    (16#64#, 16#65#, 16#72#, 16#69#, 16#76#, 16#65#, 16#64#);
                  C_Ap_Lab : constant Octet_Array (1 .. 12) :=
                    (16#63#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
                     16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
                  S_Ap_Lab : constant Octet_Array (1 .. 12) :=
                    (16#73#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
                     16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
               begin
                  Encode_Hs_Message
                    (Hs_Type_EE, Ee_Body, Ee_Hs, Ee_Hs_Last);
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, Ee_Hs (1 .. Ee_Hs_Last));
                  Tls_Core.Aead_Channel.Send
                    (D.Hs_Out_Dir,
                     Ee_Hs (1 .. Ee_Hs_Last),
                     Tls_Core.Aead_Channel.Inner_Type_Handshake,
                     Ee_Rec, Ee_Rec_Last);

                  Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Th_After_EE);
                  Build_Finished_Body (S_Hs_Sec, Th_After_EE, Verify_Data);
                  Encode_Hs_Message
                    (Hs_Type_Finished, Verify_Data,
                     Fin_Hs, Fin_Hs_Last);
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, Fin_Hs (1 .. Fin_Hs_Last));
                  Tls_Core.Aead_Channel.Send
                    (D.Hs_Out_Dir,
                     Fin_Hs (1 .. Fin_Hs_Last),
                     Tls_Core.Aead_Channel.Inner_Type_Handshake,
                     Fin_Rec, Fin_Rec_Last);

                  declare
                     Cursor : Natural := 0;
                  begin
                     Out_Buf (1 .. Sh_Record_Last) :=
                       Sh_Record (1 .. Sh_Record_Last);
                     Cursor := Sh_Record_Last;
                     Out_Buf (Cursor + 1 .. Cursor + Ee_Rec_Last) :=
                       Ee_Rec (1 .. Ee_Rec_Last);
                     Cursor := Cursor + Ee_Rec_Last;
                     Out_Buf (Cursor + 1 .. Cursor + Fin_Rec_Last) :=
                       Fin_Rec (1 .. Fin_Rec_Last);
                     Out_Last := Cursor + Fin_Rec_Last;
                  end;

                  Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Th_After_SF);
                  Tls_Core.Sha256.Hash (Empty_In, Empty_Hash);
                  Hkdf_Expand_Label_Sha256
                    (Secret  => D.Hs_Secret,
                     Label   => Derived_Lab,
                     Context => Empty_Hash,
                     Output  => Derived_2_Sec);
                  Tls_Core.Key_Schedule.Extract
                    (Salt    => Derived_2_Sec,
                     IKM     => Zero_Secret,
                     Out_PRK => Master_Secret);
                  Hkdf_Expand_Label_Sha256
                    (Secret  => Master_Secret,
                     Label   => C_Ap_Lab,
                     Context => Th_After_SF,
                     Output  => D.App_C_Ap);
                  Hkdf_Expand_Label_Sha256
                    (Secret  => Master_Secret,
                     Label   => S_Ap_Lab,
                     Context => Th_After_SF,
                     Output  => D.App_S_Ap);
                  D.App_Set := True;
                  --  Save Master_Secret so the Awaiting_Cf branch can
                  --  derive resumption_master_secret (RFC 8446 §7.1)
                  --  once the client Finished is appended.
                  D.Master_Sec := Master_Secret;
                  D.Master_Set := True;
                  Build_Finished_Body
                    (D.C_Hs_Sec, Th_After_SF, D.Expected_Cf);
               end;

               D.Cur_State := Awaiting_Cf;
            end;

         when others =>
            null;
      end case;
   end Step;

   procedure Open_App_Directions
     (D          : Driver;
      Out_Dir    : out Tls_Core.Aead_Channel.Direction;
      In_Dir     : out Tls_Core.Aead_Channel.Direction;
      Out_Secret : out Tls_Core.Key_Schedule.Secret;
      In_Secret  : out Tls_Core.Key_Schedule.Secret)
   is
   begin
      case D.My_Role is
         when Server =>
            --  Server: out encrypts with s_ap; in decrypts with c_ap.
            Out_Secret := D.App_S_Ap;
            In_Secret  := D.App_C_Ap;
            Tls_Core.Aead_Channel.Init_Sha256
              (Out_Dir, D.Suite, Out_Secret);
            Tls_Core.Aead_Channel.Init_Sha256
              (In_Dir,  D.Suite, In_Secret);
         when Client =>
            --  Client: out encrypts with c_ap; in decrypts with s_ap.
            Out_Secret := D.App_C_Ap;
            In_Secret  := D.App_S_Ap;
            Tls_Core.Aead_Channel.Init_Sha256
              (Out_Dir, D.Suite, Out_Secret);
            Tls_Core.Aead_Channel.Init_Sha256
              (In_Dir,  D.Suite, In_Secret);
      end case;
   end Open_App_Directions;

   ---------------------------------------------------------------------
   --  Open_App_Directions — backward-compat shim that drops the secrets.
   ---------------------------------------------------------------------

   procedure Open_App_Directions
     (D       : Driver;
      Out_Dir : out Tls_Core.Aead_Channel.Direction;
      In_Dir  : out Tls_Core.Aead_Channel.Direction)
   is
      Discard_Out_Sec : Tls_Core.Key_Schedule.Secret;
      Discard_In_Sec  : Tls_Core.Key_Schedule.Secret;
   begin
      Open_App_Directions
        (D, Out_Dir, In_Dir, Discard_Out_Sec, Discard_In_Sec);
      pragma Unreferenced (Discard_Out_Sec, Discard_In_Sec);
   end Open_App_Directions;

   ---------------------------------------------------------------------
   --  Send_Key_Update — RFC 8446 §4.6.3.
   --
   --  Wire layout: ONE TLSCiphertext record carrying the 5-byte
   --  KeyUpdate handshake message, encrypted under the *current*
   --  Out_Dir traffic key (because §4.6.3 says: "after sending the
   --  KeyUpdate, the sender SHALL send all its traffic using the
   --  next generation of keys"). Key rotation happens AFTER Send.
   ---------------------------------------------------------------------

   procedure Send_Key_Update
     (D              : Driver;
      Out_Dir        : in out Tls_Core.Aead_Channel.Direction;
      Send_Secret    : in out Tls_Core.Key_Schedule.Secret;
      Request_Update : Octet;
      Out_Buf        : out Octet_Array;
      Out_Last       : out Natural)
   is
      pragma Unreferenced (D);
      Ku_Msg : Octet_Array (1 .. Tls_Core.Key_Update.Wire_Size) :=
        (others => 0);
      Ku_Last : Natural;
      Next_Secret : Tls_Core.Key_Schedule.Secret;
   begin
      Out_Buf := (others => 0);
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
         Out_Buf, Out_Last);

      --  3. Derive the next traffic secret per §7.2 and rotate the
      --     local send key + IV + sequence counter.
      Tls_Core.Key_Update.Derive_Next_Sha256 (Send_Secret, Next_Secret);
      Send_Secret := Next_Secret;
      Tls_Core.Aead_Channel.Rotate_Sha256 (Out_Dir, Send_Secret);
   end Send_Key_Update;

   ---------------------------------------------------------------------
   --  Process_Inbound_Key_Update — RFC 8446 §4.6.3.
   --
   --  In_Plaintext is the 5-byte handshake-content-type plaintext
   --  decrypted from the peer's KeyUpdate record. We validate it,
   --  rotate the In_Dir + Recv_Secret to the next §7.2 secret, and
   --  surface Want_Reply so the caller can fire Send_Key_Update
   --  (with request_update = update_not_requested) if needed.
   ---------------------------------------------------------------------

   procedure Process_Inbound_Key_Update
     (D            : Driver;
      In_Plaintext : Octet_Array;
      In_Dir       : in out Tls_Core.Aead_Channel.Direction;
      Recv_Secret  : in out Tls_Core.Key_Schedule.Secret;
      Want_Reply   : out Boolean;
      OK           : out Boolean)
   is
      pragma Unreferenced (D);
      Request_Update : Octet;
      Decode_OK : Boolean;
      Next_Secret : Tls_Core.Key_Schedule.Secret;
   begin
      Want_Reply := False;
      OK := False;
      Tls_Core.Key_Update.Decode (In_Plaintext, Request_Update, Decode_OK);
      if not Decode_OK then
         return;
      end if;

      --  Rotate the peer-side decrypt key per §7.2.
      Tls_Core.Key_Update.Derive_Next_Sha256 (Recv_Secret, Next_Secret);
      Recv_Secret := Next_Secret;
      Tls_Core.Aead_Channel.Rotate_Sha256 (In_Dir, Recv_Secret);

      Want_Reply :=
        Request_Update = Tls_Core.Key_Update.Update_Requested;
      OK := True;
   end Process_Inbound_Key_Update;

   ---------------------------------------------------------------------
   --  Alert helpers (RFC 8446 §6).
   --
   --  Build_Plaintext_Alert, Build_Encrypted_Alert, Ensure_App_Out_Dir:
   --  moved to Tls_Core.Tls13_Driver.Helpers.

   ---------------------------------------------------------------------
   --  Set_Sni_Hostname / Sni_Hostname — RFC 6066 §3.
   ---------------------------------------------------------------------

   procedure Set_Sni_Hostname
     (D        : in out Driver;
      Hostname : Octet_Array)
   is
   begin
      D.Sni_Hostname := (others => 0);
      D.Sni_Len := Hostname'Length;
      if Hostname'Length > 0 then
         D.Sni_Hostname (1 .. Hostname'Length) := Hostname;
      end if;
   end Set_Sni_Hostname;

   procedure Sni_Hostname
     (D        : Driver;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is
   begin
      Out_Buf := (others => 0);
      Out_Last := D.Sni_Len;
      if D.Sni_Len > 0 then
         Out_Buf (1 .. D.Sni_Len) := D.Sni_Hostname (1 .. D.Sni_Len);
      end if;
   end Sni_Hostname;

   ---------------------------------------------------------------------
   --  Set_Alpn_Offers / Alpn_Offers / Set_Selected_Alpn /
   --  Selected_Alpn — RFC 7301 + RFC 8446 §4.2.
   ---------------------------------------------------------------------

   procedure Set_Alpn_Offers
     (D     : in out Driver;
      Names : Octet_Array)
   is
   begin
      D.Alpn_Offers := (others => 0);
      D.Alpn_Offers_Len := Names'Length;
      if Names'Length > 0 then
         D.Alpn_Offers (1 .. Names'Length) := Names;
      end if;
   end Set_Alpn_Offers;

   procedure Alpn_Offers
     (D        : Driver;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is
   begin
      Out_Buf := (others => 0);
      Out_Last := D.Alpn_Offers_Len;
      if D.Alpn_Offers_Len > 0 then
         Out_Buf (1 .. D.Alpn_Offers_Len) :=
           D.Alpn_Offers (1 .. D.Alpn_Offers_Len);
      end if;
   end Alpn_Offers;

   procedure Set_Selected_Alpn
     (D    : in out Driver;
      Name : Octet_Array)
   is
   begin
      D.Selected_Alpn := (others => 0);
      D.Selected_Alpn_Len := Name'Length;
      if Name'Length > 0 then
         D.Selected_Alpn (1 .. Name'Length) := Name;
      end if;
   end Set_Selected_Alpn;

   procedure Selected_Alpn
     (D        : Driver;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is
   begin
      Out_Buf := (others => 0);
      Out_Last := D.Selected_Alpn_Len;
      if D.Selected_Alpn_Len > 0 then
         Out_Buf (1 .. D.Selected_Alpn_Len) :=
           D.Selected_Alpn (1 .. D.Selected_Alpn_Len);
      end if;
   end Selected_Alpn;

   ---------------------------------------------------------------------
   --  Send_Close_Notify — RFC 8446 §6.1 graceful shutdown.
   ---------------------------------------------------------------------

   procedure Send_Close_Notify
     (D        : in out Driver;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is
   begin
      Ensure_App_Out_Dir (D);
      Build_Encrypted_Alert
        (D.App_Out_Dir,
         Tls_Core.Alert.Level_Warning,
         Tls_Core.Alert.Desc_Close_Notify,
         Out_Buf, Out_Last);
      D.Last_Alert := Tls_Core.Alert.Desc_Close_Notify;
      D.Cur_State := Closed;
   end Send_Close_Notify;

   ---------------------------------------------------------------------
   --  Send_Fatal_Alert — application-level fatal alert.
   ---------------------------------------------------------------------

   procedure Send_Fatal_Alert
     (D           : in out Driver;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   is
   begin
      case D.Cur_State is
         when Done =>
            Ensure_App_Out_Dir (D);
            Build_Encrypted_Alert
              (D.App_Out_Dir,
               Tls_Core.Alert.Level_Fatal,
               Description, Out_Buf, Out_Last);
         when Idle | Awaiting_CH =>
            Build_Plaintext_Alert
              (Tls_Core.Alert.Level_Fatal,
               Description, Out_Buf, Out_Last);
         when others =>
            --  Excluded by Pre.
            Out_Buf := (others => 0);
            Out_Last := 0;
      end case;
      D.Last_Alert := Description;
      D.Cur_State := Failed;
   end Send_Fatal_Alert;

   ---------------------------------------------------------------------
   --  Send_New_Session_Ticket — RFC 8446 §4.6.1.
   --
   --  Wire shape per §4.6.1: the Handshake message has type 0x04, a
   --  3-byte length, and the NST body. We then encrypt the whole
   --  Handshake message as one TLSCiphertext of inner-content-type
   --  Handshake (§5.4 — post-handshake messages reuse the handshake
   --  inner type but ride on the application_data Aead_Channel).
   ---------------------------------------------------------------------

   procedure Send_New_Session_Ticket
     (D            : Driver;
      Out_Dir      : in out Tls_Core.Aead_Channel.Direction;
      Lifetime     : Tls_Core.Session_Ticket.U32;
      Age_Add      : Tls_Core.Session_Ticket.U32;
      Ticket_Nonce : Octet_Array;
      Ticket_Bytes : Octet_Array;
      Out_Buf      : out Octet_Array;
      Out_Last     : out Natural)
   is
      pragma Unreferenced (D);

      Hs_Type_New_Session_Ticket : constant Octet := 16#04#;

      --  Worst-case body length per Session_Ticket spec.
      Body_Buf : Octet_Array
        (1 .. Tls_Core.Session_Ticket.Max_Nst_Body_Length) :=
          (others => 0);
      Body_Last : Natural;

      --  Handshake-message wrapper (4-byte header + body).
      Hs_Buf : Octet_Array
        (1 .. 4 + Tls_Core.Session_Ticket.Max_Nst_Body_Length) :=
          (others => 0);
      Hs_Last : Natural;
   begin
      Out_Buf := (others => 0);
      Out_Last := 0;

      --  1. Build NST body.
      Tls_Core.Session_Ticket.Encode_Body
        (Lifetime     => Lifetime,
         Age_Add      => Age_Add,
         Ticket_Nonce => Ticket_Nonce,
         Ticket       => Ticket_Bytes,
         Out_Buf      => Body_Buf,
         Out_Last     => Body_Last);

      --  2. Wrap as Handshake message (type 4 + u24 length + body).
      Encode_Hs_Message
        (Hs_Type_New_Session_Ticket,
         Body_Buf (1 .. Body_Last),
         Hs_Buf, Hs_Last);

      --  3. Encrypt the whole Handshake message as one application
      --     traffic record. Inner type is Handshake per §5.4.
      Tls_Core.Aead_Channel.Send
        (Out_Dir,
         Hs_Buf (1 .. Hs_Last),
         Tls_Core.Aead_Channel.Inner_Type_Handshake,
         Out_Buf, Out_Last);
   end Send_New_Session_Ticket;

   ---------------------------------------------------------------------
   --  Receive_New_Session_Ticket — RFC 8446 §4.6.1 client side.
   --
   --  Decrypts one TLSCiphertext record on the application_data
   --  In_Dir, validates that it is a Handshake-type-4 message
   --  carrying a NewSessionTicket body, and inserts the resulting
   --  (ticket, resumption_secret, suite) triple into Cache.
   ---------------------------------------------------------------------

   procedure Receive_New_Session_Ticket
     (D            : Driver;
      In_Dir       : in out Tls_Core.Aead_Channel.Direction;
      Cache        : in out Tls_Core.Session_Cache.Cache;
      Record_Bytes : Octet_Array;
      OK           : out Boolean)
   is
      Hs_Type_New_Session_Ticket : constant Octet := 16#04#;

      Pt_Buf : Octet_Array
        (1 .. 4 + Tls_Core.Session_Ticket.Max_Nst_Body_Length) :=
          (others => 0);
      Pt_Last    : Natural;
      Inner_Type : Octet;
      Decrypt_OK : Boolean;
   begin
      OK := False;

      Tls_Core.Aead_Channel.Receive
        (In_Dir, Record_Bytes,
         Pt_Buf, Pt_Last, Inner_Type, Decrypt_OK);
      if not Decrypt_OK
        or else Inner_Type /=
                  Tls_Core.Aead_Channel.Inner_Type_Handshake
        or else Pt_Last < 4
        or else Pt_Buf (1) /= Hs_Type_New_Session_Ticket
      then
         return;
      end if;

      --  Validate the u24 length matches the rest of the buffer.
      declare
         L : constant Natural :=
           Natural (Pt_Buf (2)) * 65536
           + Natural (Pt_Buf (3)) * 256
           + Natural (Pt_Buf (4));
      begin
         if 4 + L /= Pt_Last then
            return;
         end if;
         if L < 14
           or else L > Tls_Core.Session_Ticket.Max_Nst_Body_Length
         then
            return;
         end if;

         --  Decode body. Body_Slice has 'First = 1 by construction.
         declare
            Body_Slice : constant Octet_Array (1 .. L) :=
              Pt_Buf (5 .. 4 + L);
            Lt   : Tls_Core.Session_Ticket.U32;
            Ag   : Tls_Core.Session_Ticket.U32;
            Nf   : Natural;
            Tf   : Natural;
            Nl   : Integer;
            Tl   : Integer;
            Decode_OK : Boolean;
         begin
            Tls_Core.Session_Ticket.Decode_Body
              (In_Buf       => Body_Slice,
               Lifetime     => Lt,
               Age_Add      => Ag,
               Nonce_First  => Nf,
               Nonce_Last   => Nl,
               Ticket_First => Tf,
               Ticket_Last  => Tl,
               OK           => Decode_OK);
            if not Decode_OK then
               return;
            end if;

            --  Insert into cache. The Decode_Body Post guarantees
            --  the index ranges are valid sub-slices of Body_Slice,
            --  so the slice expressions below are safe.
            if Nl >= Nf then
               Tls_Core.Session_Cache.Insert
                 (C                 => Cache,
                  Lifetime          => Lt,
                  Age_Add           => Ag,
                  Ticket_Nonce      => Body_Slice (Nf .. Nl),
                  Ticket            => Body_Slice (Tf .. Tl),
                  Resumption_Secret => D.Res_Master_Sec,
                  Suite             => D.Suite);
            else
               declare
                  Empty_Nonce : constant Octet_Array (1 .. 0) :=
                    (others => 0);
               begin
                  Tls_Core.Session_Cache.Insert
                    (C                 => Cache,
                     Lifetime          => Lt,
                     Age_Add           => Ag,
                     Ticket_Nonce      => Empty_Nonce,
                     Ticket            => Body_Slice (Tf .. Tl),
                     Resumption_Secret => D.Res_Master_Sec,
                     Suite             => D.Suite);
               end;
            end if;
            OK := True;
         end;
      end;
   end Receive_New_Session_Ticket;

   ---------------------------------------------------------------------
   --  Process_Post_Handshake_Plaintext — RFC 8446 §4.6 demux.
   --
   --  Caller has already AEAD-decrypted one inbound app-data record
   --  via Aead_Channel.Receive (advancing In_Dir.Seq).  We inspect
   --  Inner_Type + Plaintext (1) and dispatch to the existing
   --  per-message primitives.
   ---------------------------------------------------------------------

   procedure Process_Post_Handshake_Plaintext
     (D            : Driver;
      Plaintext    : Octet_Array;
      Inner_Type   : Octet;
      In_Dir       : in out Tls_Core.Aead_Channel.Direction;
      Recv_Secret  : in out Tls_Core.Key_Schedule.Secret;
      Cache        : in out Tls_Core.Session_Cache.Cache;
      Saw_Nst      : out Boolean;
      Saw_KeyUpdate : out Boolean;
      Want_Reply   : out Boolean;
      OK           : out Boolean)
   is
      Hs_Type_New_Session_Ticket : constant Octet := 16#04#;
   begin
      Saw_Nst := False;
      Saw_KeyUpdate := False;
      Want_Reply := False;
      OK := True;

      --  Inner_Type 0x17 (Application_Data) is not our concern —
      --  caller treats Plaintext as app data.
      if Inner_Type /= Tls_Core.Aead_Channel.Inner_Type_Handshake then
         return;
      end if;

      --  RFC 8446 §4.6 post-handshake messages all carry inner type
      --  Handshake (0x16) and start with the §4 handshake header
      --  (1-byte type + uint24 length + body).  Need at least 4
      --  bytes to read the header.
      if Plaintext'Length < 4 then
         OK := False;
         return;
      end if;

      if Plaintext (Plaintext'First) = Hs_Type_New_Session_Ticket then
         --  RFC 8446 §4.6.1.  Validate the header length, then
         --  decode + insert into Cache (mirror of the post-decrypt
         --  block in Receive_New_Session_Ticket).
         declare
            Hi : constant Natural :=
              Natural (Plaintext (Plaintext'First + 1));
            Mid : constant Natural :=
              Natural (Plaintext (Plaintext'First + 2));
            Lo : constant Natural :=
              Natural (Plaintext (Plaintext'First + 3));
            L : constant Natural := Hi * 65536 + Mid * 256 + Lo;
         begin
            if 4 + L /= Plaintext'Length
              or else L < 14
              or else L >
                Tls_Core.Session_Ticket.Max_Nst_Body_Length
            then
               OK := False;
               return;
            end if;
            declare
               Body_Slice : constant Octet_Array (1 .. L) :=
                 Plaintext (Plaintext'First + 4 ..
                            Plaintext'First + 3 + L);
               Lt   : Tls_Core.Session_Ticket.U32;
               Ag   : Tls_Core.Session_Ticket.U32;
               Nf, Tf : Natural;
               Nl, Tl : Integer;
               Decode_OK : Boolean;
            begin
               Tls_Core.Session_Ticket.Decode_Body
                 (In_Buf       => Body_Slice,
                  Lifetime     => Lt,
                  Age_Add      => Ag,
                  Nonce_First  => Nf,
                  Nonce_Last   => Nl,
                  Ticket_First => Tf,
                  Ticket_Last  => Tl,
                  OK           => Decode_OK);
               if not Decode_OK then
                  OK := False;
                  return;
               end if;
               if Nl >= Nf then
                  Tls_Core.Session_Cache.Insert
                    (C                 => Cache,
                     Lifetime          => Lt,
                     Age_Add           => Ag,
                     Ticket_Nonce      => Body_Slice (Nf .. Nl),
                     Ticket            => Body_Slice (Tf .. Tl),
                     Resumption_Secret => D.Res_Master_Sec,
                     Suite             => D.Suite);
               else
                  declare
                     Empty_Nonce : constant Octet_Array (1 .. 0) :=
                       (others => 0);
                  begin
                     Tls_Core.Session_Cache.Insert
                       (C                 => Cache,
                        Lifetime          => Lt,
                        Age_Add           => Ag,
                        Ticket_Nonce      => Empty_Nonce,
                        Ticket            => Body_Slice (Tf .. Tl),
                        Resumption_Secret => D.Res_Master_Sec,
                        Suite             => D.Suite);
                  end;
               end if;
               Saw_Nst := True;
            end;
         end;
      elsif Plaintext (Plaintext'First) =
              Tls_Core.Key_Update.Hs_Type_Key_Update
      then
         --  RFC 8446 §4.6.3.  Process_Inbound_Key_Update operates
         --  on plaintext + rotates In_Dir + Recv_Secret in place.
         --  In_Dir.Seq must be < Last for the Pre to hold; v0.5
         --  callers re-Init the dir each demux call to keep this.
         declare
            Inner_OK : Boolean;
         begin
            Process_Inbound_Key_Update
              (D            => D,
               In_Plaintext => Plaintext,
               In_Dir       => In_Dir,
               Recv_Secret  => Recv_Secret,
               Want_Reply   => Want_Reply,
               OK           => Inner_OK);
            if not Inner_OK then
               OK := False;
               return;
            end if;
            Saw_KeyUpdate := True;
         end;
      else
         --  RFC 8446 §4.6 doesn't define any other post-handshake
         --  handshake-message type for this profile (no Cert_Request
         --  in PSK mode).  Per §6.2 unexpected_message — leave
         --  OK := False; caller decides whether to alert.
         OK := False;
      end if;
   end Process_Post_Handshake_Plaintext;

   ---------------------------------------------------------------------
   --  Init_Psk_Resumption_Client — RFC 8446 §2.2 / §4.6.1.
   --
   --  Derive PSK from (Slot.Resumption_Secret, Slot.Ticket_Nonce);
   --  use Slot.Ticket as the PSK identity. After this, Step proceeds
   --  exactly as for Init_Psk_Client.
   ---------------------------------------------------------------------

   procedure Init_Psk_Resumption_Client
     (D    : out Driver;
      Slot : Tls_Core.Session_Cache.Slot)
   is
      Derived_Psk : Tls_Core.Key_Schedule.Secret;
      Priv_32     : Tls_Core.X25519.Bytes_32;
      Pub_32      : Tls_Core.X25519.Bytes_32;
   begin
      --  Compute the resumption-PSK on the spot.
      Tls_Core.Session_Ticket.Derive_Psk_From_Ticket_Sha256
        (Resumption_Secret => Slot.Resumption_Secret,
         Ticket_Nonce      =>
           Slot.Ticket_Nonce (1 .. Slot.Ticket_Nonce_Len),
         Psk               => Derived_Psk);

      --  Initialise as a regular PSK client (the existing PSK_KE
      --  path drives the handshake).
      D.My_Role := Client;
      D.Cur_State := Idle;
      Tls_Core.Transcript.Init (D.Hash_Ctx);
      D.PSK := Derived_Psk;
      D.Identity := (others => 0);
      D.Identity_Len := Slot.Ticket_Len;
      D.Identity (1 .. Slot.Ticket_Len) :=
        Slot.Ticket (1 .. Slot.Ticket_Len);
      D.Is_Resumption := True;  --  use "res binder" label
      D.App_Set := False;
      Prime_Driver_Defaults (D);
      D.Hrr_Demand    := False;
      D.Hrr_Sent      := False;
      D.Hrr_Aware     := False;
      D.Hrr_Seen      := False;
      D.Hrr_Group     := Tls_Core.Suites.Group_Secp256r1;
      D.Hrr_Cookie    := (others => 0);
      D.Hrr_Cookie_Len := 0;
      D.Hrr_Ch1_Hash  := (others => 0);
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
      D.My_Ecdhe_Pub  := Pub_32;
      D.Peer_Ecdhe_Pub := (others => 0);
      D.Ecdhe_Shared := (others => 0);
   end Init_Psk_Resumption_Client;

end Tls_Core.Tls13_Driver;
