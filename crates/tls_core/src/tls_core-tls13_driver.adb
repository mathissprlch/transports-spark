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
with Tls_Core.Key_Sched;
with Tls_Core.Tls13_Driver.Helpers;
with Tls_Core.Tls13_Driver.Step_Awaiting_Cf;
with Tls_Core.Tls13_Driver.Step_Awaiting_Ch;
with Tls_Core.Tls13_Driver.Step_Hrr;
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
            Step_Hrr.Handle_Sh_Or_Hrr (D, In_Bytes, Out_Buf, Out_Last);

         when Awaiting_Ch_2 =>
            Step_Hrr.Handle_Ch_2 (D, In_Bytes, Out_Buf, Out_Last);

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
