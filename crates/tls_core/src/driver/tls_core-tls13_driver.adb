with Tls_Core.Tls13_Driver.Helpers;
with Tls_Core.Tls13_Driver.Step_Awaiting_Cf;
with Tls_Core.Tls13_Driver.Step_Awaiting_Ch;
with Tls_Core.Tls13_Driver.Step_Awaiting_Ch_Cert;
with Tls_Core.Tls13_Driver.Step_Hrr;
with Tls_Core.Tls13_Driver.Step_Awaiting_Sf;
with Tls_Core.Tls13_Driver.Step_Awaiting_Sf_Cert;
with Tls_Core.Tls13_Driver.Step_Idle;
with Tls_Core.X25519;

package body Tls_Core.Tls13_Driver
  with SPARK_Mode
is



   use Helpers;

   procedure Init_Psk_Server
     (D            : out Driver;
      PSK          : Octet_Array;
      Psk_Identity : Octet_Array;
      Ecdhe_Priv   : Octet_Array)
   is separate;

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
   is separate;

   procedure Init_Psk_Client
     (D            : out Driver;
      PSK          : Octet_Array;
      Psk_Identity : Octet_Array;
      Ecdhe_Priv   : Octet_Array)
   is separate;

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
   is separate;

   ---------------------------------------------------------------------
   --  Init_Psk_Server_With_Hrr / Init_Psk_Client_Hrr_Aware
   --  (RFC 8446 §4.1.4 — HelloRetryRequest)
   ---------------------------------------------------------------------

   procedure Init_Psk_Server_With_Hrr
     (D              : out Driver;
      PSK            : Octet_Array;
      Psk_Identity   : Octet_Array;
      Ecdhe_Priv     : Octet_Array;
      Demanded_Group : Tls_Core.Suites.U16;
      Cookie         : Octet_Array)
   is separate;

   procedure Init_Psk_Client_Hrr_Aware
     (D            : out Driver;
      PSK          : Octet_Array;
      Psk_Identity : Octet_Array;
      Ecdhe_Priv   : Octet_Array)
   is separate;

   --  Helpers (Fail_Plaintext, Fail_Encrypted, Build_Finished_Body,
   --  Encode_Hs_Message, Wrap_Tls_Plaintext, constants) moved to
   --  Tls_Core.Tls13_Driver.Helpers.

   ---------------------------------------------------------------------
   --  Step — server side, PSK_KE profile.
   ---------------------------------------------------------------------

   procedure Step
     (D        : in out Driver;
      In_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is separate;

   procedure Open_App_Directions
     (D          : Driver;
      Out_Dir    : out Tls_Core.Aead_Channel.Direction;
      In_Dir     : out Tls_Core.Aead_Channel.Direction;
      Out_Secret : out Tls_Core.Key_Sched.Max_Secret;
      In_Secret  : out Tls_Core.Key_Sched.Max_Secret) is
   begin
      case D.My_Role is
         when Server =>
            --  Server: out encrypts with s_ap; in decrypts with c_ap.
            Out_Secret := D.App_S_Ap;
            In_Secret := D.App_C_Ap;
            Tls_Core.Key_Sched.Init_Hs_Channel (D.Suite, Out_Dir, Out_Secret);
            Tls_Core.Key_Sched.Init_Hs_Channel (D.Suite, In_Dir, In_Secret);

         when Client =>
            --  Client: out encrypts with c_ap; in decrypts with s_ap.
            Out_Secret := D.App_C_Ap;
            In_Secret := D.App_S_Ap;
            Tls_Core.Key_Sched.Init_Hs_Channel (D.Suite, Out_Dir, Out_Secret);
            Tls_Core.Key_Sched.Init_Hs_Channel (D.Suite, In_Dir, In_Secret);
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
      Discard_Out_Sec : Tls_Core.Key_Sched.Max_Secret;
      Discard_In_Sec  : Tls_Core.Key_Sched.Max_Secret;
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
      Send_Secret    : in out Tls_Core.Key_Sched.Max_Secret;
      Request_Update : Octet;
      Out_Buf        : out Octet_Array;
      Out_Last       : out Natural)
   is separate;

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
      Recv_Secret  : in out Tls_Core.Key_Sched.Max_Secret;
      Want_Reply   : out Boolean;
      OK           : out Boolean)
   is separate;

   ---------------------------------------------------------------------
   --  Alert helpers (RFC 8446 §6).
   --
   --  Build_Plaintext_Alert, Build_Encrypted_Alert, Ensure_App_Out_Dir:
   --  moved to Tls_Core.Tls13_Driver.Helpers.

   ---------------------------------------------------------------------
   --  Set_Sni_Hostname / Sni_Hostname — RFC 6066 §3.
   ---------------------------------------------------------------------

   procedure Set_Sni_Hostname (D : in out Driver; Hostname : Octet_Array) is
   begin
      D.Sni_Hostname := [others => 0];
      D.Sni_Len := Hostname'Length;
      if Hostname'Length > 0 then
         D.Sni_Hostname (1 .. Hostname'Length) := Hostname;
      end if;
   end Set_Sni_Hostname;

   procedure Sni_Hostname
     (D : Driver; Out_Buf : out Octet_Array; Out_Last : out Natural) is
   begin
      Out_Buf := [others => 0];
      Out_Last := D.Sni_Len;
      if D.Sni_Len > 0 then
         Out_Buf (1 .. D.Sni_Len) := D.Sni_Hostname (1 .. D.Sni_Len);
      end if;
   end Sni_Hostname;

   ---------------------------------------------------------------------
   --  Set_Alpn_Offers / Alpn_Offers / Set_Selected_Alpn /
   --  Selected_Alpn — RFC 7301 + RFC 8446 §4.2.
   ---------------------------------------------------------------------

   procedure Set_Alpn_Offers (D : in out Driver; Names : Octet_Array) is
   begin
      D.Alpn_Offers := [others => 0];
      D.Alpn_Offers_Len := Names'Length;
      if Names'Length > 0 then
         D.Alpn_Offers (1 .. Names'Length) := Names;
      end if;
   end Set_Alpn_Offers;

   procedure Alpn_Offers
     (D : Driver; Out_Buf : out Octet_Array; Out_Last : out Natural) is
   begin
      Out_Buf := [others => 0];
      Out_Last := D.Alpn_Offers_Len;
      if D.Alpn_Offers_Len > 0 then
         Out_Buf (1 .. D.Alpn_Offers_Len) :=
           D.Alpn_Offers (1 .. D.Alpn_Offers_Len);
      end if;
   end Alpn_Offers;

   procedure Set_Selected_Alpn (D : in out Driver; Name : Octet_Array) is
   begin
      D.Selected_Alpn := [others => 0];
      D.Selected_Alpn_Len := Name'Length;
      if Name'Length > 0 then
         D.Selected_Alpn (1 .. Name'Length) := Name;
      end if;
   end Set_Selected_Alpn;

   procedure Selected_Alpn
     (D : Driver; Out_Buf : out Octet_Array; Out_Last : out Natural) is
   begin
      Out_Buf := [others => 0];
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
     (D : in out Driver; Out_Buf : out Octet_Array; Out_Last : out Natural)
   is separate;

   ---------------------------------------------------------------------
   --  Send_Fatal_Alert — application-level fatal alert.
   ---------------------------------------------------------------------

   procedure Send_Fatal_Alert
     (D           : in out Driver;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   is separate;

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
   is separate;

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
   is separate;

   ---------------------------------------------------------------------
   --  Process_Post_Handshake_Plaintext — RFC 8446 §4.6 demux.
   --
   --  Caller has already AEAD-decrypted one inbound app-data record
   --  via Aead_Channel.Receive (advancing In_Dir.Seq).  We inspect
   --  Inner_Type + Plaintext (1) and dispatch to the existing
   --  per-message primitives.
   ---------------------------------------------------------------------

   procedure Process_Post_Handshake_Plaintext
     (D             : Driver;
      Plaintext     : Octet_Array;
      Inner_Type    : Octet;
      In_Dir        : in out Tls_Core.Aead_Channel.Direction;
      Recv_Secret   : in out Tls_Core.Key_Sched.Max_Secret;
      Cache         : in out Tls_Core.Session_Cache.Cache;
      Saw_Nst       : out Boolean;
      Saw_KeyUpdate : out Boolean;
      Want_Reply    : out Boolean;
      OK            : out Boolean)
   is separate;

   ---------------------------------------------------------------------
   --  Init_Psk_Resumption_Client — RFC 8446 §2.2 / §4.6.1.
   --
   --  Derive PSK from (Slot.Resumption_Secret, Slot.Ticket_Nonce);
   --  use Slot.Ticket as the PSK identity. After this, Step proceeds
   --  exactly as for Init_Psk_Client.
   ---------------------------------------------------------------------

   procedure Init_Psk_Resumption_Client
     (D : out Driver; Slot : Tls_Core.Session_Cache.Slot)
   is separate;

end Tls_Core.Tls13_Driver;
