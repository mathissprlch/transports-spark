--  Tls_Core.Tls13_Driver — spec-compliant TLS 1.3 handshake driver.
--
--  Distinct from Tls_Core.Handshake_Driver: this version emits
--  proper TLSPlaintext / TLSCiphertext records on the wire,
--  encrypts the handshake messages after ServerHello under the
--  handshake_traffic_secret, sends the mandatory
--  EncryptedExtensions message (RFC 8446 §4.3.1), and follows the
--  RFC 8446 §5.2 TLSInnerPlaintext content-type-byte convention.
--
--  Required for any external-reference-impl interop (openssl,
--  grpcurl, browsers) — those peers reject the simplified-record
--  shape Handshake_Driver emits.
--
--  This slice supports the **psk_dhe_ke** profile (RFC 8446 §7.1
--  mode 3 — PSK + ECDHE) with **runtime cipher-suite negotiation**:
--  the client offers all three v0.5 production suites in §B.4
--  preference order, advertises `psk_dhe_ke` (the byte 0x01 in the
--  psk_key_exchange_modes extension), the server picks the first
--  acceptable suite, and both sides exchange X25519 key shares
--  whose shared secret is threaded into the Handshake-Secret
--  HKDF-Extract step. Send / Receive go through
--  Tls_Core.Aead_Channel which dispatches the AEAD primitive on
--  the negotiated suite.
--
--  Mode 1 (psk_ke — PSK without DHE) is **not implemented** in
--  the driver per CLAUDE.md §0a (RFC 8446 §A.2 discourages it; no
--  production peer accepts it by default). The wire-format
--  scaffolding in Tls_Core.Hello.Encode_Client_Hello_Psk now
--  always emits psk_dhe_ke with a key_share, never plain psk_ke.
--
--  Wall-hit (left visible): the SHA-384 key-schedule path through
--  Tls13_Driver is not yet ported. The driver therefore restricts
--  its server-side selection to the two SHA-256-based suites
--  (TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256). If the
--  client offers only TLS_AES_256_GCM_SHA384, the server fails the
--  handshake (handshake_failure equivalent). Aead_Channel itself
--  fully supports all three suites (see Aead_Channel round-trip
--  scenarios in tls_core_tests).

with Tls_Core.Aead_Channel;
with Tls_Core.Alert;
with Tls_Core.Handshake_Buffer;
with Tls_Core.Hello_Retry;
with Tls_Core.Key_Schedule;
with Tls_Core.Key_Update;
with Tls_Core.Record_Layer;
with Tls_Core.Session_Cache;
with Tls_Core.Session_Ticket;
with Tls_Core.Sha256;
with Tls_Core.Suites;
with Tls_Core.Transcript;

package Tls_Core.Tls13_Driver
with SPARK_Mode
is

   use type Tls_Core.Suites.Cipher_Suite_Id;

   pragma Unevaluated_Use_Of_Old (Allow);

   use type Tls_Core.Octet;
   use type Tls_Core.Suites.Cipher_Suite_Id;
   use type Tls_Core.Record_Layer.Seq_Number;

   type Role is (Client, Server);

   --  Driver states for the HRR-aware PSK_KE flow (RFC 8446 §4.1.4).
   --
   --  Client linear progression:
   --    Idle → Awaiting_Sh_Or_Hrr →  (HRR seen)  → Awaiting_Sf
   --                              \
   --                               → (SH seen)  → Awaiting_Sf path inline
   --    Awaiting_Sf → Awaiting_Cf-equivalent (SH+EE+SF) → Done
   --
   --  Server linear progression (HRR demanded):
   --    Awaiting_CH → (Hrr_Demand True) → Awaiting_Ch_2 → Awaiting_Cf → Done
   --                \
   --                 → (Hrr_Demand False) → Awaiting_Cf → Done
   --
   --  Awaiting_Sh_Or_Hrr / Awaiting_Ch_2 are the new states added for
   --  HRR support; the existing PSK_KE states keep their semantics so
   --  the non-HRR flow at Init_Psk_{Server,Client} remains unchanged.
   type State is
     (Idle,                --  Client's initial state (non-HRR mode).
      Awaiting_CH,         --  Server's initial state.
      Awaiting_Sh_Or_Hrr,  --  Client sent CH1; awaiting SH or HRR.
      Awaiting_Ch_2,       --  Server sent HRR; awaiting CH2.
      Awaiting_Sf,         --  Client sent CH; awaiting SH+EE+SF flight.
      Awaiting_Cf,         --  Server sent SH+EE+SF; awaiting client Finished.
      Done,
      Closed,             --  Graceful shutdown — close_notify sent or
                          --  received after Done. RFC 8446 §6.1.
      Failed);

   type Driver is private;

   --  Initialise as psk_dhe_ke (mode 3) server. The PSK is the same
   --  byte string the peer (e.g. openssl s_client -psk) uses;
   --  Identity is the external PSK identity it advertises.
   --  Ecdhe_Priv is the server's X25519 private scalar for the
   --  ephemeral key share; the public key is derived during init
   --  via Tls_Core.X25519.Derive_Public.
   procedure Init_Psk_Server
     (D            : out Driver;
      PSK          : Octet_Array;
      Psk_Identity : Octet_Array;
      Ecdhe_Priv   : Octet_Array)
   with
     Pre =>
       PSK'Length = 32
       and then Psk_Identity'Length in 1 .. 64
       and then Ecdhe_Priv'Length = 32;

   --  Initialise as psk_dhe_ke (mode 3) client.
   procedure Init_Psk_Client
     (D            : out Driver;
      PSK          : Octet_Array;
      Psk_Identity : Octet_Array;
      Ecdhe_Priv   : Octet_Array)
   with
     Pre =>
       PSK'Length = 32
       and then Psk_Identity'Length in 1 .. 64
       and then Ecdhe_Priv'Length = 32;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  HRR-aware initialisation (RFC 8446 §4.1.4).
   --
   --  Standard:    RFC 8446 §4.1.4 (HelloRetryRequest), §4.4.1
   --               (transcript-hash quirk).
   --  Spec mirror: miTLS src/tls/MiTLS.Handshake.Server.fst :
   --               processClientHello (HRR branch).
   --
   --  Behaviour:   Init_Psk_Server_With_Hrr forces the server to
   --               emit one HRR after the first CH and await a CH2
   --               carrying the named-group + cookie echo; only then
   --               does it run the §4.1.3 SH+EE+SF emission. Cookie
   --               is the 1..32 byte caller-supplied bytestring the
   --               server expects the client to echo back. The
   --               client side calls Init_Psk_Client_Hrr_Aware so
   --               its initial Step transitions to Awaiting_Sh_Or_Hrr
   --               instead of Awaiting_Sf.
   --
   --  Functional:  No functional Post — wire layout is exercised
   --               end-to-end via the HRR loopback test scenario.
   --  Proven at:   gnatprove --level=2 (audit-clean) — body sets
   --               record fields only.
   --------------------------------------------------------------------
   procedure Init_Psk_Server_With_Hrr
     (D                 : out Driver;
      PSK               : Octet_Array;
      Psk_Identity      : Octet_Array;
      Ecdhe_Priv        : Octet_Array;
      Demanded_Group    : Tls_Core.Suites.U16;
      Cookie            : Octet_Array)
   with
     Pre =>
       PSK'Length = 32
       and then Psk_Identity'Length in 1 .. 64
       and then Ecdhe_Priv'Length = 32
       and then Cookie'Length in 0 .. Tls_Core.Hello_Retry.Max_Cookie_Length;

   procedure Init_Psk_Client_Hrr_Aware
     (D            : out Driver;
      PSK          : Octet_Array;
      Psk_Identity : Octet_Array;
      Ecdhe_Priv   : Octet_Array)
   with
     Pre =>
       PSK'Length = 32
       and then Psk_Identity'Length in 1 .. 64
       and then Ecdhe_Priv'Length = 32;

   --  Drive one flight. Caller hands in the bytes received over
   --  TCP since the last Step (one or more TLSPlaintext /
   --  TLSCiphertext records concatenated). Driver writes the
   --  outbound flight to Out_Buf — also a concatenation of records.
   --
   --  No functional Post: the per-state RFC 8446 §4 / §7.1 mode-1
   --  PSK_KE transitions are exercised end-to-end via the
   --  RFC 8448 PSK vector at the test-harness level.
   procedure Step
     (D         : in out Driver;
      In_Bytes  : Octet_Array;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 1024,
     Post =>
       Out_Last in 0 .. Out_Buf'Last;

   function Current_State (D : Driver) return State;

   --  Selected cipher suite — meaningful after Step has reached
   --  Awaiting_Sf (client) or Awaiting_Cf (server). Until then, the
   --  default Chacha20_Poly1305_Sha256 is returned.
   function Selected_Suite (D : Driver) return Tls_Core.Suites.Cipher_Suite_Id;

   --------------------------------------------------------------------
   --  Alert protocol — RFC 8446 §6 surface.
   --------------------------------------------------------------------

   --  When Step transitions to Failed, this returns the
   --  AlertDescription byte the driver would send over the wire.
   --  Defaults to Desc_Internal_Error before any failure has been
   --  recorded; defaults to 0 (Desc_Close_Notify) on Closed.
   function Last_Alert_Description (D : Driver) return Octet;

   --  True iff the driver has derived the application traffic
   --  secrets — Step transitions to Done only after this is set,
   --  but the converse isn't enforced by the type system, so the
   --  alert APIs require the predicate explicitly.
   function App_Secrets_Set (D : Driver) return Boolean;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Build a §6.1 close_notify alert record for
   --                      graceful shutdown after the handshake.
   --
   --  Standard:    RFC 8446 §6.1 (close_notify is sent at end of
   --               session; recipient MUST NOT send any further
   --               application_data).
   --
   --  After Done, the local side encrypts an Alert{warning,
   --  close_notify} under the application traffic secret and writes
   --  the resulting TLSCiphertext to Out_Buf. State transitions to
   --  Closed. Caller is responsible for putting the bytes on the
   --  wire and (if both sides have closed) tearing the TCP socket.
   --
   --  Functional:  Out_Last is the length of one TLSCiphertext
   --               record carrying the encoded close_notify Alert.
   --               D.Cur_State after the call is Closed.
   --  Proven at:   gnatprove --level=2 (audit-clean) — body builds
   --               2-byte alert, calls Aead_Channel.Send.
   --------------------------------------------------------------------
   procedure Send_Close_Notify
     (D        : in out Driver;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   with
     Pre =>
       Current_State (D) = Done
       and then App_Secrets_Set (D)
       and then (Selected_Suite (D) = Tls_Core.Suites.Chacha20_Poly1305_Sha256
                 or else Selected_Suite (D)
                           = Tls_Core.Suites.Aes_128_Gcm_Sha256)
       and then Out_Buf'First = 1
       and then Out_Buf'Length >= 5 + 2 + 1 + 16;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Build a fatal alert record (encrypted if
   --                      handshake-stage keys exist; plaintext
   --                      otherwise) for the given description.
   --
   --  Standard:    RFC 8446 §6.2.
   --
   --  Marks the driver Failed. Out_Buf holds one TLSCiphertext (or
   --  TLSPlaintext, if no keys are derived yet) carrying the alert.
   --
   --  Use this when the application layer detects an error the
   --  driver itself cannot detect (e.g. ALPN rejection).
   --------------------------------------------------------------------
   procedure Send_Fatal_Alert
     (D           : in out Driver;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   with
     Pre =>
       (Current_State (D) in Idle | Awaiting_CH | Done)
       and then (Selected_Suite (D) = Tls_Core.Suites.Chacha20_Poly1305_Sha256
                 or else Selected_Suite (D)
                           = Tls_Core.Suites.Aes_128_Gcm_Sha256)
       and then (if Current_State (D) = Done then App_Secrets_Set (D))
       and then Out_Buf'First = 1
       and then Out_Buf'Length >= 5 + 2 + 1 + 16;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Open application-data Aead_Channel
   --                      directions (after Done).
   --
   --  Standard:    RFC 8446 §7.3 (per-direction key/IV derivation
   --               from c_ap / s_ap traffic secrets)
   --  Spec mirror: miTLS src/tls/MiTLS.KS.fst : derive_app_keys
   --
   --  Functional:  Out_Dir.Suite = D.Selected_Suite ∧
   --               In_Dir.Suite  = D.Selected_Suite. Sequence numbers
   --               start at 0; nonces are unique per RFC 8446 §5.3.
   --  Proven at:   gnatprove --level=2 (audit-clean) — body is
   --               Aead_Channel.Init_Sha256 dispatch only.
   --
   --  Server: encrypts outbound with server_application_traffic_secret;
   --          decrypts inbound with client_application_traffic_secret.
   --
   --  Out_Secret / In_Secret echo back the *current* traffic secrets
   --  used to derive (Out_Dir, In_Dir). They start equal to the
   --  application_traffic_secret_0 the handshake produced and are
   --  the values the §4.6.3 KeyUpdate handler rotates with
   --  Send_Key_Update / Process_Inbound_Key_Update.
   --------------------------------------------------------------------
   procedure Open_App_Directions
     (D          : Driver;
      Out_Dir    : out Tls_Core.Aead_Channel.Direction;
      In_Dir     : out Tls_Core.Aead_Channel.Direction;
      Out_Secret : out Tls_Core.Key_Schedule.Secret;
      In_Secret  : out Tls_Core.Key_Schedule.Secret)
   with Pre => Current_State (D) = Done;

   --  Backward-compat shim that drops the secrets — pre-KeyUpdate
   --  callers don't need them. New code should use the four-out
   --  variant so it can drive KeyUpdate later.
   procedure Open_App_Directions
     (D       : Driver;
      Out_Dir : out Tls_Core.Aead_Channel.Direction;
      In_Dir  : out Tls_Core.Aead_Channel.Direction)
   with
     Pre =>
       Current_State (D) = Done
       and then (Selected_Suite (D) = Tls_Core.Suites.Chacha20_Poly1305_Sha256
                 or else Selected_Suite (D)
                           = Tls_Core.Suites.Aes_128_Gcm_Sha256)
       and then not Out_Dir'Constrained
       and then not In_Dir'Constrained;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Send a KeyUpdate post-handshake message
   --                      and rotate the local send key.
   --
   --  Standard:    RFC 8446 §4.6.3 (KeyUpdate) + §7.2 (next traffic
   --               secret derivation).
   --  Spec mirror: miTLS src/tls/MiTLS.Handshake.Server.fst : rekey
   --
   --  Functional:  Out_Buf (1 .. Out_Last) is one TLSCiphertext
   --               record (handshake content type) carrying the
   --               5-byte KeyUpdate message, encrypted under the
   --               *current* Send_Secret + Out_Dir state. AFTER
   --               sending, Send_Secret is replaced with
   --               next_traffic_secret and Out_Dir is re-keyed +
   --               sequence reset to 0.
   --  Proven at:   gnatprove --level=2 (audit-clean) — composition
   --               of Key_Update.Encode + Aead_Channel.Send +
   --               Key_Update.Derive_Next_Sha256 +
   --               Aead_Channel.Rotate_Sha256.
   --
   --  Pre rules out the SHA-384 path; the driver only completes
   --  handshakes on SHA-256-based suites today (see §package
   --  wall-hit note on `Step`).
   --------------------------------------------------------------------
   procedure Send_Key_Update
     (D              : Driver;
      Out_Dir        : in out Tls_Core.Aead_Channel.Direction;
      Send_Secret    : in out Tls_Core.Key_Schedule.Secret;
      Request_Update : Octet;
      Out_Buf        : out Octet_Array;
      Out_Last       : out Natural)
   with
     Pre  =>
       Current_State (D) = Done
       and then Out_Buf'First = 1
       and then Out_Buf'Length >= 64
       and then (Request_Update = Tls_Core.Key_Update.Update_Not_Requested
                 or else Request_Update =
                           Tls_Core.Key_Update.Update_Requested)
       and then (Selected_Suite (D) =
                   Tls_Core.Suites.Chacha20_Poly1305_Sha256
                 or else Selected_Suite (D) =
                   Tls_Core.Suites.Aes_128_Gcm_Sha256)
       and then Out_Dir.Suite = Selected_Suite (D)
       and then Tls_Core.Aead_Channel.Seq_Of (Out_Dir)
                  < Tls_Core.Record_Layer.Seq_Number'Last,
     Post =>
       Out_Last in 0 .. Out_Buf'Last
       and then Out_Dir.Suite = Out_Dir.Suite'Old;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Process a decrypted KeyUpdate plaintext:
   --                      validate, rotate the local recv key, and
   --                      flag whether we owe a reply.
   --
   --  Standard:    RFC 8446 §4.6.3 — the receiver always rotates
   --               the peer's traffic secret; if request_update = 1
   --               the receiver MUST send its own KeyUpdate (with
   --               request_update = 0) before any further
   --               application data on the send direction.
   --
   --  Functional:  When OK = True, In_Dir + Recv_Secret are
   --               rotated to the next §7.2 secret. Want_Reply is
   --               True iff the peer's request_update byte equals
   --               Update_Requested. When OK = False the inputs
   --               are unchanged and the caller MUST treat this
   --               as fatal illegal_parameter (§4.6.3).
   --  Proven at:   gnatprove --level=2 (audit-clean).
   --
   --  In_Plaintext is the decrypted handshake-content-type
   --  TLSInnerPlaintext, i.e. exactly what Aead_Channel.Receive
   --  returned with Inner_Type = Inner_Type_Handshake.
   --------------------------------------------------------------------
   procedure Process_Inbound_Key_Update
     (D            : Driver;
      In_Plaintext : Octet_Array;
      In_Dir       : in out Tls_Core.Aead_Channel.Direction;
      Recv_Secret  : in out Tls_Core.Key_Schedule.Secret;
      Want_Reply   : out Boolean;
      OK           : out Boolean)
   with
     Pre =>
       Current_State (D) = Done
       and then (Selected_Suite (D) =
                   Tls_Core.Suites.Chacha20_Poly1305_Sha256
                 or else Selected_Suite (D) =
                   Tls_Core.Suites.Aes_128_Gcm_Sha256)
       and then In_Dir.Suite = Selected_Suite (D),
     Post =>
       In_Dir.Suite = In_Dir.Suite'Old;

   --------------------------------------------------------------------
   --  Session resumption — RFC 8446 §4.6.1 NewSessionTicket and
   --                       §2.2 / §4.6.1 resumption flow.
   --
   --  Three entry points wire the NewSessionTicket post-handshake
   --  message and the resumption flow into the existing PSK_KE
   --  driver:
   --
   --    1. Send_New_Session_Ticket — server-side; builds an NST
   --       record on the application_data Aead_Channel after Done.
   --
   --    2. Receive_New_Session_Ticket — client-side; parses an NST
   --       record received on the application_data Aead_Channel
   --       and inserts the (ticket, resumption_secret) pair into
   --       a Session_Cache.
   --
   --    3. Init_Psk_Resumption_Client — initialise a fresh client
   --       Driver from a previously-stored Slot, deriving the
   --       resumption-PSK on the spot (RFC 8446 §4.6.1) and feeding
   --       it into the same PSK_KE Step path as Init_Psk_Client.
   --       (For v0.5: drives the existing PSK_KE driver. Once the
   --       parallel C7 mode-3 / psk_dhe_ke track lands, this routine
   --       becomes the entry point for resumed psk_dhe_ke handshakes.)
   --
   --  All three routines work on SHA-256-based suites only — same
   --  scope as the rest of the driver (see package wall-hit note).
   --------------------------------------------------------------------

   --  True after Step has reached Done AND the resumption_master_secret
   --  was successfully derived per RFC 8446 §7.1. Required precondition
   --  for both Send_New_Session_Ticket (server) and the lookup flow
   --  that culminates in Receive_New_Session_Ticket (client).
   function Resumption_Master_Secret_Available (D : Driver) return Boolean;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Build a NewSessionTicket post-handshake
   --                      message (server only) and write it as one
   --                      encrypted application_data record into
   --                      Out_Buf using the application Aead_Channel
   --                      Out_Dir the caller already opened.
   --
   --  Standard:    RFC 8446 §4.6.1 (NewSessionTicket).
   --  Spec mirror: miTLS src/tls/MiTLS.Handshake.Server.fst :
   --                 server_send_new_ticket
   --
   --  Functional:  Out_Buf (1 .. Out_Last) is one TLSCiphertext
   --               record carrying a Handshake-type-4 message whose
   --               body decodes via Session_Ticket.Decode_Body. The
   --               (resumption_master_secret, ticket_nonce) pair
   --               recreated on the receiving side reconstructs the
   --               PSK that this Driver already used for the binder.
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --
   --  Out_Buf must be large enough for one encrypted record carrying
   --  the worst-case NST body (1548 bytes) plus the 4-byte handshake
   --  header, the 5-byte record header, the 1-byte inner type, and
   --  the 16-byte AEAD tag. 2048 covers it with margin.
   --------------------------------------------------------------------
   procedure Send_New_Session_Ticket
     (D            : Driver;
      Out_Dir      : in out Tls_Core.Aead_Channel.Direction;
      Lifetime     : Tls_Core.Session_Ticket.U32;
      Age_Add      : Tls_Core.Session_Ticket.U32;
      Ticket_Nonce : Octet_Array;
      Ticket_Bytes : Octet_Array;
      Out_Buf      : out Octet_Array;
      Out_Last     : out Natural)
   with
     Pre =>
       Current_State (D) = Done
       and then Resumption_Master_Secret_Available (D)
       and then Out_Buf'First = 1
       and then Out_Buf'Length >= 2048
       and then Ticket_Nonce'Length in
         0 .. Tls_Core.Session_Ticket.Max_Ticket_Nonce_Length
       and then Ticket_Bytes'Length in
         1 .. Tls_Core.Session_Ticket.Max_Ticket_Length
       and then Out_Dir.Suite = Selected_Suite (D)
       and then (Out_Dir.Suite = Tls_Core.Suites.Chacha20_Poly1305_Sha256
                 or else Out_Dir.Suite =
                           Tls_Core.Suites.Aes_128_Gcm_Sha256)
       and then Tls_Core.Aead_Channel.Seq_Of (Out_Dir)
                  < Tls_Core.Record_Layer.Seq_Number'Last,
     Post =>
       Out_Last in 0 .. Out_Buf'Last
       and then Out_Dir.Suite = Out_Dir.Suite'Old;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Consume one TLSCiphertext record on the
   --                      application_data In_Dir, treat it as a
   --                      NewSessionTicket post-handshake message,
   --                      and insert the resulting (ticket,
   --                      resumption_secret, suite) tuple into
   --                      Cache.
   --
   --  Standard:    RFC 8446 §4.6.1 (NewSessionTicket consumption).
   --  Spec mirror: miTLS src/tls/MiTLS.Handshake.Client.fst :
   --                 client_recv_new_ticket
   --
   --  Functional:  When OK = True, at least one slot in Cache has
   --               Used = True (and matches the wire-decoded fields).
   --               When OK = False, Cache is unchanged.
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --
   --  Record_Bytes is one TLSCiphertext record exactly as it came
   --  off the wire. Pre-bound: 4096 bytes covers the largest NST
   --  shape we accept (1548-byte body + 4-byte HS header + 5-byte
   --  record header + 1-byte inner type + 16-byte AEAD tag, with
   --  margin).
   --------------------------------------------------------------------
   procedure Receive_New_Session_Ticket
     (D            : Driver;
      In_Dir       : in out Tls_Core.Aead_Channel.Direction;
      Cache        : in out Tls_Core.Session_Cache.Cache;
      Record_Bytes : Octet_Array;
      OK           : out Boolean)
   with
     Pre =>
       Current_State (D) = Done
       and then Resumption_Master_Secret_Available (D)
       and then Record_Bytes'First = 1
       and then Record_Bytes'Length in (5 + 1 + 16) .. 4096
       and then In_Dir.Suite = Selected_Suite (D)
       and then (In_Dir.Suite = Tls_Core.Suites.Chacha20_Poly1305_Sha256
                 or else In_Dir.Suite =
                           Tls_Core.Suites.Aes_128_Gcm_Sha256)
       and then Tls_Core.Aead_Channel.Seq_Of (In_Dir)
                  < Tls_Core.Record_Layer.Seq_Number'Last,
     Post =>
       In_Dir.Suite = In_Dir.Suite'Old;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Initialise as a resumption client. The PSK
   --                      itself is computed on the spot from the
   --                      stored resumption_master_secret + ticket_nonce
   --                      (RFC 8446 §4.6.1); the opaque ticket bytes
   --                      become the PSK identity.
   --
   --  After this call, Step proceeds exactly as for Init_Psk_Client.
   --  Once the parallel C7 mode-3 (psk_dhe_ke) track lands, this
   --  entry point becomes the canonical resumption initialiser.
   --
   --  Standard:    RFC 8446 §2.2, §4.2.11, §4.6.1.
   --  Spec mirror: miTLS src/tls/MiTLS.KS.fst : ks_client_13_resume_init
   --
   --  Functional:  D.PSK = Session_Ticket.Derive_Psk_From_Ticket_Sha256
   --               (Slot.Resumption_Secret, Slot.Ticket_Nonce). D.Identity
   --               = Slot.Ticket. D.Cur_State = Idle (ready for the
   --               first Step that emits the resumption ClientHello).
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --
   --  v0.5 cap: 64-byte identity, matching Tls_Core.Hello's
   --  Psk_Identity_Len. Real-world ticket bytes can exceed this; the
   --  driver-internal cap will lift in the same wave that lifts
   --  Tls_Core.Hello's identity bound.
   --------------------------------------------------------------------
   procedure Init_Psk_Resumption_Client
     (D    : out Driver;
      Slot : Tls_Core.Session_Cache.Slot)
   with
     Pre =>
       Slot.Used
       and then Slot.Ticket_Len in 1 .. 64
       and then Slot.Ticket_Nonce_Len in
         0 .. Tls_Core.Session_Ticket.Max_Ticket_Nonce_Length;

private

   subtype Psk_Bytes  is Octet_Array (1 .. 32);
   subtype Identity_Bytes is Octet_Array (1 .. 64);

   type Driver is record
      My_Role     : Role := Server;
      Cur_State   : State := Awaiting_CH;
      Hash_Ctx    : Tls_Core.Transcript.Accumulator;

      PSK         : Psk_Bytes := (others => 0);
      Identity    : Identity_Bytes := (others => 0);
      Identity_Len : Natural := 0;

      --  X25519 ECDHE state (RFC 8446 §4.2.8 + §7.1 mode 3).
      --
      --  My_Ecdhe_Priv  — local private scalar (set in Init from the
      --                   caller-supplied bytes; never put on the wire).
      --  My_Ecdhe_Pub   — local public u-coordinate, derived in Init
      --                   via X25519.Derive_Public; written to the CH
      --                   (client) or SH (server) key_share extension.
      --  Peer_Ecdhe_Pub — peer's public u-coordinate, parsed from the
      --                   counterpart Hello message.
      --  Ecdhe_Shared   — X25519 (My_Ecdhe_Priv, Peer_Ecdhe_Pub),
      --                   threaded into Handshake-Secret HKDF-Extract
      --                   as the IKM (replaces the all-zeros IKM that
      --                   psk_ke / mode 1 would have used).
      My_Ecdhe_Priv  : Octet_Array (1 .. 32) := (others => 0);
      My_Ecdhe_Pub   : Octet_Array (1 .. 32) := (others => 0);
      Peer_Ecdhe_Pub : Octet_Array (1 .. 32) := (others => 0);
      Ecdhe_Shared   : Octet_Array (1 .. 32) := (others => 0);

      --  Negotiated cipher suite. Default value is meaningless
      --  until Step transitions out of Idle / Awaiting_CH.
      Suite       : Tls_Core.Suites.Cipher_Suite_Id :=
        Tls_Core.Suites.Chacha20_Poly1305_Sha256;

      --  Aead_Channel directions for handshake encryption
      --  (post-SH). Variant-record state pinned by Suite.
      Hs_Out_Dir  : Tls_Core.Aead_Channel.Direction;
      Hs_In_Dir   : Tls_Core.Aead_Channel.Direction;

      --  Saved handshake-stage state used after Awaiting_CH. v0.5
      --  internal-key-schedule path is SHA-256-only, so secrets and
      --  digests are sized for SHA-256. AES-256-GCM-SHA384 negotiation
      --  is therefore not yet completable through Step (see Wall-hit
      --  note in package comment).
      C_Hs_Sec    : Tls_Core.Key_Schedule.Secret := (others => 0);
      S_Hs_Sec    : Tls_Core.Key_Schedule.Secret := (others => 0);
      Hs_Secret   : Tls_Core.Key_Schedule.Secret := (others => 0);

      --  Expected client Finished verify_data, computed at the
      --  moment server Finished is sent — saved here so the
      --  Awaiting_Cf path can do a constant-time compare against
      --  the decrypted body.
      Expected_Cf : Tls_Core.Sha256.Digest := (others => 0);

      --  Application-data secrets (filled at the same time, used
      --  via Open_App_Directions after Done).
      App_C_Ap    : Tls_Core.Key_Schedule.Secret := (others => 0);
      App_S_Ap    : Tls_Core.Key_Schedule.Secret := (others => 0);
      App_Set     : Boolean := False;

      --  Master_Secret saved at the moment the application-traffic
      --  secrets are derived, so the Awaiting_Cf branch (server) and
      --  the inline post-Finished branch (client) can compute
      --  resumption_master_secret over CH..CF.
      Master_Sec     : Tls_Core.Key_Schedule.Secret := (others => 0);
      Master_Set     : Boolean := False;

      --  resumption_master_secret per RFC 8446 §7.1 — derived after
      --  client Finished is appended to the transcript (CH..CF).
      Res_Master_Sec : Tls_Core.Key_Schedule.Secret := (others => 0);
      Res_Master_Set : Boolean := False;

      --  HelloRetryRequest fields (RFC 8446 §4.1.4 / §4.4.1).
      --
      --  Server side:
      --    Hrr_Demand  — set at init-time; tells the Awaiting_CH
      --                  branch to emit HRR instead of SH+EE+SF on
      --                  the first CH it sees.
      --    Hrr_Sent    — flips True once the server has emitted HRR
      --                  and is awaiting CH2 (see Awaiting_Ch_2).
      --    Hrr_Group   — the named-group codepoint the server
      --                  demands the client use in CH2's key_share.
      --                  Echoed in the HRR's key_share extension.
      --
      --  Client side:
      --    Hrr_Aware   — set at init-time; tells the Idle branch to
      --                  transition to Awaiting_Sh_Or_Hrr (instead
      --                  of Awaiting_Sf) so the next Step can
      --                  dispatch on the magic random.
      --    Hrr_Seen    — flips True once the client has consumed an
      --                  HRR and emitted CH2.
      --
      --  Cookie bytes (server: emitted in HRR, validated against
      --  CH2's echo; client: stored after HRR receipt, echoed in
      --  CH2). Cookie_Len is 0..Max_Cookie_Length.
      Hrr_Demand  : Boolean := False;
      Hrr_Sent    : Boolean := False;
      Hrr_Aware   : Boolean := False;
      Hrr_Seen    : Boolean := False;
      Hrr_Group   : Tls_Core.Suites.U16 :=
        Tls_Core.Suites.Group_Secp256r1;
      Hrr_Cookie  : Tls_Core.Hello_Retry.Cookie_Bytes := (others => 0);
      Hrr_Cookie_Len : Natural := 0;

      --  Saved CH1-transcript hash, computed at the moment HRR is
      --  about to be emitted (server) or processed (client). Used
      --  to feed the §4.4.1 synthetic message_hash record into a
      --  freshly-Init'd Transcript accumulator before appending HRR
      --  + CH2 + the rest of the handshake. Kept after transcript
      --  rebuild for diagnostic / test introspection.
      Hrr_Ch1_Hash : Tls_Core.Sha256.Digest := (others => 0);

      --  True once the handshake-stage Aead_Channel directions
      --  have been initialised with real (non-zero) traffic secrets.
      --  Drives plaintext-vs-encrypted alert dispatch (RFC 8446 §6).
      Hs_Keys_Set : Boolean := False;

      --  Last AlertDescription this driver emitted or recorded.
      Last_Alert  : Octet := Tls_Core.Alert.Desc_Internal_Error;

      --  Application-data direction reused by Send_Close_Notify /
      --  Send_Fatal_Alert post-Done.
      App_Out_Dir : Tls_Core.Aead_Channel.Direction;
      App_Out_Set : Boolean := False;

      --  Inbound handshake-message reassembly buffer (RFC 8446 §5.1).
      --  Each Step call funnels every record's handshake-channel
      --  content through this buffer and pops complete handshake
      --  messages one at a time. This makes the driver tolerant to:
      --    - cert chains and other large messages split across two
      --      or more TLSCiphertext records
      --    - multiple handshake messages packed into a single
      --      record (server EE+SF in one TLSCiphertext, etc.)
      --  The buffer is reset (Init) at construction and any time
      --  the driver transitions through a state that doesn't
      --  preserve message-boundary continuity (e.g. HRR rebuild).
      Hs_In_Buf   : Tls_Core.Handshake_Buffer.Buffer;
   end record;

   function Current_State (D : Driver) return State is (D.Cur_State);

   function Selected_Suite (D : Driver) return Tls_Core.Suites.Cipher_Suite_Id
   is (D.Suite);

   function Last_Alert_Description (D : Driver) return Octet is (D.Last_Alert);

   function App_Secrets_Set (D : Driver) return Boolean is (D.App_Set);

   function Resumption_Master_Secret_Available (D : Driver) return Boolean
   is (D.Res_Master_Set);

end Tls_Core.Tls13_Driver;
