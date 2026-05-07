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
--  This slice supports the PSK_KE profile (RFC 8446 §7.1 mode 1)
--  with **runtime cipher-suite negotiation**: the client offers
--  all three v0.5 production suites in §B.4 preference order, the
--  server picks the first acceptable one, and Send / Receive go
--  through Tls_Core.Aead_Channel which dispatches the AEAD
--  primitive on the negotiated suite.
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
with Tls_Core.Key_Schedule;
with Tls_Core.Sha256;
with Tls_Core.Suites;
with Tls_Core.Transcript;

package Tls_Core.Tls13_Driver
with SPARK_Mode
is

   pragma Unevaluated_Use_Of_Old (Allow);

   type Role is (Client, Server);

   type State is
     (Idle,               --  Client's initial state.
      Awaiting_CH,        --  Server's initial state.
      Awaiting_Sf,        --  Client sent CH; awaiting SH+EE+SF flight.
      Awaiting_Cf,        --  Server sent SH+EE+SF; awaiting client Finished.
      Done,
      Failed);

   type Driver is private;

   --  Initialise as PSK_KE server. The PSK is the same byte string
   --  the peer (e.g. openssl s_client -psk) uses; Identity is the
   --  external PSK identity it advertises.
   procedure Init_Psk_Server
     (D            : out Driver;
      PSK          : Octet_Array;
      Psk_Identity : Octet_Array);

   --  Initialise as PSK_KE client.
   procedure Init_Psk_Client
     (D            : out Driver;
      PSK          : Octet_Array;
      Psk_Identity : Octet_Array);

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
   --------------------------------------------------------------------
   procedure Open_App_Directions
     (D       : Driver;
      Out_Dir : out Tls_Core.Aead_Channel.Direction;
      In_Dir  : out Tls_Core.Aead_Channel.Direction)
   with Pre => Current_State (D) = Done;

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
   end record;

   function Current_State (D : Driver) return State is (D.Cur_State);

   function Selected_Suite (D : Driver) return Tls_Core.Suites.Cipher_Suite_Id
   is (D.Suite);

end Tls_Core.Tls13_Driver;
