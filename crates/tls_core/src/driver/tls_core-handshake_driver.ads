--  Tls_Core.Handshake_Driver — wire-level PSK_KE state machine.
--
--  Drives the four-message PSK_KE handshake (RFC 8446 §2.2 +
--  appendix on PSK-only mode) symbolically: each side starts
--  Idle, transitions through {Sent_CH, Recv_SH, Sent_Finished,
--  Recv_Finished, Done} as inbound Handshake records arrive
--  and outbound ones are produced. Once Done, traffic-secret
--  fields hold the four secrets from §7.1.
--
--  This is the orchestration layer over the v0.5 primitives:
--
--    Tls_Core.Records          -- parse/encode TLSPlaintext frames
--    Tls_Core.Transcript       -- running SHA-256 over Handshake bytes
--    Tls_Core.Handshake        -- PSK_KE key-schedule tree
--    Tls_Core.Finished         -- RFC §4.4.4 verify_data
--
--  No I/O. The driver works in terms of Octet_Array buffers; the
--  caller plugs in whatever transport ferries bytes across.
--
--  miTLS reference: src/tls/MiTLS.Handshake.fst transition log;
--  the F* `step` ghost there has the same call/return shape.

with Tls_Core.Ed25519;
with Tls_Core.Handshake;
with Tls_Core.Transcript;
with Tls_Core.X25519;

package Tls_Core.Handshake_Driver
  with SPARK_Mode
is

   type Role is (Client, Server);

   --  RFC 8446 §4.1.4 mode selection: this v0.5 driver supports
   --     - PSK_KE          — pre-shared key only
   --     - ECDHE           — pure ECDHE with X25519, no server auth
   --     - ECDHE_With_Cert — ECDHE plus an Ed25519-signed
   --                         CertificateVerify per RFC 8446 §4.4.3.
   --                         The "Certificate" message in this mode
   --                         carries a raw Ed25519 public key
   --                         (not a wrapped X.509 chain — the X.509
   --                         parsing path is exercised separately
   --                         by Tls_Core.X509). Client validates by
   --                         comparing the received public key to a
   --                         caller-supplied trusted pin.
   type Mode is (PSK_KE, ECDHE, ECDHE_With_Cert);

   type State is
     (Idle,                 --  Nothing sent or received yet.
      Awaiting_Server_Hello,  --  Client sent CH, waiting for SH.
      Awaiting_Client_Hello,  --  Server is waiting for CH.
      Awaiting_Finished,    --  Hellos exchanged, awaiting peer Finished.
      Done,                 --  All four messages processed.
      Failed);              --  Verify failed or unexpected message.

   --  Driver context. Internally holds the role, current state,
   --  the transcript-hash accumulator, the PSK, and on success
   --  the four traffic secrets from RFC 8446 §7.1.
   type Driver is private;

   --  Initialize for a given role with a 32-byte PSK. PSK_KE mode.
   procedure Init (D : out Driver; For_Role : Role; PSK : Octet_Array)
   with Pre => PSK'Length = 32 and then PSK'Last < Integer'Last - 1024;

   --  Initialize for ECDHE mode. The caller supplies the X25519
   --  private key (32 bytes); the driver derives its own public,
   --  embeds it in the outgoing Hello, and on receipt of the peer
   --  Hello extracts the peer public + computes the shared secret.
   procedure Init_Ecdhe
     (D : out Driver; For_Role : Role; Private_Key : Tls_Core.X25519.Bytes_32);

   --  Server-side cert mode. The driver embeds the Ed25519 public
   --  key (derived from `Sign_Seed`) in a synthetic Certificate
   --  message, signs the transcript with `Sign_Seed` and emits
   --  the result as CertificateVerify per RFC 8446 §4.4.3.
   procedure Init_Ecdhe_With_Cert
     (D           : out Driver;
      Private_Key : Tls_Core.X25519.Bytes_32;
      Sign_Seed   : Tls_Core.Ed25519.Bytes_32);

   --  Client-side cert-verifying mode. `Trusted_Pub_Key` is the
   --  Ed25519 public key the client expects to see in the server's
   --  Certificate message; if the received Cert doesn't match,
   --  state transitions to Failed. The signature in
   --  CertificateVerify is verified against this same key.
   procedure Init_Ecdhe_Verify
     (D               : out Driver;
      Private_Key     : Tls_Core.X25519.Bytes_32;
      Trusted_Pub_Key : Tls_Core.Ed25519.Bytes_32);

   --  Accept an inbound Handshake message body (no record-layer
   --  envelope; just the type+u24-length+body bytes). Advances
   --  state, optionally producing an outbound Handshake message
   --  body in Out_Buf. Sets Out_Last = 0 if no reply this step.
   --
   --  When state hits Done, traffic secrets are populated and
   --  Get_Secrets can be called.
   procedure Step
     (D        : in out Driver;
      In_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   with
     Pre =>
       In_Bytes'Length in 0 .. 1024
       and then In_Bytes'Last < Integer'Last - 1024
       and then Out_Buf'Length >= 256
       and then Out_Buf'First = 1;

   --  Query state.
   function Current_State (D : Driver) return State;

   --  After Done: copy out the four traffic secrets.
   procedure Get_Secrets
     (D : Driver; Out_Sec : out Tls_Core.Handshake.Traffic_Secrets)
   with Pre => Current_State (D) = Done;

private

   subtype PSK_Bytes is Octet_Array (1 .. 32);
   subtype Hello_Bytes is Octet_Array (1 .. 1024);

   type Driver is record
      My_Role   : Role := Client;
      My_Mode   : Mode := PSK_KE;
      Cur_State : State := Idle;
      Hash_Ctx  : Tls_Core.Transcript.Accumulator;
      PSK       : PSK_Bytes := (others => 0);

      --  ECDHE state — populated only when My_Mode in {ECDHE, ECDHE_With_Cert}.
      My_Priv  : Tls_Core.X25519.Bytes_32 := (others => 0);
      My_Pub   : Tls_Core.X25519.Bytes_32 := (others => 0);
      Peer_Pub : Tls_Core.X25519.Bytes_32 := (others => 0);
      Shared   : Tls_Core.X25519.Bytes_32 := (others => 0);

      --  Cert-mode state — populated only when My_Mode = ECDHE_With_Cert.
      Sign_Seed   : Tls_Core.Ed25519.Bytes_32 := (others => 0);
      Sign_Pub    : Tls_Core.Ed25519.Bytes_32 := (others => 0);
      Trusted_Pub : Tls_Core.Ed25519.Bytes_32 := (others => 0);

      --  We retain the recorded ClientHello and ServerHello bytes
      --  (and the peer Finished bytes) so the §7.1 schedule can
      --  re-key using the exact transcripts the peers exchanged.
      CH_Buf : Hello_Bytes := (others => 0);
      CH_Len : Natural := 0;
      SH_Buf : Hello_Bytes := (others => 0);
      SH_Len : Natural := 0;
      SF_Buf : Hello_Bytes := (others => 0);
      SF_Len : Natural := 0;

      --  Filled when state becomes Done.
      Secrets_Set : Boolean := False;
      Secrets     : Tls_Core.Handshake.Traffic_Secrets;
   end record;

   function Current_State (D : Driver) return State
   is (D.Cur_State);

end Tls_Core.Handshake_Driver;
