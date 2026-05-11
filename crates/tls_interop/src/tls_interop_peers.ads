--  Tls_Interop_Peers — typed per-peer command-line synthesis.
--
--  Given a Cell_Spec (peer + role + mode + endpoint + creds), this
--  package returns the binary name + argument list to spawn that
--  peer.  Adding a new peer = add an enum literal + a case branch
--  in Build_Command.  No bash, no per-peer .sh files.

with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with GNAT.OS_Lib;

package Tls_Interop_Peers is

   type Peer_Kind is
     (Ada_Native,    --  our own tls_cli binary
      Openssl,
      Gnutls,
      Mbedtls,
      Rustls,
      Go_Lang,
      Boringssl,
      Wolfssl);      --  wolfSSL example client/server

   type Role_Kind is (Client, Server);

   type Mode_Kind is
     (Psk_Dhe_Ke,    --  RFC 8446 §7.1 mode 3, external PSK
      Cert_Ec,       --  ECDSA-P256 cert chain
      Cert_Rsa);     --  RSA-PSS verify-only

   type Cipher_Kind is
     (Auto,
      Chacha20_Poly1305_Sha256,
      Aes128_Gcm_Sha256,
      Aes256_Gcm_Sha384);

   type Cell_Spec is record
      Peer         : Peer_Kind;
      Role         : Role_Kind;
      Mode         : Mode_Kind;
      Cipher       : Cipher_Kind := Auto;
      Port         : Natural := 0;
      Host         : Unbounded_String := Null_Unbounded_String;

      --  PSK material — only meaningful when Mode = Psk_Dhe_Ke.
      Psk_Hex      : Unbounded_String := Null_Unbounded_String;
      Psk_Identity : Unbounded_String := Null_Unbounded_String;

      --  Cert material — only meaningful when Mode in Cert_Ec | Cert_Rsa.
      Cert_Pem     : Unbounded_String := Null_Unbounded_String;
      Key_Pem      : Unbounded_String := Null_Unbounded_String;
      Trust_Pem    : Unbounded_String := Null_Unbounded_String;
      Hostname     : Unbounded_String := Null_Unbounded_String;

      --  Path to a 32-byte file containing the PSK (used by tls_cli).
      Psk_File     : Unbounded_String := Null_Unbounded_String;
   end record;

   ---------------------------------------------------------------------
   --  Build the command to spawn for a Cell.
   --
   --  Bin       : full path to the binary (looked up via $PATH).
   --  Args      : Argument_List_Access; caller must free via
   --              GNAT.OS_Lib.Free after the spawn returns.
   --  Supported : True iff the peer's binary is installed AND it
   --              implements this Mode.  Cells with Supported = False
   --              are reported as "N/A — <reason>".
   --  Reason    : human-readable explanation when Supported = False
   --              (e.g., "binary not installed", "peer has no
   --              external PSK API").
   ---------------------------------------------------------------------
   procedure Build_Command
     (Cell      : Cell_Spec;
      Bin       : out Unbounded_String;
      Args      : out GNAT.OS_Lib.Argument_List_Access;
      Supported : out Boolean;
      Reason    : out Unbounded_String);

   --  True iff the peer's binary (or, for Go, `go`) is on $PATH.
   --  Does NOT check per-mode support; that's in Build_Command.
   function Binary_Available (P : Peer_Kind) return Boolean;

   --  String labels for the report table.
   function Image (P : Peer_Kind) return String;
   function Image (M : Mode_Kind) return String;
   function Image (R : Role_Kind) return String;
   function Image (C : Cipher_Kind) return String;

   ---------------------------------------------------------------------
   --  Feature inventory.  One feature = one row in the per-peer
   --  matrix table.  The orchestrator walks every (peer, feature,
   --  direction) tuple, dispatching to one of four buckets:
   --
   --    PASS           — both Ada and peer support; cell ran green
   --    FAIL           — both support; ran but produced wrong result
   --    NOT_IMPL_ADA   — peer supports, Ada driver does not yet
   --    NOT_IMPL_3P    — Ada supports, peer's CLI / library does not
   --
   --  Categories close cleanly: every feature is exactly one bucket.
   ---------------------------------------------------------------------

   type Feature_Kind is
     (Cert_Ecdsa_P256_Sha256,
      --  ECDSA-P256 cert chain, ecdsa_secp256r1_sha256 sign+verify.

      Cert_Rsa_Pss_Sha256,
      --  RSA cert chain, rsa_pss_rsae_sha256.  Ada verifies but the
      --  v0.5 server doesn't sign RSA-PSS (only ECDSA).

      Psk_External_Chacha20,
      --  RFC 8446 §4.2.11 external PSK + ChaCha20-Poly1305-SHA256.

      Psk_External_Aes128,
      --  RFC 8446 §4.2.11 external PSK + AES-128-GCM-SHA256.

      Psk_External_Aes256,
      --  RFC 8446 §4.2.11 external PSK + AES-256-GCM-SHA384.  Ada
      --  has the cipher suite but no negotiation glue yet; matrix
      --  reports it as NOT_IMPL_ADA pending wiring.

      Psk_Resumption,
      --  RFC 8446 §4.6.1 resumption-PSK (cert-mode → NewSessionTicket
      --  → reconnect with ticket).  c2s tested via two-phase shell
      --  script; s2c pending Ada server resumption-accept wiring.

      Hello_Retry_Request,
      --  RFC 8446 §4.1.4 — server demands a different named group.

      Sni_Alpn,
      --  RFC 6066 §3 SNI + RFC 7301 ALPN extensions in the
      --  cert-mode CH/SH.

      Zero_Rtt,
      --  RFC 8446 §4.2.10 / §2.3 0-RTT early data.  NOT_IMPL_ADA;
      --  v0.6+ scope per CLAUDE.md §0a (production-default rule).

      Key_Update);
      --  RFC 8446 §4.6.3 post-handshake key rotation.

   --  Does the peer's CLI / library expose this feature in a way
   --  our matrix harness can drive?  This is "peer-CLI-supports",
   --  not "peer-library-supports" — rustls-the-library has external
   --  PSK but rustls-mio CLI doesn't expose it, hence NOT_IMPL_3P.
   function Peer_Supports (P : Peer_Kind; F : Feature_Kind) return Boolean;

   --  Does the Ada driver implement this feature in v0.5?  When
   --  False, the matrix shows NOT_IMPL_ADA + a work-item link from
   --  Ada_Unblock_Link below.
   function Ada_Supports (F : Feature_Kind) return Boolean;

   --  Can the test meaningfully attempt to run this feature, even if
   --  Ada_Supports is False?  True = the test will run and fail
   --  (reclassified to XFAIL).  False = the test can't run at all
   --  (e.g. no signing key, no early-data CLI flag) — shown as XFAIL
   --  without spawning processes.
   function Ada_Can_Attempt (F : Feature_Kind) return Boolean;

   --  Work-item identifier for an XFAIL cell.  Points to a row in
   --  docs/v0.5-not-impl.md.  Empty when Ada_Supports = True.
   function Ada_Unblock_Link (F : Feature_Kind) return String;

   --  Short label for the feature in the matrix table.
   function Image (F : Feature_Kind) return String;

   --  All non-deprecated features the v0.5 matrix iterates over.
   function All_Features return String;

   type Cell_Result is (Pass, Fail, Xfail_Ada, Not_Impl_3P);
   function Image (R : Cell_Result) return String;

   procedure Feature_To_Cell
     (F : Feature_Kind;
      M : out Mode_Kind;
      C : out Cipher_Kind);

end Tls_Interop_Peers;
