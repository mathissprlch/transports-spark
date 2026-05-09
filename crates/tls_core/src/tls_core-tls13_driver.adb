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
with Tls_Core.X25519;

package body Tls_Core.Tls13_Driver
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;

   ---------------------------------------------------------------------
   --  Constants
   ---------------------------------------------------------------------

   Rec_Type_Handshake : constant Octet := 16#16#;
   Rec_Type_Alert     : constant Octet := 16#15#;
   --  Rec_Type_App_Data declared in Tls_Core.Channel.

   Hs_Type_CH         : constant Octet := 16#01#;
   Hs_Type_SH         : constant Octet := 16#02#;
   Hs_Type_EE         : constant Octet := 16#08#;
   Hs_Type_Cert       : constant Octet := 16#0B#;
   Hs_Type_Cert_Verify: constant Octet := 16#0F#;
   Hs_Type_Finished   : constant Octet := 16#14#;

   procedure Hkdf_Expand_Label_Sha256
     is new Tls_Core.Hkdf.Expand_Label
       (Hash_Length      => Tls_Core.Sha256.Hash_Length,
        Max_Info         => 512,
        Spec_Hmac_Expand => Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand,
        Hmac_Expand      => Tls_Core.Hkdf_Sha256.Hmac_Expand);

   ---------------------------------------------------------------------
   --  Init_Psk_Server
   ---------------------------------------------------------------------

   --  Helper: prime the Driver's variant-record / secret fields so
   --  flow analysis sees every member as initialised even though
   --  the actual handshake logic in Step overwrites them later.
   --  Hs_Out_Dir / Hs_In_Dir start as the default chacha20 variant;
   --  Step swaps them to the negotiated variant once D.Suite is set.
   --  Note: this body has 3 pre-existing unproven Init_Sha256 calls
   --  ("D.Hs_Out_Dir.Suite is not set" etc.) — gnatprove can't see
   --  through the inlining + variant-record discriminant interaction
   --  for an `out` parameter component. Independent of the alert
   --  protocol work; tracked separately.
   procedure Prime_Driver_Defaults (D : in out Driver);
   procedure Prime_Driver_Defaults (D : in out Driver) is
      Zero_Secret : constant Tls_Core.Key_Schedule.Secret := (others => 0);
      Zero_Digest : constant Tls_Core.Sha256.Digest := (others => 0);
   begin
      D.Suite := Tls_Core.Suites.Chacha20_Poly1305_Sha256;
      D.C_Hs_Sec  := Zero_Secret;
      D.S_Hs_Sec  := Zero_Secret;
      D.Hs_Secret := Zero_Secret;
      D.Expected_Cf := Zero_Digest;
      D.App_C_Ap := Zero_Secret;
      D.App_S_Ap := Zero_Secret;
      D.Master_Sec := Zero_Secret;
      D.Master_Set := False;
      D.Res_Master_Sec := Zero_Secret;
      D.Res_Master_Set := False;
      Tls_Core.Aead_Channel.Init_Sha256
        (D.Hs_Out_Dir, Tls_Core.Suites.Chacha20_Poly1305_Sha256, Zero_Secret);
      Tls_Core.Aead_Channel.Init_Sha256
        (D.Hs_In_Dir,  Tls_Core.Suites.Chacha20_Poly1305_Sha256, Zero_Secret);
   end Prime_Driver_Defaults;

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

   ---------------------------------------------------------------------
   --  Helpers
   ---------------------------------------------------------------------

   --  Alert helper forward declarations (bodies near end of package).
   --  Step error paths call Fail_Plaintext / Fail_Encrypted to record
   --  D.Last_Alert and emit an alert record before returning.

   procedure Build_Plaintext_Alert
     (Level       : Octet;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   with
     Pre => Out_Buf'First = 1 and then Out_Buf'Length >= 7;

   procedure Build_Encrypted_Alert
     (Dir         : in out Tls_Core.Aead_Channel.Direction;
      Level       : Octet;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   with
     Pre =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 5 + 2 + 1 + 16
       and then (case Dir.Suite is
                   when Tls_Core.Suites.Chacha20_Poly1305_Sha256 => True,
                   when Tls_Core.Suites.Aes_128_Gcm_Sha256 =>
                     Tls_Core.Record_Layer.Seq_Of (Dir.Aes128.Stream)
                       < Tls_Core.Record_Layer.Seq_Number'Last,
                   when Tls_Core.Suites.Aes_256_Gcm_Sha384 =>
                     Tls_Core.Record_Layer.Seq_Of (Dir.Aes256.Stream)
                       < Tls_Core.Record_Layer.Seq_Number'Last);

   --  Failure helper for paths before any handshake keys are derived
   --  (Idle / Awaiting_CH). Emits a 7-byte plaintext alert record.
   procedure Fail_Plaintext
     (D           : in out Driver;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   with
     Pre => Out_Buf'First = 1 and then Out_Buf'Length >= 7;

   --  Failure helper for paths after handshake-stage keys exist
   --  (Awaiting_Sf / Awaiting_Cf). Emits an encrypted alert record
   --  under D.Hs_Out_Dir.
   procedure Fail_Encrypted
     (D           : in out Driver;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   with
     Pre =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 5 + 2 + 1 + 16
       and then (case D.Hs_Out_Dir.Suite is
                   when Tls_Core.Suites.Chacha20_Poly1305_Sha256 => True,
                   when Tls_Core.Suites.Aes_128_Gcm_Sha256 =>
                     Tls_Core.Record_Layer.Seq_Of (D.Hs_Out_Dir.Aes128.Stream)
                       < Tls_Core.Record_Layer.Seq_Number'Last,
                   when Tls_Core.Suites.Aes_256_Gcm_Sha384 =>
                     Tls_Core.Record_Layer.Seq_Of (D.Hs_Out_Dir.Aes256.Stream)
                       < Tls_Core.Record_Layer.Seq_Number'Last);

   procedure Fail_Plaintext
     (D           : in out Driver;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   is
   begin
      Build_Plaintext_Alert
        (Tls_Core.Alert.Level_Fatal, Description, Out_Buf, Out_Last);
      D.Last_Alert := Description;
      D.Cur_State := Failed;
   end Fail_Plaintext;

   procedure Fail_Encrypted
     (D           : in out Driver;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   is
   begin
      Build_Encrypted_Alert
        (D.Hs_Out_Dir, Tls_Core.Alert.Level_Fatal, Description,
         Out_Buf, Out_Last);
      D.Last_Alert := Description;
      D.Cur_State := Failed;
   end Fail_Encrypted;

   procedure Build_Finished_Body
     (Base_Key       : Tls_Core.Key_Schedule.Secret;
      Transcript_Hash : Tls_Core.Sha256.Digest;
      Out_Verify     : out Tls_Core.Sha256.Digest);
   procedure Build_Finished_Body
     (Base_Key       : Tls_Core.Key_Schedule.Secret;
      Transcript_Hash : Tls_Core.Sha256.Digest;
      Out_Verify     : out Tls_Core.Sha256.Digest)
   is
      Empty_Ctx : constant Octet_Array (1 .. 0) := (others => 0);
      Label : constant Octet_Array (1 .. 8) :=
        (16#66#, 16#69#, 16#6E#, 16#69#, 16#73#, 16#68#, 16#65#, 16#64#);
      Finished_Key : Tls_Core.Sha256.Digest;
   begin
      Hkdf_Expand_Label_Sha256
        (Secret  => Base_Key,
         Label   => Label,
         Context => Empty_Ctx,
         Output  => Finished_Key);
      Tls_Core.Hmac_Sha256.Compute
        (Key     => Finished_Key,
         Message => Transcript_Hash,
         Out_Tag => Out_Verify);
   end Build_Finished_Body;

   procedure Encode_Hs_Message
     (Msg_Type : Octet;
      Body_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural);
   procedure Encode_Hs_Message
     (Msg_Type : Octet;
      Body_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is
      Len : constant Natural := Body_Bytes'Length;
   begin
      Out_Buf := (others => 0);
      Out_Buf (1) := Msg_Type;
      Out_Buf (2) := Octet ((Len / 65536) mod 256);
      Out_Buf (3) := Octet ((Len / 256) mod 256);
      Out_Buf (4) := Octet (Len mod 256);
      if Len > 0 then
         Out_Buf (5 .. 4 + Len) := Body_Bytes;
      end if;
      Out_Last := 4 + Len;
   end Encode_Hs_Message;

   --  Wrap a handshake message in a TLSPlaintext record.
   procedure Wrap_Tls_Plaintext
     (Hs_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural);
   procedure Wrap_Tls_Plaintext
     (Hs_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is
      Len : constant Natural := Hs_Bytes'Length;
   begin
      Out_Buf := (others => 0);
      Out_Buf (1) := Rec_Type_Handshake;
      Out_Buf (2) := 16#03#;
      Out_Buf (3) := 16#03#;
      Out_Buf (4) := Octet ((Len / 256) mod 256);
      Out_Buf (5) := Octet (Len mod 256);
      Out_Buf (6 .. 5 + Len) := Hs_Bytes;
      Out_Last := 5 + Len;
   end Wrap_Tls_Plaintext;

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
            --  Client only: emit ClientHello, dispatched on D.Mode.
            if D.My_Role /= Client then
               D.Cur_State := Failed;
               return;
            end if;
            if D.Mode = Cert_Mode then
               --  RFC 8446 §4.1.2 cert-mode ClientHello — no PSK
               --  extension, no binder. Includes signature_algorithms.
               declare
                  Client_Random : constant Tls_Core.Hello.Random_Bytes :=
                    (others => 16#A1#);
                  Ch_Body : Octet_Array (1 .. 512) := (others => 0);
                  Ch_Body_Last : Natural;
                  Ch_Hs   : Octet_Array (1 .. 1024) := (others => 0);
                  Ch_Hs_Last : Natural;
                  Ch_Rec  : Octet_Array (1 .. 1024) := (others => 0);
                  Ch_Rec_Last : Natural;
               begin
                  Tls_Core.Hello.Encode_Client_Hello_Cert
                    (Random      => Client_Random,
                     Key_Share   => D.My_Ecdhe_Pub,
                     Server_Name => D.Sni_Hostname (1 .. D.Sni_Len),
                     Alpn_Offers => D.Alpn_Offers (1 .. D.Alpn_Offers_Len),
                     Out_Buf     => Ch_Body,
                     Out_Last    => Ch_Body_Last);
                  Encode_Hs_Message
                    (Hs_Type_CH, Ch_Body (1 .. Ch_Body_Last),
                     Ch_Hs, Ch_Hs_Last);
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, Ch_Hs (1 .. Ch_Hs_Last));
                  Wrap_Tls_Plaintext
                    (Ch_Hs (1 .. Ch_Hs_Last), Ch_Rec, Ch_Rec_Last);
                  Out_Buf (1 .. Ch_Rec_Last) := Ch_Rec (1 .. Ch_Rec_Last);
                  Out_Last := Ch_Rec_Last;
                  --  Cert mode does not pair with HRR-aware client
                  --  init in v0.5 (HRR + cert is a v0.5.x extension).
                  D.Cur_State := Awaiting_Sf;
               end;
               return;
            end if;
            declare
               Client_Random : constant Tls_Core.Hello.Random_Bytes :=
                 (others => 16#A1#);
               Ch_Body : Octet_Array (1 .. 512) := (others => 0);
               Ch_Body_Last : Natural;
               T_Last  : Natural;
               Binder  : Tls_Core.Psk_Binder.Binder_Bytes;
               Ch_Hs   : Octet_Array (1 .. 1024) := (others => 0);
               Ch_Hs_Last : Natural;
               Ch_Rec  : Octet_Array (1 .. 1024) := (others => 0);
               Ch_Rec_Last : Natural;
            begin
               Tls_Core.Hello.Encode_Client_Hello_Psk
                 (Client_Random,
                  D.Identity (1 .. D.Identity_Len),
                  D.My_Ecdhe_Pub,
                  D.Sni_Hostname (1 .. D.Sni_Len),
                  D.Alpn_Offers (1 .. D.Alpn_Offers_Len),
                  Ch_Body, Ch_Body_Last, T_Last);
               --  RFC 8446 §4.2.11.2 + §4.4.1: the binder is computed
               --  over the truncated *handshake message* (handshake
               --  type 0x01 + uint24 length + body, truncated up to
               --  but not including the binders), NOT the body alone.
               --  Build the truncated handshake-formatted bytes in
               --  Ch_Hs (scratch — overwritten by Encode_Hs_Message
               --  below), then hash that.
               Ch_Hs := (others => 0);
               Ch_Hs (1) := Hs_Type_CH;
               Ch_Hs (2) := Octet ((Ch_Body_Last / 65536) mod 256);
               Ch_Hs (3) := Octet ((Ch_Body_Last / 256) mod 256);
               Ch_Hs (4) := Octet (Ch_Body_Last mod 256);
               Ch_Hs (5 .. 4 + T_Last) := Ch_Body (1 .. T_Last);
               Tls_Core.Psk_Binder.Compute
                 (D.PSK,
                  Ch_Hs (1 .. 4 + T_Last),
                  Binder);
               Ch_Body (T_Last + 4 .. T_Last + 35) := Binder;  -- offset by binders_total_len(2)+binder_len(1)+1
               --  Wrap as handshake message (type 0x01 + u24 + body).
               Encode_Hs_Message
                 (Hs_Type_CH, Ch_Body (1 .. Ch_Body_Last),
                  Ch_Hs, Ch_Hs_Last);
               --  Append handshake message (NOT record wrapper) to transcript.
               Tls_Core.Transcript.Append
                 (D.Hash_Ctx, Ch_Hs (1 .. Ch_Hs_Last));
               --  Wrap in TLSPlaintext record.
               Wrap_Tls_Plaintext
                 (Ch_Hs (1 .. Ch_Hs_Last), Ch_Rec, Ch_Rec_Last);
               Out_Buf (1 .. Ch_Rec_Last) := Ch_Rec (1 .. Ch_Rec_Last);
               Out_Last := Ch_Rec_Last;
               --  HRR-aware client transitions to Awaiting_Sh_Or_Hrr;
               --  the next Step inspects the server's first record and
               --  dispatches by ServerHello.random == magic per
               --  RFC 8446 §4.1.4. Non-HRR-aware client falls through
               --  to the historical Awaiting_Sf direct path.
               if D.Hrr_Aware then
                  D.Cur_State := Awaiting_Sh_Or_Hrr;
               else
                  D.Cur_State := Awaiting_Sf;
               end if;
            end;

         when Awaiting_Sf =>
            --  Client: parse server flight.  For PSK mode the flight
            --  is SH || EE || SF.  For cert mode (RFC 8446 §2.2) the
            --  flight is SH || EE || Cert || CertVerify || SF, with
            --  the Cert + CertVerify §4.4.2 / §4.4.3 messages between
            --  EE and SF.  After verifying SF, emit encrypted client
            --  Finished.
            if D.My_Role /= Client then
               D.Cur_State := Failed;
               return;
            end if;

            if D.Mode = Cert_Mode then
               --  Cert-mode flight reception.  Same SH parse + ECDHE
               --  computation as PSK mode, but key schedule uses PSK = 0
               --  (RFC 8446 §7.1) and the sub-state machine after the
               --  handshake-stage Aead_Channel is opened expects four
               --  encrypted messages: EE → Cert → CertVerify → SF.
               declare
                  Cursor : Natural := In_Bytes'First;

                  Empty_In    : constant Octet_Array (1 .. 0) :=
                    (others => 0);
                  Zero_Secret : constant Tls_Core.Key_Schedule.Secret :=
                    (others => 0);
                  Zero32      : constant Octet_Array (1 .. 32) :=
                    (others => 0);
                  Empty_Hash  : Tls_Core.Sha256.Digest;

                  Derived_Lab : constant Octet_Array (1 .. 7) :=
                    (16#64#, 16#65#, 16#72#, 16#69#, 16#76#, 16#65#,
                     16#64#);
                  C_Hs_Lab : constant Octet_Array (1 .. 12) :=
                    (16#63#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
                     16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
                  S_Hs_Lab : constant Octet_Array (1 .. 12) :=
                    (16#73#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
                     16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
                  C_Ap_Lab : constant Octet_Array (1 .. 12) :=
                    (16#63#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
                     16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
                  S_Ap_Lab : constant Octet_Array (1 .. 12) :=
                    (16#73#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
                     16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);

                  Early_Secret : Tls_Core.Key_Schedule.Secret;
                  Derived_1    : Tls_Core.Key_Schedule.Secret;
                  Th_After_Sh   : Tls_Core.Sha256.Digest;
                  Th_After_Cert : Tls_Core.Sha256.Digest;
                  Th_After_CV   : Tls_Core.Sha256.Digest;
                  Th_After_Sf   : Tls_Core.Sha256.Digest;

                  --  Leaf-cert scratch — the raw DER bytes recovered
                  --  from the §4.4.2 Certificate message body.
                  Leaf_Buf : Octet_Array (1 .. 4096) := (others => 0);
                  Leaf_Len : Natural := 0;
               begin
                  --  Step 1: parse SH TLSPlaintext (same shape as
                  --  PSK SH; just no pre_shared_key extension).
                  if Cursor + 4 > In_Bytes'Last
                    or else In_Bytes (Cursor) /= Rec_Type_Handshake
                  then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  declare
                     use type Tls_Core.Suites.U16;
                     Sh_Rec_Len : constant Natural :=
                       Natural (In_Bytes (Cursor + 3)) * 256
                       + Natural (In_Bytes (Cursor + 4));
                     Sh_Rec_F : constant Natural := Cursor + 5;
                     Sh_Rec_L : constant Natural :=
                       Sh_Rec_F + Sh_Rec_Len - 1;
                  begin
                     if Sh_Rec_L > In_Bytes'Last
                       or else Sh_Rec_Len < 4
                       or else In_Bytes (Sh_Rec_F) /= Hs_Type_SH
                     then
                        D.Cur_State := Failed;
                        return;
                     end if;
                     if Sh_Rec_F + 40 > In_Bytes'Last
                       or else In_Bytes (Sh_Rec_F + 38) /= 0
                     then
                        D.Cur_State := Failed;
                        return;
                     end if;
                     declare
                        Code : constant Tls_Core.Suites.U16 :=
                          Tls_Core.Suites.U16
                            (In_Bytes (Sh_Rec_F + 39)) * 256
                          + Tls_Core.Suites.U16
                              (In_Bytes (Sh_Rec_F + 40));
                     begin
                        if not Tls_Core.Suites.Is_Supported_Suite (Code)
                          or else Code =
                            Tls_Core.Suites.TLS_AES_256_GCM_SHA384
                        then
                           D.Cur_State := Failed;
                           return;
                        end if;
                        D.Suite := Tls_Core.Suites.Suite_Of_Code (Code);
                     end;
                     declare
                        Sh_Body_F : constant Natural := Sh_Rec_F + 4;
                        Sh_Body_L : constant Natural := Sh_Rec_L;
                        Ks_F, Ks_L : Natural;
                        Ks_OK : Boolean;
                        Peer_Pub : Tls_Core.X25519.Bytes_32;
                        Shared   : Tls_Core.X25519.Bytes_32;
                     begin
                        Tls_Core.Hello.Decode_Server_Hello_Psk_Key_Share
                          (In_Bytes (Sh_Body_F .. Sh_Body_L),
                           Ks_F, Ks_L, Ks_OK);
                        if not Ks_OK then
                           D.Cur_State := Failed;
                           return;
                        end if;
                        for I in 1 .. 32 loop
                           pragma Loop_Invariant (I in 1 .. 32);
                           Peer_Pub (I) := In_Bytes (Ks_F + I - 1);
                        end loop;
                        D.Peer_Ecdhe_Pub := Peer_Pub;
                        Tls_Core.X25519.Scalar_Mult
                          (D.My_Ecdhe_Priv, Peer_Pub, Shared);
                        D.Ecdhe_Shared := Shared;
                     end;
                     Tls_Core.Transcript.Append
                       (D.Hash_Ctx, In_Bytes (Sh_Rec_F .. Sh_Rec_L));
                     Cursor := Sh_Rec_L + 1;
                  end;

                  --  Step 2: cert-mode key schedule (PSK = 0).
                  Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Th_After_Sh);
                  Tls_Core.Key_Schedule.Extract
                    (Salt => Zero_Secret, IKM => Zero32,
                     Out_PRK => Early_Secret);
                  Tls_Core.Key_Schedule.Derive_Secret
                    (Secret_In  => Early_Secret,
                     Label      => Derived_Lab,
                     Messages   => Empty_In,
                     Out_Secret => Derived_1);
                  Tls_Core.Key_Schedule.Extract
                    (Salt => Derived_1, IKM => D.Ecdhe_Shared,
                     Out_PRK => D.Hs_Secret);
                  Hkdf_Expand_Label_Sha256
                    (Secret  => D.Hs_Secret,
                     Label   => C_Hs_Lab,
                     Context => Th_After_Sh,
                     Output  => D.C_Hs_Sec);
                  Hkdf_Expand_Label_Sha256
                    (Secret  => D.Hs_Secret,
                     Label   => S_Hs_Lab,
                     Context => Th_After_Sh,
                     Output  => D.S_Hs_Sec);
                  Tls_Core.Aead_Channel.Init_Sha256
                    (D.Hs_In_Dir,  D.Suite, D.S_Hs_Sec);
                  Tls_Core.Aead_Channel.Init_Sha256
                    (D.Hs_Out_Dir, D.Suite, D.C_Hs_Sec);

                  --  Step 3: drain encrypted records, dispatch on
                  --  EE / Cert / CertVerify / SF.
                  declare
                     type Sub_State is
                       (Expect_EE, Expect_Cert, Expect_CertVerify,
                        Expect_SF, Done_Sub);
                     Sub  : Sub_State := Expect_EE;
                     Pt_Buf : Octet_Array (1 .. 16640) := (others => 0);
                     Pt_Last : Natural;
                     Inner_Type : Octet;
                     Aead_OK : Boolean;
                     Rec_Len : Natural;
                     Rec_End : Natural;
                     Push_OK : Boolean;
                     Msg_Buf : Octet_Array
                       (1 .. Tls_Core.Handshake_Buffer.Max_Buf) :=
                         (others => 0);
                     Msg_Last : Natural;
                     Body_Len : Natural;
                     Expected_Sf : Tls_Core.Sha256.Digest;
                     Diff : Octet;
                  begin
                     Tls_Core.Handshake_Buffer.Init (D.Hs_In_Buf);
                     while Cursor <= In_Bytes'Last
                       and then Sub /= Done_Sub
                     loop
                        pragma Loop_Invariant
                          (Cursor in In_Bytes'First .. In_Bytes'Last + 1);
                        if Cursor + 4 > In_Bytes'Last
                          or else In_Bytes (Cursor) /=
                            Tls_Core.Aead_Channel.Inner_Type_Application_Data
                        then
                           Fail_Encrypted
                             (D, Tls_Core.Alert.Desc_Decode_Error,
                              Out_Buf, Out_Last);
                           return;
                        end if;
                        Rec_Len := Natural (In_Bytes (Cursor + 3)) * 256
                                   + Natural (In_Bytes (Cursor + 4));
                        Rec_End := Cursor + 5 + Rec_Len - 1;
                        if Rec_End > In_Bytes'Last then
                           Fail_Encrypted
                             (D, Tls_Core.Alert.Desc_Decode_Error,
                              Out_Buf, Out_Last);
                           return;
                        end if;
                        Tls_Core.Aead_Channel.Receive
                          (D.Hs_In_Dir, In_Bytes (Cursor .. Rec_End),
                           Pt_Buf, Pt_Last, Inner_Type, Aead_OK);
                        if not Aead_OK then
                           Fail_Encrypted
                             (D, Tls_Core.Alert.Desc_Bad_Record_Mac,
                              Out_Buf, Out_Last);
                           return;
                        end if;
                        if Inner_Type /=
                             Tls_Core.Aead_Channel.Inner_Type_Handshake
                        then
                           Fail_Encrypted
                             (D, Tls_Core.Alert.Desc_Unexpected_Message,
                              Out_Buf, Out_Last);
                           return;
                        end if;
                        if Pt_Last >
                             Tls_Core.Handshake_Buffer.Max_Buf
                        then
                           Fail_Encrypted
                             (D, Tls_Core.Alert.Desc_Decode_Error,
                              Out_Buf, Out_Last);
                           return;
                        end if;
                        Tls_Core.Handshake_Buffer.Push_Record_Bytes
                          (D.Hs_In_Buf, Pt_Buf (1 .. Pt_Last), Push_OK);
                        if not Push_OK then
                           Fail_Encrypted
                             (D, Tls_Core.Alert.Desc_Internal_Error,
                              Out_Buf, Out_Last);
                           return;
                        end if;
                        Cursor := Rec_End + 1;

                        while Tls_Core.Handshake_Buffer
                                .Has_Complete_Message (D.Hs_In_Buf)
                          and then Sub /= Done_Sub
                        loop
                           pragma Loop_Invariant
                             (Sub in Expect_EE | Expect_Cert
                                   | Expect_CertVerify | Expect_SF);
                           Body_Len :=
                             Tls_Core.Handshake_Buffer.Peek_Body_Length
                               (D.Hs_In_Buf);
                           if Body_Len + 4 > Msg_Buf'Length then
                              Fail_Encrypted
                                (D, Tls_Core.Alert.Desc_Decode_Error,
                                 Out_Buf, Out_Last);
                              return;
                           end if;
                           Tls_Core.Handshake_Buffer
                             .Pop_Complete_Message
                               (D.Hs_In_Buf, Msg_Buf, Msg_Last);

                           case Sub is
                              when Expect_EE =>
                                 if Msg_Last < 4
                                   or else Msg_Buf (1) /= Hs_Type_EE
                                 then
                                    Fail_Encrypted
                                      (D, Tls_Core.Alert
                                            .Desc_Decode_Error,
                                       Out_Buf, Out_Last);
                                    return;
                                 end if;
                                 Tls_Core.Transcript.Append
                                   (D.Hash_Ctx,
                                    Msg_Buf (1 .. Msg_Last));
                                 Sub := Expect_Cert;

                              when Expect_Cert =>
                                 --  §4.4.2 — handshake_type 0x0B.
                                 --  Body: opaque cert_request_context
                                 --        (u8 len), CertificateEntry
                                 --        list (u24 len + entries).
                                 if Msg_Last < 4 + 1 + 3
                                   or else Msg_Buf (1) /= Hs_Type_Cert
                                 then
                                    Fail_Encrypted
                                      (D, Tls_Core.Alert
                                            .Desc_Decode_Error,
                                       Out_Buf, Out_Last);
                                    return;
                                 end if;
                                 declare
                                    OK : Boolean;
                                    Cert_F, Cert_L : Natural;
                                    Body_Bytes : Octet_Array
                                      (1 .. Msg_Last - 4);
                                 begin
                                    Body_Bytes :=
                                      Msg_Buf (5 .. Msg_Last);
                                    Tls_Core.Cert_Verify
                                      .Decode_Body_Single
                                        (Body_Bytes,
                                         OK, Cert_F, Cert_L);
                                    if not OK
                                      or else Cert_L < Cert_F
                                      or else Cert_L - Cert_F + 1
                                              > Leaf_Buf'Length
                                    then
                                       --  Use Decode_Error to
                                       --  distinguish from
                                       --  Bad_Certificate (which is
                                       --  reserved for chain/sig
                                       --  failure below).
                                       Fail_Encrypted
                                         (D, Tls_Core.Alert
                                               .Desc_Decode_Error,
                                          Out_Buf, Out_Last);
                                       return;
                                    end if;
                                    Leaf_Len := Cert_L - Cert_F + 1;
                                    Leaf_Buf (1 .. Leaf_Len) :=
                                      Body_Bytes (Cert_F .. Cert_L);
                                 end;
                                 Tls_Core.Transcript.Append
                                   (D.Hash_Ctx,
                                    Msg_Buf (1 .. Msg_Last));
                                 Tls_Core.Transcript.Snapshot
                                   (D.Hash_Ctx, Th_After_Cert);
                                 Sub := Expect_CertVerify;

                              when Expect_CertVerify =>
                                 if Msg_Last < 4 + 4
                                   or else Msg_Buf (1) /=
                                             Hs_Type_Cert_Verify
                                 then
                                    Fail_Encrypted
                                      (D, Tls_Core.Alert
                                            .Desc_Decode_Error,
                                       Out_Buf, Out_Last);
                                    return;
                                 end if;
                                 declare
                                    OK : Boolean;
                                    Sig_Scheme : Interfaces.Unsigned_16;
                                    Sig_F, Sig_L : Natural;
                                    Body_Bytes : Octet_Array
                                      (1 .. Msg_Last - 4);
                                    use type Interfaces.Unsigned_16;
                                 begin
                                    Body_Bytes :=
                                      Msg_Buf (5 .. Msg_Last);
                                    Tls_Core.Cert_Verify.Decode_Body
                                      (Body_Bytes,
                                       OK, Sig_Scheme, Sig_F, Sig_L);
                                    if not OK
                                      or else Sig_Scheme /= 16#0403#
                                    then
                                       Fail_Encrypted
                                         (D, Tls_Core.Alert
                                               .Desc_Decode_Error,
                                          Out_Buf, Out_Last);
                                       return;
                                    end if;
                                    --  Build All_Certs = leaf || trust
                                    --  anchors so the validator's
                                    --  Chain_In and Trust offsets share
                                    --  one backing buffer.
                                    declare
                                       Total_Len : constant Natural :=
                                         Leaf_Len + D.Trust_Anchor_Len;
                                       All_Certs : Octet_Array
                                         (1 .. Total_Len) :=
                                           (others => 0);
                                       Chain_In : Tls_Core.Cert_Chain
                                         .Chain;
                                       Trust : Tls_Core.Cert_Chain
                                         .Trust_Store;
                                       Result : Tls_Core.Cert_Chain
                                         .Validation_Result;
                                    begin
                                       if Total_Len < 16 then
                                          Fail_Encrypted
                                            (D, Tls_Core.Alert
                                                  .Desc_Bad_Certificate,
                                             Out_Buf, Out_Last);
                                          return;
                                       end if;
                                       All_Certs (1 .. Leaf_Len) :=
                                         Leaf_Buf (1 .. Leaf_Len);
                                       All_Certs
                                         (Leaf_Len + 1 .. Total_Len) :=
                                         D.Trust_Anchor_Bytes
                                           (1 .. D.Trust_Anchor_Len);
                                       Chain_In.Count := 1;
                                       Chain_In.Entries (1) :=
                                         (First => 1, Last => Leaf_Len);
                                       Trust.Count :=
                                         D.Trust_Anchor_Spec.Count;
                                       for I in 1
                                         .. D.Trust_Anchor_Spec.Count
                                       loop
                                          pragma Loop_Invariant
                                            (I in 1
                                             .. D.Trust_Anchor_Spec
                                                  .Count);
                                          Trust.Entries (I) :=
                                            (First =>
                                               D.Trust_Anchor_Spec
                                                 .Entries (I).First
                                               + Leaf_Len,
                                             Last =>
                                               D.Trust_Anchor_Spec
                                                 .Entries (I).Last
                                               + Leaf_Len);
                                       end loop;
                                       Tls_Core.Cert_Chain
                                         .Authenticate_Server
                                           (All_Certs       => All_Certs,
                                            Chain_In        => Chain_In,
                                            Trust           => Trust,
                                            Hostname        =>
                                              D.Sni_Hostname
                                                (1 .. D.Sni_Len),
                                            Sig_Scheme      => Sig_Scheme,
                                            Sig_Body        =>
                                              Body_Bytes
                                                (Sig_F .. Sig_L),
                                            Transcript_Hash =>
                                              Th_After_Cert,
                                            Result          => Result);
                                       if not Tls_Core.Cert_Chain
                                                ."=" (Result, Tls_Core
                                                                .Cert_Chain
                                                                .OK_Validated)
                                       then
                                          Fail_Encrypted
                                            (D, Tls_Core.Alert
                                                  .Desc_Bad_Certificate,
                                             Out_Buf, Out_Last);
                                          return;
                                       end if;
                                    end;
                                 end;
                                 Tls_Core.Transcript.Append
                                   (D.Hash_Ctx,
                                    Msg_Buf (1 .. Msg_Last));
                                 Tls_Core.Transcript.Snapshot
                                   (D.Hash_Ctx, Th_After_CV);
                                 Sub := Expect_SF;

                              when Expect_SF =>
                                 if Msg_Last /= 4 + 32
                                   or else Msg_Buf (1) /=
                                             Hs_Type_Finished
                                 then
                                    Fail_Encrypted
                                      (D, Tls_Core.Alert
                                            .Desc_Decode_Error,
                                       Out_Buf, Out_Last);
                                    return;
                                 end if;
                                 Build_Finished_Body
                                   (D.S_Hs_Sec, Th_After_CV,
                                    Expected_Sf);
                                 Diff := 0;
                                 for I in 1 .. 32 loop
                                    pragma Loop_Invariant
                                      (I in 1 .. 32);
                                    Diff := Diff or
                                      (Msg_Buf (4 + I)
                                       xor Expected_Sf (I));
                                 end loop;
                                 if Diff /= 0 then
                                    D.Cur_State := Failed;
                                    return;
                                 end if;
                                 Tls_Core.Transcript.Append
                                   (D.Hash_Ctx,
                                    Msg_Buf (1 .. Msg_Last));
                                 Sub := Done_Sub;

                              when Done_Sub =>
                                 null;
                           end case;
                        end loop;
                     end loop;
                     if Sub /= Done_Sub then
                        Fail_Encrypted
                          (D, Tls_Core.Alert.Desc_Decode_Error,
                           Out_Buf, Out_Last);
                        return;
                     end if;
                  end;

                  --  Step 4: app traffic secrets.
                  Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Th_After_Sf);
                  declare
                     Derived_2_Sec : Tls_Core.Key_Schedule.Secret;
                     Master_Secret : Tls_Core.Key_Schedule.Secret;
                  begin
                     Tls_Core.Sha256.Hash (Empty_In, Empty_Hash);
                     Hkdf_Expand_Label_Sha256
                       (Secret  => D.Hs_Secret,
                        Label   => Derived_Lab,
                        Context => Empty_Hash,
                        Output  => Derived_2_Sec);
                     Tls_Core.Key_Schedule.Extract
                       (Salt => Derived_2_Sec, IKM => Zero_Secret,
                        Out_PRK => Master_Secret);
                     Hkdf_Expand_Label_Sha256
                       (Secret  => Master_Secret,
                        Label   => C_Ap_Lab,
                        Context => Th_After_Sf,
                        Output  => D.App_C_Ap);
                     Hkdf_Expand_Label_Sha256
                       (Secret  => Master_Secret,
                        Label   => S_Ap_Lab,
                        Context => Th_After_Sf,
                        Output  => D.App_S_Ap);
                     D.App_Set := True;
                     D.Master_Sec := Master_Secret;
                     D.Master_Set := True;
                  end;

                  --  Step 5: build + send client Finished.
                  declare
                     Cf_Verify : Tls_Core.Sha256.Digest;
                     Cf_Hs : Octet_Array (1 .. 4 + 32) := (others => 0);
                     Cf_Hs_Last : Natural;
                     Cf_Rec : Octet_Array (1 .. 256) := (others => 0);
                     Cf_Rec_Last : Natural;
                  begin
                     Build_Finished_Body
                       (D.C_Hs_Sec, Th_After_Sf, Cf_Verify);
                     Encode_Hs_Message
                       (Hs_Type_Finished, Cf_Verify,
                        Cf_Hs, Cf_Hs_Last);
                     Tls_Core.Transcript.Append
                       (D.Hash_Ctx, Cf_Hs (1 .. Cf_Hs_Last));
                     Tls_Core.Aead_Channel.Send
                       (D.Hs_Out_Dir,
                        Cf_Hs (1 .. Cf_Hs_Last),
                        Tls_Core.Aead_Channel.Inner_Type_Handshake,
                        Cf_Rec, Cf_Rec_Last);
                     Out_Buf (1 .. Cf_Rec_Last) :=
                       Cf_Rec (1 .. Cf_Rec_Last);
                     Out_Last := Cf_Rec_Last;
                  end;

                  --  resumption_master_secret per §7.1 (CH..CF).
                  if D.Master_Set then
                     declare
                        Th_After_Cf : Tls_Core.Sha256.Digest;
                     begin
                        Tls_Core.Transcript.Snapshot
                          (D.Hash_Ctx, Th_After_Cf);
                        Tls_Core.Session_Ticket
                          .Derive_Resumption_Master_Secret_Sha256
                            (Master_Secret     => D.Master_Sec,
                             Transcript_Hash   => Th_After_Cf,
                             Resumption_Secret => D.Res_Master_Sec);
                        D.Res_Master_Set := True;
                     end;
                  end if;

                  D.Cur_State := Done;
               end;
               return;
            end if;

            declare
               Cursor : Natural := In_Bytes'First;

               --  Used to derive c_hs / s_hs after parsing SH.
               Empty_Hash    : Tls_Core.Sha256.Digest;
               Empty_In      : constant Octet_Array (1 .. 0) :=
                 (others => 0);
               Zero_Secret   : constant Tls_Core.Key_Schedule.Secret :=
                 (others => 0);
               Derived_Lab   : constant Octet_Array (1 .. 7) :=
                 (16#64#, 16#65#, 16#72#, 16#69#, 16#76#, 16#65#, 16#64#);
               C_Hs_Lab      : constant Octet_Array (1 .. 12) :=
                 (16#63#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
                  16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
               S_Hs_Lab      : constant Octet_Array (1 .. 12) :=
                 (16#73#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
                  16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
               C_Ap_Lab      : constant Octet_Array (1 .. 12) :=
                 (16#63#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
                  16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
               S_Ap_Lab      : constant Octet_Array (1 .. 12) :=
                 (16#73#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
                  16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);

               Early_Secret  : Tls_Core.Key_Schedule.Secret;
               Derived_1     : Tls_Core.Key_Schedule.Secret;
               Th_After_Sh   : Tls_Core.Sha256.Digest;
               Th_After_Ee   : Tls_Core.Sha256.Digest;
               Th_After_Sf   : Tls_Core.Sha256.Digest;
            begin
               --  Step 1: parse SH TLSPlaintext.
               if Cursor + 4 > In_Bytes'Last
                 or else In_Bytes (Cursor) /= Rec_Type_Handshake
               then
                  D.Cur_State := Failed;
                  return;
               end if;
               declare
                  use type Tls_Core.Suites.U16;
                  Sh_Rec_Len : constant Natural :=
                    Natural (In_Bytes (Cursor + 3)) * 256
                    + Natural (In_Bytes (Cursor + 4));
                  Sh_Rec_F : constant Natural := Cursor + 5;
                  Sh_Rec_L : constant Natural := Sh_Rec_F + Sh_Rec_Len - 1;
               begin
                  if Sh_Rec_L > In_Bytes'Last
                    or else Sh_Rec_Len < 4
                    or else In_Bytes (Sh_Rec_F) /= Hs_Type_SH
                  then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  --  Extract server's selected cipher_suite from SH
                  --  per RFC 8446 §4.1.3. SH wire layout (after the
                  --  4-byte Handshake header at Sh_Rec_F):
                  --    + 4 ..  5  legacy_version  (0x0303)
                  --    + 6 .. 37  random          (32 bytes)
                  --    + 38       session_id_len  (== 0 for v0.5)
                  --    + 39 .. 40 cipher_suite    (u16)
                  if Sh_Rec_F + 40 > In_Bytes'Last
                    or else In_Bytes (Sh_Rec_F + 38) /= 0
                  then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  declare
                     Code : constant Tls_Core.Suites.U16 :=
                       Tls_Core.Suites.U16 (In_Bytes (Sh_Rec_F + 39)) * 256
                       + Tls_Core.Suites.U16 (In_Bytes (Sh_Rec_F + 40));
                  begin
                     if not Tls_Core.Suites.Is_Supported_Suite (Code)
                       or else Code =
                                 Tls_Core.Suites.TLS_AES_256_GCM_SHA384
                     then
                        --  Unrecognised, or AES-256-GCM-SHA384 (driver
                        --  schedule path is SHA-256-only — see package
                        --  wall-hit note).
                        D.Cur_State := Failed;
                        return;
                     end if;
                     D.Suite := Tls_Core.Suites.Suite_Of_Code (Code);
                  end;
                  --  RFC 8446 §4.2.8 / §7.1 mode 3 — extract the
                  --  server's X25519 public key from the SH key_share
                  --  extension and compute the ECDHE shared secret.
                  --  Decode_Server_Hello_Psk_Key_Share takes the SH
                  --  body (bytes after the 4-byte handshake header).
                  declare
                     Sh_Body_F : constant Natural := Sh_Rec_F + 4;
                     Sh_Body_L : constant Natural := Sh_Rec_L;
                     Ks_F, Ks_L : Natural;
                     Ks_OK : Boolean;
                     Peer_Pub : Tls_Core.X25519.Bytes_32;
                     Shared   : Tls_Core.X25519.Bytes_32;
                  begin
                     Tls_Core.Hello.Decode_Server_Hello_Psk_Key_Share
                       (In_Bytes (Sh_Body_F .. Sh_Body_L),
                        Ks_F, Ks_L, Ks_OK);
                     if not Ks_OK then
                        D.Cur_State := Failed;
                        return;
                     end if;
                     for I in 1 .. 32 loop
                        pragma Loop_Invariant (I in 1 .. 32);
                        Peer_Pub (I) := In_Bytes (Ks_F + I - 1);
                     end loop;
                     D.Peer_Ecdhe_Pub := Peer_Pub;
                     Tls_Core.X25519.Scalar_Mult
                       (D.My_Ecdhe_Priv, Peer_Pub, Shared);
                     D.Ecdhe_Shared := Shared;
                  end;
                  --  Append SH handshake message to transcript.
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, In_Bytes (Sh_Rec_F .. Sh_Rec_L));
                  Cursor := Sh_Rec_L + 1;
               end;

               --  Step 2: derive handshake secrets. RFC 8446 §7.1 mode 3:
               --    Handshake_Secret = HKDF-Extract(Derived_1, ECDHE_secret)
               --  where ECDHE_secret is the X25519 shared we just computed.
               Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Th_After_Sh);
               Tls_Core.Key_Schedule.Extract
                 (Salt => Zero_Secret, IKM => D.PSK,
                  Out_PRK => Early_Secret);
               Tls_Core.Key_Schedule.Derive_Secret
                 (Secret_In => Early_Secret,
                  Label     => Derived_Lab,
                  Messages  => Empty_In,
                  Out_Secret => Derived_1);
               Tls_Core.Key_Schedule.Extract
                 (Salt => Derived_1, IKM => D.Ecdhe_Shared,
                  Out_PRK => D.Hs_Secret);
               Hkdf_Expand_Label_Sha256
                 (Secret  => D.Hs_Secret,
                  Label   => C_Hs_Lab,
                  Context => Th_After_Sh,
                  Output  => D.C_Hs_Sec);
               Hkdf_Expand_Label_Sha256
                 (Secret  => D.Hs_Secret,
                  Label   => S_Hs_Lab,
                  Context => Th_After_Sh,
                  Output  => D.S_Hs_Sec);
               --  Client: in decrypts with s_hs; out encrypts with c_hs.
               --  Init_Sha256 dispatches the AEAD by D.Suite.
               Tls_Core.Aead_Channel.Init_Sha256
                 (D.Hs_In_Dir,  D.Suite, D.S_Hs_Sec);
               Tls_Core.Aead_Channel.Init_Sha256
                 (D.Hs_Out_Dir, D.Suite, D.C_Hs_Sec);

               --  Step 3+4: decrypt every subsequent record on the
               --  handshake stream, push the inner plaintext through
               --  Tls_Core.Handshake_Buffer, and pop complete handshake
               --  messages in expected order. RFC 8446 §5.1 allows a
               --  handshake message to span multiple records; §4 also
               --  permits multiple handshake messages packed in a
               --  single record. Both shapes are handled by the
               --  buffer + per-message pop loop.
               --
               --  Substate transitions:
               --    Expect_EE  → after EE appended to transcript and
               --                 Th_After_Ee snapshotted (for §4.4.4
               --                 SF verify_data binding) →  Expect_SF
               --    Expect_SF  → after SF verify_data check passes →
               --                 Done_Sub (loop exits)
               declare
                  type Sub_State is (Expect_EE, Expect_SF, Done_Sub);
                  Sub  : Sub_State := Expect_EE;
                  --  Per-record scratch.
                  Pt_Buf : Octet_Array (1 .. 16640) := (others => 0);
                  Pt_Last : Natural;
                  Inner_Type : Octet;
                  Aead_OK : Boolean;
                  Rec_Len : Natural;
                  Rec_End : Natural;
                  Push_OK : Boolean;
                  --  Per-message scratch.
                  Msg_Buf : Octet_Array (1 .. Tls_Core.Handshake_Buffer.Max_Buf)
                    := (others => 0);
                  Msg_Last : Natural;
                  Body_Len : Natural;
                  Expected_Sf : Tls_Core.Sha256.Digest;
                  Diff : Octet;
               begin
                  Tls_Core.Handshake_Buffer.Init (D.Hs_In_Buf);

                  --  Outer loop: walk inbound records.
                  while Cursor <= In_Bytes'Last and then Sub /= Done_Sub loop
                     pragma Loop_Invariant
                       (Cursor in In_Bytes'First .. In_Bytes'Last + 1);
                     if Cursor + 4 > In_Bytes'Last
                       or else In_Bytes (Cursor) /=
                                 Tls_Core.Aead_Channel.Inner_Type_Application_Data
                     then
                        Fail_Encrypted
                          (D, Tls_Core.Alert.Desc_Decode_Error,
                           Out_Buf, Out_Last);
                        return;
                     end if;
                     Rec_Len := Natural (In_Bytes (Cursor + 3)) * 256
                                + Natural (In_Bytes (Cursor + 4));
                     Rec_End := Cursor + 5 + Rec_Len - 1;
                     if Rec_End > In_Bytes'Last then
                        Fail_Encrypted
                          (D, Tls_Core.Alert.Desc_Decode_Error,
                           Out_Buf, Out_Last);
                        return;
                     end if;
                     Tls_Core.Aead_Channel.Receive
                       (D.Hs_In_Dir, In_Bytes (Cursor .. Rec_End),
                        Pt_Buf, Pt_Last, Inner_Type, Aead_OK);
                     if not Aead_OK then
                        Fail_Encrypted
                          (D, Tls_Core.Alert.Desc_Bad_Record_Mac,
                           Out_Buf, Out_Last);
                        return;
                     end if;
                     if Inner_Type /=
                          Tls_Core.Aead_Channel.Inner_Type_Handshake
                     then
                        Fail_Encrypted
                          (D, Tls_Core.Alert.Desc_Unexpected_Message,
                           Out_Buf, Out_Last);
                        return;
                     end if;
                     --  Push this record's inner plaintext into the
                     --  reassembly buffer.
                     if Pt_Last >
                          Tls_Core.Handshake_Buffer.Max_Buf
                     then
                        Fail_Encrypted
                          (D, Tls_Core.Alert.Desc_Decode_Error,
                           Out_Buf, Out_Last);
                        return;
                     end if;
                     Tls_Core.Handshake_Buffer.Push_Record_Bytes
                       (D.Hs_In_Buf, Pt_Buf (1 .. Pt_Last), Push_OK);
                     if not Push_OK then
                        Fail_Encrypted
                          (D, Tls_Core.Alert.Desc_Internal_Error,
                           Out_Buf, Out_Last);
                        return;
                     end if;
                     Cursor := Rec_End + 1;

                     --  Inner loop: drain complete handshake messages.
                     while Tls_Core.Handshake_Buffer.Has_Complete_Message
                             (D.Hs_In_Buf)
                       and then Sub /= Done_Sub
                     loop
                        pragma Loop_Invariant (Sub in Expect_EE | Expect_SF);
                        Body_Len :=
                          Tls_Core.Handshake_Buffer.Peek_Body_Length
                            (D.Hs_In_Buf);
                        if Body_Len + 4 > Msg_Buf'Length then
                           Fail_Encrypted
                             (D, Tls_Core.Alert.Desc_Decode_Error,
                              Out_Buf, Out_Last);
                           return;
                        end if;
                        Tls_Core.Handshake_Buffer.Pop_Complete_Message
                          (D.Hs_In_Buf, Msg_Buf, Msg_Last);

                        case Sub is
                           when Expect_EE =>
                              if Msg_Last < 4
                                or else Msg_Buf (1) /= Hs_Type_EE
                              then
                                 Fail_Encrypted
                                   (D, Tls_Core.Alert.Desc_Decode_Error,
                                    Out_Buf, Out_Last);
                                 return;
                              end if;
                              Tls_Core.Transcript.Append
                                (D.Hash_Ctx, Msg_Buf (1 .. Msg_Last));
                              Tls_Core.Transcript.Snapshot
                                (D.Hash_Ctx, Th_After_Ee);
                              Sub := Expect_SF;

                           when Expect_SF =>
                              if Msg_Last /= 4 + 32
                                or else Msg_Buf (1) /= Hs_Type_Finished
                              then
                                 Fail_Encrypted
                                   (D, Tls_Core.Alert.Desc_Decode_Error,
                                    Out_Buf, Out_Last);
                                 return;
                              end if;
                              --  Verify server Finished verify_data:
                              --  HMAC of s_hs_finished_key over Th_After_Ee.
                              Build_Finished_Body
                                (D.S_Hs_Sec, Th_After_Ee, Expected_Sf);
                              Diff := 0;
                              for I in 1 .. 32 loop
                                 pragma Loop_Invariant (I in 1 .. 32);
                                 Diff := Diff or
                                   (Msg_Buf (4 + I) xor Expected_Sf (I));
                              end loop;
                              if Diff /= 0 then
                                 D.Cur_State := Failed;
                                 return;
                              end if;
                              Tls_Core.Transcript.Append
                                (D.Hash_Ctx, Msg_Buf (1 .. Msg_Last));
                              Sub := Done_Sub;

                           when Done_Sub =>
                              null;
                        end case;
                     end loop;
                  end loop;

                  if Sub /= Done_Sub then
                     --  Ran out of records before SF was popped.
                     Fail_Encrypted
                       (D, Tls_Core.Alert.Desc_Decode_Error,
                        Out_Buf, Out_Last);
                     return;
                  end if;
               end;

               --  Step 5: derive app secrets.
               Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Th_After_Sf);
               declare
                  Derived_2_Sec : Tls_Core.Key_Schedule.Secret;
                  Master_Secret : Tls_Core.Key_Schedule.Secret;
               begin
                  Tls_Core.Sha256.Hash (Empty_In, Empty_Hash);
                  Hkdf_Expand_Label_Sha256
                    (Secret  => D.Hs_Secret,
                     Label   => Derived_Lab,
                     Context => Empty_Hash,
                     Output  => Derived_2_Sec);
                  Tls_Core.Key_Schedule.Extract
                    (Salt => Derived_2_Sec, IKM => Zero_Secret,
                     Out_PRK => Master_Secret);
                  Hkdf_Expand_Label_Sha256
                    (Secret  => Master_Secret,
                     Label   => C_Ap_Lab,
                     Context => Th_After_Sf,
                     Output  => D.App_C_Ap);
                  Hkdf_Expand_Label_Sha256
                    (Secret  => Master_Secret,
                     Label   => S_Ap_Lab,
                     Context => Th_After_Sf,
                     Output  => D.App_S_Ap);
                  D.App_Set := True;
                  --  Save Master_Secret so we can derive
                  --  resumption_master_secret (RFC 8446 §7.1) once
                  --  the client Finished is appended to the
                  --  transcript below.
                  D.Master_Sec := Master_Secret;
                  D.Master_Set := True;
               end;

               --  Step 6: build + send client Finished.
               declare
                  Cf_Verify : Tls_Core.Sha256.Digest;
                  Cf_Hs : Octet_Array (1 .. 4 + 32) := (others => 0);
                  Cf_Hs_Last : Natural;
                  Cf_Rec : Octet_Array (1 .. 256) := (others => 0);
                  Cf_Rec_Last : Natural;
               begin
                  Build_Finished_Body
                    (D.C_Hs_Sec, Th_After_Sf, Cf_Verify);
                  Encode_Hs_Message
                    (Hs_Type_Finished, Cf_Verify,
                     Cf_Hs, Cf_Hs_Last);
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, Cf_Hs (1 .. Cf_Hs_Last));
                  Tls_Core.Aead_Channel.Send
                    (D.Hs_Out_Dir,
                     Cf_Hs (1 .. Cf_Hs_Last),
                     Tls_Core.Aead_Channel.Inner_Type_Handshake,
                     Cf_Rec, Cf_Rec_Last);
                  Out_Buf (1 .. Cf_Rec_Last) := Cf_Rec (1 .. Cf_Rec_Last);
                  Out_Last := Cf_Rec_Last;
               end;

               --  Derive resumption_master_secret per RFC 8446 §7.1:
               --    Derive-Secret(Master_Secret, "res master", CH..CF)
               --  Client side: Master_Sec was saved above when
               --  App_C_Ap / App_S_Ap were derived; the transcript
               --  now spans CH..CF (we just appended CF).
               if D.Master_Set then
                  declare
                     Th_After_Cf : Tls_Core.Sha256.Digest;
                  begin
                     Tls_Core.Transcript.Snapshot
                       (D.Hash_Ctx, Th_After_Cf);
                     Tls_Core.Session_Ticket
                       .Derive_Resumption_Master_Secret_Sha256
                         (Master_Secret     => D.Master_Sec,
                          Transcript_Hash   => Th_After_Cf,
                          Resumption_Secret => D.Res_Master_Sec);
                     D.Res_Master_Set := True;
                  end;
               end if;

               D.Cur_State := Done;
            end;

         when Awaiting_CH =>
            --  RFC 8446 §4.1.3 cert-mode dispatch: parse cert CH,
            --  emit SH+EE+Cert+CertVerify+SF flight, transition to
            --  Awaiting_Cf. Mirrors the PSK branch's structure but
            --  with no binder check, no PSK extension, and the
            --  §4.4.2 + §4.4.3 cert/sig wire pieces inserted between
            --  EE and SF.
            if D.Mode = Cert_Mode then
               --  Step 1: parse outer TLSPlaintext + handshake header.
               if In_Bytes'Length < 5
                 or else In_Bytes (In_Bytes'First) /= Rec_Type_Handshake
               then
                  Fail_Plaintext
                    (D, Tls_Core.Alert.Desc_Decode_Error,
                     Out_Buf, Out_Last);
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
                     Hs_Body_L : constant Natural :=
                       Hs_Body_F + Hs_Body_Len - 1;

                     Random : Tls_Core.Hello.Random_Bytes;
                     Sid_F, Sid_L : Natural;
                     Suites_F, Suites_L : Natural;
                     Sig_Algs_F, Sig_Algs_L : Natural;
                     Ks_F, Ks_L : Natural;
                     Decode_OK : Boolean;
                  begin
                     if Hs_Body_L > Rec_L then
                        D.Cur_State := Failed;
                        return;
                     end if;
                     Tls_Core.Hello.Decode_Client_Hello_Cert
                       (In_Bytes (Hs_Body_F .. Hs_Body_L),
                        Random, Sid_F, Sid_L,
                        Suites_F, Suites_L,
                        Sig_Algs_F, Sig_Algs_L,
                        Ks_F, Ks_L, Decode_OK);
                     if not Decode_OK then
                        D.Cur_State := Failed;
                        return;
                     end if;
                     pragma Unreferenced (Sig_Algs_F, Sig_Algs_L);
                     --  Capture legacy_session_id for SH echo (§4.1.3).
                     if Sid_F > 0 and then Sid_L >= Sid_F
                       and then Sid_L - Sid_F + 1 <= 32
                     then
                        D.Session_Id_Echo_Len := Sid_L - Sid_F + 1;
                        D.Session_Id_Echo (1 .. D.Session_Id_Echo_Len) :=
                          In_Bytes (Sid_F .. Sid_L);
                     else
                        D.Session_Id_Echo_Len := 0;
                     end if;
                     --  v0.5 sig_algs scope is fixed at
                     --  ecdsa_secp256r1_sha256; client is required to
                     --  offer it. Decode_Client_Hello_Cert already
                     --  asserts presence; per-scheme picking is a
                     --  v0.5.x refinement.
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
                     --  Cipher-suite selection — same v0.5 SHA-256
                     --  restriction as PSK branch.
                     declare
                        use type Tls_Core.Suites.U16;
                        Found : Boolean := False;
                        Code  : Tls_Core.Suites.U16;
                        Q : Natural := Suites_F;
                     begin
                        while Q + 1 <= Suites_L loop
                           pragma Loop_Invariant
                             (Q in Suites_F .. Suites_L + 1);
                           Code :=
                             Tls_Core.Suites.U16 (In_Bytes (Q)) * 256
                             + Tls_Core.Suites.U16 (In_Bytes (Q + 1));
                           if Code =
                                Tls_Core.Suites.TLS_AES_128_GCM_SHA256
                           then
                              D.Suite :=
                                Tls_Core.Suites.Aes_128_Gcm_Sha256;
                              Found := True;
                              exit;
                           elsif Code =
                                   Tls_Core.Suites
                                     .TLS_CHACHA20_POLY1305_SHA256
                           then
                              D.Suite :=
                                Tls_Core.Suites
                                  .Chacha20_Poly1305_Sha256;
                              Found := True;
                              exit;
                           end if;
                           Q := Q + 2;
                        end loop;
                        if not Found then
                           D.Cur_State := Failed;
                           return;
                        end if;
                     end;
                     --  Append CH (handshake message) to transcript.
                     Tls_Core.Transcript.Append
                       (D.Hash_Ctx, In_Bytes (Rec_F .. Rec_L));
                  end;
               end;

               --  Step 2: build SH + key schedule + EE + Cert +
               --  CertVerify + SF.  Cert-mode key schedule (§7.1):
               --    Early_Secret = HKDF-Extract(Zero, Zero)  -- PSK = 0
               --    Derived_1    = Derive-Secret(Early, "derived", "")
               --    Hs_Secret    = HKDF-Extract(Derived_1, ECDHE)
               declare
                  Server_Random : constant Tls_Core.Hello.Random_Bytes :=
                    (others => 16#5E#);

                  Sh_Body : Octet_Array (1 .. 256) := (others => 0);
                  Sh_Body_Last : Natural;
                  Sh_Hs    : Octet_Array (1 .. 512) := (others => 0);
                  Sh_Hs_Last : Natural;
                  Sh_Rec   : Octet_Array (1 .. 1024) := (others => 0);
                  Sh_Rec_Last : Natural;

                  Zero32   : constant Octet_Array (1 .. 32) :=
                    (others => 0);
                  Empty_In : constant Octet_Array (1 .. 0) :=
                    (others => 0);
                  Empty_Hash : Tls_Core.Sha256.Digest;

                  Derived_Lab : constant Octet_Array (1 .. 7) :=
                    (16#64#, 16#65#, 16#72#, 16#69#, 16#76#, 16#65#,
                     16#64#);
                  C_Hs_Lab : constant Octet_Array (1 .. 12) :=
                    (16#63#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
                     16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
                  S_Hs_Lab : constant Octet_Array (1 .. 12) :=
                    (16#73#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
                     16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
                  C_Ap_Lab : constant Octet_Array (1 .. 12) :=
                    (16#63#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
                     16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
                  S_Ap_Lab : constant Octet_Array (1 .. 12) :=
                    (16#73#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
                     16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);

                  Early_Secret : Tls_Core.Key_Schedule.Secret;
                  Derived_1    : Tls_Core.Key_Schedule.Secret;

                  Th_After_Sh   : Tls_Core.Sha256.Digest;
                  Th_After_Cert : Tls_Core.Sha256.Digest;
                  Th_After_CV   : Tls_Core.Sha256.Digest;
                  Th_After_Sf   : Tls_Core.Sha256.Digest;

                  Out_Cursor : Natural := 0;
               begin
                  --  Build SH (cert-mode SH = no pre_shared_key ext).
                  Tls_Core.Hello.Encode_Server_Hello_Cert
                    (Server_Random,
                     D.Session_Id_Echo (1 .. D.Session_Id_Echo_Len),
                     Tls_Core.Suites.Code_Of_Suite (D.Suite),
                     D.My_Ecdhe_Pub,
                     Sh_Body, Sh_Body_Last);
                  Encode_Hs_Message
                    (Hs_Type_SH, Sh_Body (1 .. Sh_Body_Last),
                     Sh_Hs, Sh_Hs_Last);
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, Sh_Hs (1 .. Sh_Hs_Last));
                  Wrap_Tls_Plaintext
                    (Sh_Hs (1 .. Sh_Hs_Last), Sh_Rec, Sh_Rec_Last);

                  --  Cert-mode key schedule.
                  Tls_Core.Key_Schedule.Extract
                    (Salt => Zero32, IKM => Zero32,
                     Out_PRK => Early_Secret);
                  Tls_Core.Key_Schedule.Derive_Secret
                    (Secret_In  => Early_Secret,
                     Label      => Derived_Lab,
                     Messages   => Empty_In,
                     Out_Secret => Derived_1);
                  Tls_Core.Key_Schedule.Extract
                    (Salt => Derived_1, IKM => D.Ecdhe_Shared,
                     Out_PRK => D.Hs_Secret);
                  Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Th_After_Sh);
                  Hkdf_Expand_Label_Sha256
                    (Secret  => D.Hs_Secret,
                     Label   => C_Hs_Lab,
                     Context => Th_After_Sh,
                     Output  => D.C_Hs_Sec);
                  Hkdf_Expand_Label_Sha256
                    (Secret  => D.Hs_Secret,
                     Label   => S_Hs_Lab,
                     Context => Th_After_Sh,
                     Output  => D.S_Hs_Sec);
                  --  Open handshake-stage Aead_Channel directions.
                  Tls_Core.Aead_Channel.Init_Sha256
                    (D.Hs_Out_Dir, D.Suite, D.S_Hs_Sec);
                  Tls_Core.Aead_Channel.Init_Sha256
                    (D.Hs_In_Dir,  D.Suite, D.C_Hs_Sec);

                  --  Output buffer accumulator: SH (TLSPlaintext)
                  --  followed by encrypted EE/Cert/CertVerify/SF
                  --  records.
                  Out_Buf (1 .. Sh_Rec_Last) := Sh_Rec (1 .. Sh_Rec_Last);
                  Out_Cursor := Sh_Rec_Last;

                  --  EE — empty extensions.
                  declare
                     Ee_Body : constant Octet_Array (1 .. 2) :=
                       (16#00#, 16#00#);
                     Ee_Hs   : Octet_Array (1 .. 6) := (others => 0);
                     Ee_Hs_Last : Natural;
                     Ee_Rec  : Octet_Array (1 .. 256) := (others => 0);
                     Ee_Rec_Last : Natural;
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
                     Out_Buf (Out_Cursor + 1 ..
                                Out_Cursor + Ee_Rec_Last) :=
                       Ee_Rec (1 .. Ee_Rec_Last);
                     Out_Cursor := Out_Cursor + Ee_Rec_Last;
                  end;

                  --  Certificate (RFC 8446 §4.4.2). v0.5 emits the
                  --  leaf cert only — a single CertificateEntry.
                  --  Cert_Chain_Spec.Entries (1) names the leaf
                  --  (First..Last) inside D.Cert_Chain_Bytes.
                  declare
                     Leaf_F : constant Natural :=
                       D.Cert_Chain_Spec.Entries (1).First;
                     Leaf_L : constant Natural :=
                       D.Cert_Chain_Spec.Entries (1).Last;
                     Cert_Body : Octet_Array (1 .. 1 + 3 + 3 + 2 + 2048)
                       := (others => 0);
                     Cert_Body_Last : Natural;
                     Cert_Hs   : Octet_Array (1 .. 4 + 1 + 3 + 3 + 2 + 2048)
                       := (others => 0);
                     Cert_Hs_Last : Natural;
                     Cert_Rec  : Octet_Array (1 .. 4 + 1 + 3 + 3 + 2 + 2048 + 32)
                       := (others => 0);
                     Cert_Rec_Last : Natural;
                  begin
                     if Leaf_F < D.Cert_Chain_Bytes'First
                       or else Leaf_L > D.Cert_Chain_Bytes'Last
                       or else Leaf_F > Leaf_L
                       or else Leaf_L - Leaf_F + 1 > 2048
                     then
                        D.Cur_State := Failed;
                        return;
                     end if;
                     Tls_Core.Cert_Verify.Encode_Body_Single
                       (D.Cert_Chain_Bytes (Leaf_F .. Leaf_L),
                        Cert_Body, Cert_Body_Last);
                     Encode_Hs_Message
                       (Hs_Type_Cert, Cert_Body (1 .. Cert_Body_Last),
                        Cert_Hs, Cert_Hs_Last);
                     Tls_Core.Transcript.Append
                       (D.Hash_Ctx, Cert_Hs (1 .. Cert_Hs_Last));
                     Tls_Core.Aead_Channel.Send
                       (D.Hs_Out_Dir,
                        Cert_Hs (1 .. Cert_Hs_Last),
                        Tls_Core.Aead_Channel.Inner_Type_Handshake,
                        Cert_Rec, Cert_Rec_Last);
                     if Out_Cursor + Cert_Rec_Last > Out_Buf'Last then
                        D.Cur_State := Failed;
                        return;
                     end if;
                     Out_Buf (Out_Cursor + 1 ..
                                Out_Cursor + Cert_Rec_Last) :=
                       Cert_Rec (1 .. Cert_Rec_Last);
                     Out_Cursor := Out_Cursor + Cert_Rec_Last;
                  end;

                  --  CertificateVerify (RFC 8446 §4.4.3).
                  Tls_Core.Transcript.Snapshot
                    (D.Hash_Ctx, Th_After_Cert);
                  declare
                     Signed_Buf : Octet_Array (1 .. 64 + 33 + 1 + 32) :=
                       (others => 0);
                     Signed_Last : Natural;
                     K_Bytes : Tls_Core.Ecdsa_P256.Component;
                     K_OK    : Boolean;
                     R, S   : Tls_Core.Ecdsa_P256.Component;
                     Sign_OK : Boolean;
                     Der_Sig : Octet_Array (1 .. 72) := (others => 0);
                     Der_Last : Natural;
                     Cv_Body  : Octet_Array (1 .. 4 + 72) := (others => 0);
                     Cv_Body_Last : Natural;
                     Cv_Hs    : Octet_Array (1 .. 4 + 4 + 72) :=
                       (others => 0);
                     Cv_Hs_Last : Natural;
                     Cv_Rec   : Octet_Array (1 .. 256) := (others => 0);
                     Cv_Rec_Last : Natural;
                  begin
                     Tls_Core.Cert_Verify.Build_Signed_Content
                       (Side            => Tls_Core.Cert_Verify.Server,
                        Transcript_Hash => Th_After_Cert,
                        Out_Buf         => Signed_Buf,
                        Out_Last        => Signed_Last);
                     --  RFC 6979 §3.2 deterministic K — same K
                     --  openssl / Go / rustls / BoringSSL would
                     --  derive for the same (priv, message) pair, so
                     --  Tier-D external matrix can compare bit-for-bit.
                     Tls_Core.Ecdsa_P256.Derive_K_Rfc6979
                       (Private_Key => D.Server_Sign_Priv,
                        Message     => Signed_Buf (1 .. Signed_Last),
                        Out_K       => K_Bytes,
                        OK          => K_OK);
                     if not K_OK then
                        D.Cur_State := Failed;
                        return;
                     end if;
                     Tls_Core.Ecdsa_P256.Sign
                       (Private_Key => D.Server_Sign_Priv,
                        Message     => Signed_Buf (1 .. Signed_Last),
                        K           => K_Bytes,
                        Out_R       => R,
                        Out_S       => S,
                        OK          => Sign_OK);
                     if not Sign_OK then
                        D.Cur_State := Failed;
                        return;
                     end if;
                     Tls_Core.Cert_Verify.Encode_Ecdsa_Sig_Der
                       (R, S, Der_Sig, Der_Last);
                     Tls_Core.Cert_Verify.Encode_Body
                       (Sig_Scheme => Interfaces.Unsigned_16 (D.Sig_Alg),
                        Signature  => Der_Sig (1 .. Der_Last),
                        Out_Buf    => Cv_Body,
                        Out_Last   => Cv_Body_Last);
                     Encode_Hs_Message
                       (Hs_Type_Cert_Verify,
                        Cv_Body (1 .. Cv_Body_Last),
                        Cv_Hs, Cv_Hs_Last);
                     Tls_Core.Transcript.Append
                       (D.Hash_Ctx, Cv_Hs (1 .. Cv_Hs_Last));
                     Tls_Core.Aead_Channel.Send
                       (D.Hs_Out_Dir,
                        Cv_Hs (1 .. Cv_Hs_Last),
                        Tls_Core.Aead_Channel.Inner_Type_Handshake,
                        Cv_Rec, Cv_Rec_Last);
                     if Out_Cursor + Cv_Rec_Last > Out_Buf'Last then
                        D.Cur_State := Failed;
                        return;
                     end if;
                     Out_Buf (Out_Cursor + 1 ..
                                Out_Cursor + Cv_Rec_Last) :=
                       Cv_Rec (1 .. Cv_Rec_Last);
                     Out_Cursor := Out_Cursor + Cv_Rec_Last;
                  end;

                  --  Server Finished — HMAC of s_hs_finished_key over
                  --  transcript-after-CertVerify (§4.4.4).
                  Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Th_After_CV);
                  declare
                     Verify_Data : Tls_Core.Sha256.Digest;
                     Fin_Hs : Octet_Array (1 .. 4 + 32) := (others => 0);
                     Fin_Hs_Last : Natural;
                     Fin_Rec : Octet_Array (1 .. 256) := (others => 0);
                     Fin_Rec_Last : Natural;
                  begin
                     Build_Finished_Body
                       (D.S_Hs_Sec, Th_After_CV, Verify_Data);
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
                     if Out_Cursor + Fin_Rec_Last > Out_Buf'Last then
                        D.Cur_State := Failed;
                        return;
                     end if;
                     Out_Buf (Out_Cursor + 1 ..
                                Out_Cursor + Fin_Rec_Last) :=
                       Fin_Rec (1 .. Fin_Rec_Last);
                     Out_Last := Out_Cursor + Fin_Rec_Last;
                  end;

                  --  Application traffic secrets + expected client
                  --  Finished verify_data.
                  Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Th_After_Sf);
                  declare
                     Derived_2_Sec : Tls_Core.Key_Schedule.Secret;
                     Master_Secret : Tls_Core.Key_Schedule.Secret;
                     Zero_Secret   : constant Tls_Core.Key_Schedule.Secret :=
                       (others => 0);
                  begin
                     Tls_Core.Sha256.Hash (Empty_In, Empty_Hash);
                     Hkdf_Expand_Label_Sha256
                       (Secret  => D.Hs_Secret,
                        Label   => Derived_Lab,
                        Context => Empty_Hash,
                        Output  => Derived_2_Sec);
                     Tls_Core.Key_Schedule.Extract
                       (Salt => Derived_2_Sec, IKM => Zero_Secret,
                        Out_PRK => Master_Secret);
                     Hkdf_Expand_Label_Sha256
                       (Secret  => Master_Secret,
                        Label   => C_Ap_Lab,
                        Context => Th_After_Sf,
                        Output  => D.App_C_Ap);
                     Hkdf_Expand_Label_Sha256
                       (Secret  => Master_Secret,
                        Label   => S_Ap_Lab,
                        Context => Th_After_Sf,
                        Output  => D.App_S_Ap);
                     D.App_Set := True;
                     D.Master_Sec := Master_Secret;
                     D.Master_Set := True;
                     Build_Finished_Body
                       (D.C_Hs_Sec, Th_After_Sf, D.Expected_Cf);
                  end;

                  D.Cur_State := Awaiting_Cf;
               end;
               return;
            end if;

            --  Parse one TLSPlaintext record holding ClientHello.
            if In_Bytes'Length < 5
              or else In_Bytes (In_Bytes'First) /= Rec_Type_Handshake
            then
               Fail_Plaintext
                 (D, Tls_Core.Alert.Desc_Decode_Error,
                  Out_Buf, Out_Last);
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
                  --  Decode the CH body — also validates the client
                  --  advertises psk_dhe_ke (mode 1) and includes a
                  --  valid x25519 key_share. Returns absolute indices.
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
                  if Sid_F > 0 and then Sid_L >= Sid_F
                    and then Sid_L - Sid_F + 1 <= 32
                  then
                     D.Session_Id_Echo_Len := Sid_L - Sid_F + 1;
                     D.Session_Id_Echo (1 .. D.Session_Id_Echo_Len) :=
                       In_Bytes (Sid_F .. Sid_L);
                  else
                     D.Session_Id_Echo_Len := 0;
                  end if;
                  --  RFC 8446 §4.2.8 + §7.1 mode 3 — extract the
                  --  client's X25519 public key and compute ECDHE
                  --  shared secret on the server side.
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
                  --  Server cipher-suite selection (RFC 8446 §4.1.3):
                  --  walk client's offered list in order and pick
                  --  the first that we actually accept. v0.5 driver
                  --  internal key schedule is SHA-256-only (see
                  --  package wall-hit note), so we only accept the
                  --  two SHA-256-based suites here. If none match
                  --  → Failed (handshake_failure equivalent).
                  declare
                     use type Tls_Core.Suites.U16;
                     Found : Boolean := False;
                     Code  : Tls_Core.Suites.U16;
                     Q : Natural := Suites_F;
                  begin
                     while Q + 1 <= Suites_L loop
                        pragma Loop_Invariant
                          (Q in Suites_F .. Suites_L + 1);
                        Code :=
                          Tls_Core.Suites.U16 (In_Bytes (Q)) * 256
                          + Tls_Core.Suites.U16 (In_Bytes (Q + 1));
                        if Code = Tls_Core.Suites.TLS_AES_128_GCM_SHA256 then
                           D.Suite := Tls_Core.Suites.Aes_128_Gcm_Sha256;
                           Found := True;
                           exit;
                        elsif Code =
                              Tls_Core.Suites.TLS_CHACHA20_POLY1305_SHA256
                        then
                           D.Suite := Tls_Core.Suites.Chacha20_Poly1305_Sha256;
                           Found := True;
                           exit;
                        end if;
                        Q := Q + 2;
                     end loop;
                     if not Found then
                        D.Cur_State := Failed;
                        return;
                     end if;
                  end;
                  --  Decode_*_Psk returns absolute indices into the
                  --  In_Bytes slice it was passed; that slice has
                  --  'First = Hs_Body_F so the indices already are
                  --  in our outer In_Bytes' coordinate space.
                  declare
                     Abs_Id_F : constant Natural := Id_F;
                     Abs_Id_L : constant Natural := Id_L;
                     Abs_Bf : constant Natural := Bf;
                     Abs_Bl : constant Natural := Bl;
                     Abs_T_Last : constant Natural := T_Last;

                     --  Verify PSK identity matches expected.
                     Identity_OK : Boolean := True;
                  begin
                     if Abs_Id_L - Abs_Id_F + 1 /= D.Identity_Len then
                        Identity_OK := False;
                     else
                        for I in 1 .. D.Identity_Len loop
                           if In_Bytes (Abs_Id_F + I - 1)
                              /= D.Identity (I)
                           then
                              Identity_OK := False;
                           end if;
                        end loop;
                     end if;
                     if not Identity_OK then
                        D.Cur_State := Failed;
                        return;
                     end if;
                     --  Verify PSK binder.  RFC 8446 §4.2.11.2 + §4.4.1:
                     --  the binder is computed over the truncated
                     --  *handshake message* (Rec_F .. Abs_T_Last
                     --  spans CH type byte through last pre-binders
                     --  body byte), NOT the body alone (Hs_Body_F ..
                     --  Abs_T_Last).  Copy into a local 'First=1
                     --  buffer so Compute's 'First=1 Pre is satisfied.
                     declare
                        Computed : Tls_Core.Psk_Binder.Binder_Bytes;
                        Received : Tls_Core.Psk_Binder.Binder_Bytes;
                        Trunc_Len : constant Natural :=
                          Abs_T_Last - Rec_F + 1;
                        Hs_Trunc : Octet_Array (1 .. 16640) :=
                          (others => 0);
                     begin
                        if Trunc_Len > Hs_Trunc'Length then
                           D.Cur_State := Failed;
                           return;
                        end if;
                        Hs_Trunc (1 .. Trunc_Len) :=
                          In_Bytes (Rec_F .. Abs_T_Last);
                        Tls_Core.Psk_Binder.Compute
                          (D.PSK,
                           Hs_Trunc (1 .. Trunc_Len),
                           Computed);
                        for I in 1 .. 32 loop
                           Received (I) := In_Bytes (Abs_Bf + I - 1);
                        end loop;
                        if not Tls_Core.Psk_Binder.Verify
                                 (Computed, Received)
                        then
                           D.Cur_State := Failed;
                           return;
                        end if;
                     end;
                  end;
                  --  Append the CH handshake message (NOT the
                  --  record wrapper) to the transcript.
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, In_Bytes (Rec_F .. Rec_L));
               end;
            end;

            --  RFC 8446 §4.1.4 — HelloRetryRequest emission branch.
            --
            --  If the server was initialised with Hrr_Demand and has
            --  not yet sent an HRR, we now emit one *instead* of the
            --  SH+EE+SF flight. We also rebuild the transcript per
            --  §4.4.1: snapshot CH1's current accumulator, re-init,
            --  feed synthetic message_hash, then feed HRR. Subsequent
            --  CH2 will be appended on top of that.
            if D.Hrr_Demand and then not D.Hrr_Sent then
               declare
                  Hrr_Body     : Tls_Core.Octet_Array (1 .. 256) :=
                    (others => 0);
                  Hrr_Body_Last : Natural;
                  Hrr_Hs       : Tls_Core.Octet_Array (1 .. 512) :=
                    (others => 0);
                  Hrr_Hs_Last  : Natural;
                  Hrr_Rec      : Tls_Core.Octet_Array (1 .. 1024) :=
                    (others => 0);
                  Hrr_Rec_Last : Natural;
                  Synthetic    : Tls_Core.Octet_Array (1 .. 36) :=
                    (others => 0);
                  Cookie_Slice : constant Tls_Core.Octet_Array :=
                    D.Hrr_Cookie (1 .. D.Hrr_Cookie_Len);
               begin
                  --  Snapshot CH1 hash (transcript currently holds
                  --  exactly CH1) — we save it for diagnostic
                  --  introspection and feed it into the synthetic.
                  Tls_Core.Transcript.Snapshot
                    (D.Hash_Ctx, D.Hrr_Ch1_Hash);
                  --  Encode HRR body.
                  Tls_Core.Hello_Retry.Encode_Hrr
                    (Selected_Suite => Tls_Core.Suites.Code_Of_Suite (D.Suite),
                     Selected_Group => D.Hrr_Group,
                     Cookie         => Cookie_Slice,
                     Out_Buf        => Hrr_Body,
                     Out_Last       => Hrr_Body_Last);
                  --  Wrap as a Handshake message (type 0x02 — same
                  --  type as ServerHello per §4.1.4).
                  Encode_Hs_Message
                    (Hs_Type_SH,
                     Hrr_Body (1 .. Hrr_Body_Last),
                     Hrr_Hs, Hrr_Hs_Last);
                  --  Rebuild transcript per RFC 8446 §4.4.1:
                  --    new transcript = synthetic(CH1_hash) || HRR
                  Tls_Core.Hello_Retry.Build_Synthetic_Msg_Sha256
                    (D.Hrr_Ch1_Hash, Synthetic);
                  Tls_Core.Transcript.Init (D.Hash_Ctx);
                  Tls_Core.Transcript.Append (D.Hash_Ctx, Synthetic);
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, Hrr_Hs (1 .. Hrr_Hs_Last));
                  --  Wrap HRR as TLSPlaintext on the wire.
                  Wrap_Tls_Plaintext
                    (Hrr_Hs (1 .. Hrr_Hs_Last), Hrr_Rec, Hrr_Rec_Last);
                  Out_Buf (1 .. Hrr_Rec_Last) :=
                    Hrr_Rec (1 .. Hrr_Rec_Last);
                  Out_Last := Hrr_Rec_Last;
                  D.Hrr_Sent := True;
                  D.Cur_State := Awaiting_Ch_2;
                  return;
               end;
            end if;

            --  Build SH (handshake message), append to transcript,
            --  derive handshake secrets, build EE + Finished,
            --  encrypt, write the whole flight.
            declare
               Sh_Body : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
               Sh_Body_Last : Natural;
               Sh_Hs_Msg : Tls_Core.Octet_Array (1 .. 512) := (others => 0);
               Sh_Hs_Last : Natural;
               Sh_Record : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
               Sh_Record_Last : Natural;

               --  Use a fixed server random for now (test-friendly;
               --  real impls use a CSPRNG).
               Server_Random : constant Tls_Core.Hello.Random_Bytes :=
                 (others => 16#5E#);

               Empty_Identity_Buf : Tls_Core.Octet_Array (1 .. 0) :=
                 (others => 0);
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

               Transcript_Hash_After_SH : Tls_Core.Sha256.Digest;
            begin
               pragma Unreferenced (Empty_Identity_Buf);

               --  SH body = canonical PSK SH (echoes selected_identity = 0
               --  and the server's chosen cipher suite per RFC 8446 §4.1.3).
               --  The key_share carries the server's X25519 public key,
               --  echoing the named-group the client offered (x25519).
               Tls_Core.Hello.Encode_Server_Hello_Psk
                 (Server_Random,
                  D.Session_Id_Echo (1 .. D.Session_Id_Echo_Len),
                  Tls_Core.Suites.Code_Of_Suite (D.Suite),
                  D.My_Ecdhe_Pub,
                  Sh_Body, Sh_Body_Last);
               --  Wrap body into Handshake message (type + u24 + body).
               Encode_Hs_Message
                 (Hs_Type_SH,
                  Sh_Body (1 .. Sh_Body_Last),
                  Sh_Hs_Msg, Sh_Hs_Last);
               --  Append to transcript.
               Tls_Core.Transcript.Append
                 (D.Hash_Ctx, Sh_Hs_Msg (1 .. Sh_Hs_Last));
               --  Wrap as TLSPlaintext for the wire.
               Wrap_Tls_Plaintext
                 (Sh_Hs_Msg (1 .. Sh_Hs_Last), Sh_Record, Sh_Record_Last);

               --  Derive Early/Handshake secrets. RFC 8446 §7.1 mode 3:
               --    Handshake_Secret = HKDF-Extract(Derived_1, ECDHE_secret)
               --  D.Ecdhe_Shared was computed at CH parse time.
               Tls_Core.Key_Schedule.Extract
                 (Salt => Zero32, IKM => D.PSK, Out_PRK => Early_Secret);
               Tls_Core.Key_Schedule.Derive_Secret
                 (Secret_In  => Early_Secret,
                  Label      => Derived_Label,
                  Messages   => Empty,
                  Out_Secret => Derived_1);
               Tls_Core.Key_Schedule.Extract
                 (Salt => Derived_1, IKM => D.Ecdhe_Shared,
                  Out_PRK => Hs_Secret);
               --  Snapshot current transcript hash (CH || SH).
               Tls_Core.Transcript.Snapshot
                 (D.Hash_Ctx, Transcript_Hash_After_SH);
               --  c_hs / s_hs traffic secrets — same as Derive_Secret
               --  but with the snapshot we just took as the context.
               Hkdf_Expand_Label_Sha256
                 (Secret  => Hs_Secret,
                  Label   => C_Hs_Label,
                  Context => Transcript_Hash_After_SH,
                  Output  => C_Hs_Sec);
               Hkdf_Expand_Label_Sha256
                 (Secret  => Hs_Secret,
                  Label   => S_Hs_Label,
                  Context => Transcript_Hash_After_SH,
                  Output  => S_Hs_Sec);

               --  Open Aead_Channel Hs_Out_Dir / Hs_In_Dir (server:
               --  out encrypts with s_hs, in decrypts with c_hs). The
               --  Init_Sha256 dispatcher pins the variant to D.Suite.
               Tls_Core.Aead_Channel.Init_Sha256
                 (D.Hs_Out_Dir, D.Suite, S_Hs_Sec);
               Tls_Core.Aead_Channel.Init_Sha256
                 (D.Hs_In_Dir,  D.Suite, C_Hs_Sec);

               --  Save the secrets for later finished-key derivation
               --  + master-secret derivation in this same Step body.
               D.C_Hs_Sec := C_Hs_Sec;
               D.S_Hs_Sec := S_Hs_Sec;
               D.Hs_Secret := Hs_Secret;

               --  Build EE handshake message (empty extensions list).
               declare
                  Ee_Body : constant Octet_Array (1 .. 2) := (16#00#, 16#00#);
                  Ee_Hs   : Octet_Array (1 .. 6) := (others => 0);
                  Ee_Hs_Last : Natural;
                  Ee_Rec  : Octet_Array (1 .. 256) := (others => 0);
                  Ee_Rec_Last : Natural;
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

                  --  Build Server Finished.
                  declare
                     Th_After_EE : Tls_Core.Sha256.Digest;
                     Verify_Data : Tls_Core.Sha256.Digest;
                     Fin_Hs : Octet_Array (1 .. 4 + 32) := (others => 0);
                     Fin_Hs_Last : Natural;
                     Fin_Rec : Octet_Array (1 .. 256) := (others => 0);
                     Fin_Rec_Last : Natural;
                  begin
                     Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Th_After_EE);
                     Build_Finished_Body
                       (S_Hs_Sec, Th_After_EE, Verify_Data);
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

                     --  Concatenate SH || EE-encrypted || Finished-encrypted.
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

                     --  Snapshot transcript hash CH || SH || EE || SF
                     --  and use it for both:
                     --    * expected client Finished verify_data (via c_hs)
                     --    * application traffic secrets (via Master_Secret)
                     declare
                        Th_After_SF : Tls_Core.Sha256.Digest;

                        Empty_Hash : Tls_Core.Sha256.Digest;
                        Empty_In   : constant Octet_Array (1 .. 0) :=
                          (others => 0);
                        Derived_2_Sec : Tls_Core.Key_Schedule.Secret;
                        Master_Secret : Tls_Core.Key_Schedule.Secret;
                        Zero_Secret : constant Tls_Core.Key_Schedule.Secret :=
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
                        Tls_Core.Transcript.Snapshot
                          (D.Hash_Ctx, Th_After_SF);

                        --  Derived_2 = Derive-Secret(Hs_Secret, "derived", "")
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
                        --  Save Master_Secret so the Awaiting_Cf
                        --  branch (below) can derive
                        --  resumption_master_secret (RFC 8446 §7.1)
                        --  once the client Finished is appended to
                        --  the transcript.
                        D.Master_Sec := Master_Secret;
                        D.Master_Set := True;

                        --  Expected client Finished body — HMAC of
                        --  c_hs_finished_key over Th_After_SF.
                        Build_Finished_Body
                          (D.C_Hs_Sec, Th_After_SF, D.Expected_Cf);
                     end;
                  end;
               end;

               D.Cur_State := Awaiting_Cf;
            end;

         when Awaiting_Cf =>
            --  Read encrypted Finished record from In_Bytes.
            declare
               Pt_Buf : Octet_Array (1 .. 1024) := (others => 0);
               Pt_Last : Natural;
               Inner_Type : Octet;
               OK : Boolean;
            begin
               Tls_Core.Aead_Channel.Receive
                 (D.Hs_In_Dir, In_Bytes,
                  Pt_Buf, Pt_Last, Inner_Type, OK);
               if not OK
                 or else Inner_Type /=
                           Tls_Core.Aead_Channel.Inner_Type_Handshake
                 or else Pt_Last /= 4 + 32
                 or else Pt_Buf (1) /= Hs_Type_Finished
               then
                  D.Cur_State := Failed;
                  return;
               end if;
               --  Constant-time compare of received verify_data
               --  against the expected value computed at SF send time.
               declare
                  Diff : Octet := 0;
               begin
                  for I in 1 .. 32 loop
                     Diff := Diff or (Pt_Buf (4 + I) xor D.Expected_Cf (I));
                  end loop;
                  if Diff /= 0 then
                     D.Cur_State := Failed;
                     return;
                  end if;
               end;
               Tls_Core.Transcript.Append (D.Hash_Ctx, Pt_Buf (1 .. Pt_Last));

               --  Derive resumption_master_secret per RFC 8446 §7.1:
               --    Derive-Secret(Master_Secret, "res master", CH..CF)
               --  Server side: Master_Sec was saved in the
               --  Awaiting_CH branch when App_C_Ap / App_S_Ap were
               --  derived; the transcript now spans CH..CF (we just
               --  appended CF).
               if D.Master_Set then
                  declare
                     Th_After_Cf : Tls_Core.Sha256.Digest;
                  begin
                     Tls_Core.Transcript.Snapshot
                       (D.Hash_Ctx, Th_After_Cf);
                     Tls_Core.Session_Ticket
                       .Derive_Resumption_Master_Secret_Sha256
                         (Master_Secret     => D.Master_Sec,
                          Transcript_Hash   => Th_After_Cf,
                          Resumption_Secret => D.Res_Master_Sec);
                     D.Res_Master_Set := True;
                  end;
               end if;

               D.Cur_State := Done;
            end;

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
                 (D.PSK,
                  Ch_Hs (1 .. 4 + T_Last),
                  Binder);
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
   --  Build_Plaintext_Alert wraps an Alert{level, description} pair in
   --  a 7-byte TLSPlaintext record (0x15 || 0x0303 || 0x0002 || level
   --  || description). Used before any handshake keys are derived
   --  (§5.1 first record, e.g. server rejects ClientHello).
   --
   --  Build_Encrypted_Alert wraps the same Alert pair in a TLSCiphertext
   --  under the supplied direction. Used post-handshake when keys
   --  exist; the TLSInnerPlaintext content-type byte is 0x15 (Alert).
   ---------------------------------------------------------------------

   procedure Build_Plaintext_Alert
     (Level       : Octet;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   is
   begin
      Out_Buf := (others => 0);
      Out_Buf (1) := Rec_Type_Alert;
      Out_Buf (2) := 16#03#;
      Out_Buf (3) := 16#03#;
      Out_Buf (4) := 16#00#;
      Out_Buf (5) := 16#02#;
      Out_Buf (6) := Level;
      Out_Buf (7) := Description;
      Out_Last := 7;
   end Build_Plaintext_Alert;

   procedure Build_Encrypted_Alert
     (Dir         : in out Tls_Core.Aead_Channel.Direction;
      Level       : Octet;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   is
      Body_Bytes : Tls_Core.Alert.Alert_Bytes;
   begin
      Tls_Core.Alert.Encode
        (Tls_Core.Alert.Alert'(Level => Level, Description => Description),
         Body_Bytes);
      Tls_Core.Aead_Channel.Send
        (Dir,
         Body_Bytes,
         Tls_Core.Aead_Channel.Inner_Type_Alert,
         Out_Buf, Out_Last);
   end Build_Encrypted_Alert;

   ---------------------------------------------------------------------
   --  Ensure_App_Out_Dir — always-init D.App_Out_Dir to a fresh Seq=0
   --  direction under the current application traffic secret. Resets
   --  on every call to avoid the post-call freshness obligation a
   --  lazy-init variant cannot discharge — a simpler contract for a
   --  performance-irrelevant alert path.
   ---------------------------------------------------------------------

   procedure Ensure_App_Out_Dir (D : in out Driver)
   with
     Pre =>
       D.App_Set
       and then (D.Suite = Tls_Core.Suites.Chacha20_Poly1305_Sha256
                 or else D.Suite = Tls_Core.Suites.Aes_128_Gcm_Sha256),
     Post =>
       D.App_Out_Set
       and then D.Suite = D.Suite'Old
       and then D.App_Out_Dir.Suite = D.Suite
       and then (case D.App_Out_Dir.Suite is
                   when Tls_Core.Suites.Chacha20_Poly1305_Sha256 =>
                     Tls_Core.Channel.Stream_Seq (D.App_Out_Dir.Cha) = 0,
                   when Tls_Core.Suites.Aes_128_Gcm_Sha256 =>
                     Tls_Core.Record_Layer.Seq_Of (D.App_Out_Dir.Aes128.Stream)
                       = 0,
                   when Tls_Core.Suites.Aes_256_Gcm_Sha384 => True);
   procedure Ensure_App_Out_Dir (D : in out Driver) is
   begin
      case D.My_Role is
         when Server =>
            Tls_Core.Aead_Channel.Init_Sha256
              (D.App_Out_Dir, D.Suite, D.App_S_Ap);
         when Client =>
            Tls_Core.Aead_Channel.Init_Sha256
              (D.App_Out_Dir, D.Suite, D.App_C_Ap);
      end case;
      D.App_Out_Set := True;
   end Ensure_App_Out_Dir;

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
   begin
      --  Compute the resumption-PSK on the spot.
      Tls_Core.Session_Ticket.Derive_Psk_From_Ticket_Sha256
        (Resumption_Secret => Slot.Resumption_Secret,
         Ticket_Nonce      =>
           Slot.Ticket_Nonce (1 .. Slot.Ticket_Nonce_Len),
         Psk               => Derived_Psk);

      --  Initialise as a regular PSK client (the existing PSK_KE
      --  path drives the handshake; once the parallel C7 mode-3
      --  / psk_dhe_ke track lands, this entry point becomes the
      --  canonical resumption initialiser).
      D.My_Role := Client;
      D.Cur_State := Idle;
      Tls_Core.Transcript.Init (D.Hash_Ctx);
      D.PSK := Derived_Psk;
      D.Identity := (others => 0);
      D.Identity_Len := Slot.Ticket_Len;
      D.Identity (1 .. Slot.Ticket_Len) :=
        Slot.Ticket (1 .. Slot.Ticket_Len);
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
   end Init_Psk_Resumption_Client;

end Tls_Core.Tls13_Driver;
