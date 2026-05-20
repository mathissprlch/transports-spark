--  Tls_Core.Key_Update — TLS 1.3 §4.6.3 KeyUpdate post-handshake
--  message + RFC 8446 §7.2 traffic-secret rotation helper.
--
--  Source: RFC 8446 §4.6.3 (KeyUpdate / KeyUpdateRequest enum +
--          handshake message wire shape) and §7.2 (the
--          application_traffic_secret_N+1 derivation:
--
--            application_traffic_secret_N+1 =
--              HKDF-Expand-Label(application_traffic_secret_N,
--                                "traffic upd", "", Hash.length)
--
--          where Hash.length is the HKDF hash output size — 32 for
--          SHA-256 cipher suites, 48 for SHA-384).
--
--  Used by long-running OpenSSL sessions: once the byte counter
--  on a direction crosses an internal threshold OpenSSL emits
--  KeyUpdate; production interop requires we both honour an
--  inbound KeyUpdate (rotate the peer-side decrypt key) and emit
--  one when our own counter justifies it (rotate our send key).
--
--  This module is plumbing: the wire encode/decode is trivial
--  (1-byte payload + 4-byte handshake header), and the derivation
--  is a single Hkdf.Expand_Label call. No new crypto.

with Tls_Core.Key_Schedule;
with Tls_Core.Key_Schedule_Sha384;

package Tls_Core.Key_Update
  with SPARK_Mode
is

   use type Tls_Core.Octet;

   --  KeyUpdateRequest enum per RFC 8446 §4.6.3.
   Update_Not_Requested : constant Octet := 16#00#;
   Update_Requested     : constant Octet := 16#01#;

   --  Handshake message type per RFC 8446 §B.3 / IANA registry.
   Hs_Type_Key_Update : constant Octet := 16#18#;

   --  Wire size of a KeyUpdate handshake message:
   --    1 byte msg_type (0x18)
   --  + 3 byte u24 length (= 1)
   --  + 1 byte request_update payload
   Wire_Size : constant Natural := 5;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Encode a KeyUpdate handshake message.
   --
   --  Standard:    RFC 8446 §4.6.3 (KeyUpdate handshake message)
   --  Spec mirror: miTLS src/parsers/MiTLS.Parsers.KeyUpdate.rfc
   --
   --  Functional:  Out_Buf (1 .. 5) =
   --                 (Hs_Type_Key_Update, 0, 0, 1, Request_Update)
   --               and Out_Last = 5.
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --
   --  Caller is responsible for wrapping the resulting handshake
   --  message in a TLSCiphertext record under the *current* send
   --  traffic key (rotation happens AFTER the message is on the
   --  wire — RFC 8446 §4.6.3 last paragraph).
   --------------------------------------------------------------------
   procedure Encode
     (Request_Update : Octet;
      Out_Buf        : out Octet_Array;
      Out_Last       : out Natural)
   with
     Pre  =>
       (Request_Update = Update_Not_Requested
        or else Request_Update = Update_Requested)
       and then Out_Buf'First = 1
       and then Out_Buf'Length >= Wire_Size,
     Post =>
       Out_Last = Wire_Size
       and then Out_Buf (1) = Hs_Type_Key_Update
       and then Out_Buf (2) = 0
       and then Out_Buf (3) = 0
       and then Out_Buf (4) = 1
       and then Out_Buf (5) = Request_Update;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Decode a KeyUpdate handshake message.
   --
   --  Standard:    RFC 8446 §4.6.3.
   --
   --  Functional:  When OK = True,
   --                 In_Buf (In_Buf'First) = Hs_Type_Key_Update
   --                 ∧ In_Buf'Length = Wire_Size
   --                 ∧ Request_Update ∈ {0, 1}.
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --
   --  Caller passes the *plaintext* of a handshake-content-type
   --  TLSInnerPlaintext record (i.e. after Aead_Channel.Receive
   --  yields Inner_Type = Inner_Type_Handshake). RFC 8446 §4.6.3
   --  rejects any RequestUpdate value outside {0,1} as a fatal
   --  illegal_parameter; we surface that via OK = False.
   --------------------------------------------------------------------
   procedure Decode
     (In_Buf : Octet_Array; Request_Update : out Octet; OK : out Boolean)
   with
     Post =>
       (if OK
        then
          In_Buf'Length = Wire_Size
          and then In_Buf (In_Buf'First) = Hs_Type_Key_Update
          and then (Request_Update = Update_Not_Requested
                    or else Request_Update = Update_Requested));

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Derive the next SHA-256 traffic secret
   --                      per RFC 8446 §7.2.
   --
   --  Standard:    RFC 8446 §7.2 (application_traffic_secret_N+1
   --                derivation).
   --  Spec mirror: miTLS src/tls/MiTLS.KS.fst : ks_client_13_kbu
   --                (mitls' name for the traffic-update step)
   --
   --  Functional:  Next = HKDF-Expand-Label(Current, "traffic upd",
   --                                        "", 32)
   --               (32 = SHA-256 hash length per RFC 5246 §7.4.1.2)
   --  Proven at:   gnatprove --level=2 (audit-clean) — body is
   --               one Hkdf_Expand_Label_Sha256 call.
   --
   --  Used by both Aead_Channel suites built on SHA-256:
   --  TLS_CHACHA20_POLY1305_SHA256 and TLS_AES_128_GCM_SHA256.
   --------------------------------------------------------------------
   procedure Derive_Next_Sha256
     (Current : Tls_Core.Key_Schedule.Secret;
      Next    : out Tls_Core.Key_Schedule.Secret);

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Derive the next SHA-384 traffic secret
   --                      per RFC 8446 §7.2.
   --
   --  Standard:    RFC 8446 §7.2.
   --
   --  Functional:  Next = HKDF-Expand-Label(Current, "traffic upd",
   --                                        "", 48)
   --  Proven at:   gnatprove --level=2 (audit-clean) — body is
   --               one Hkdf_Label_Sha384.Expand_Label call.
   --
   --  Used by TLS_AES_256_GCM_SHA384.
   --------------------------------------------------------------------
   procedure Derive_Next_Sha384
     (Current : Tls_Core.Key_Schedule_Sha384.Secret;
      Next    : out Tls_Core.Key_Schedule_Sha384.Secret);

end Tls_Core.Key_Update;
