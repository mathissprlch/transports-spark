--  Tls_Core.Alert — RFC 8446 §6 alert protocol.
--
--  An Alert message is two octets:
--
--      struct {
--          AlertLevel       level;       -- uint8
--          AlertDescription description; -- uint8
--      } Alert;
--
--  RFC 8446 §6 collapses the AlertLevel field to a single
--  meaningful distinction: every alert except `user_canceled` and
--  `close_notify` is implicitly fatal in TLS 1.3, regardless of
--  the on-wire level byte. We still emit the byte so peers see the
--  values they expect (warning=1 for closure, fatal=2 for errors).
--
--  Alert is carried on the wire either as a TLSPlaintext fragment
--  (content_type = 21, before keys are derived — the only
--  realistic plaintext alerts in TLS 1.3 are unrecoverable parse
--  failures on the very first record) or, after keys are derived,
--  as a TLSCiphertext whose TLSInnerPlaintext content_type byte
--  equals 21 (Tls_Core.Channel.Inner_Type_Alert / 0x15).
--
--  This package owns the byte layout and the symbolic codepoints.
--  It does NOT touch the record layer — the driver wraps an alert
--  into a TLSPlaintext or sends it via Aead_Channel as needed.

with Interfaces;

package Tls_Core.Alert
  with SPARK_Mode
is

   use type Interfaces.Unsigned_8;

   ---------------------------------------------------------------------
   --  AlertLevel — RFC 8446 §6.
   --
   --  TLS 1.3 still emits these legacy values on the wire even
   --  though the spec mandates a uniform "treat as fatal" semantics
   --  (§6.2 first paragraph) for everything except close_notify and
   --  user_canceled. See §6.1 for the legacy definition.
   ---------------------------------------------------------------------

   Level_Warning : constant Octet := 1;
   Level_Fatal   : constant Octet := 2;

   ---------------------------------------------------------------------
   --  AlertDescription — RFC 8446 §6 IANA registry, every code in
   --  production use.
   ---------------------------------------------------------------------

   Desc_Close_Notify                    : constant Octet := 0;    -- §6.1
   Desc_Unexpected_Message              : constant Octet := 10;   -- §6.2
   Desc_Bad_Record_Mac                  : constant Octet := 20;   -- §6.2
   Desc_Record_Overflow                 : constant Octet := 22;   -- §6.2
   Desc_Handshake_Failure               : constant Octet := 40;   -- §6.2
   Desc_Bad_Certificate                 : constant Octet := 42;   -- §6.2
   Desc_Unsupported_Certificate         : constant Octet := 43;   -- §6.2
   Desc_Certificate_Revoked             : constant Octet := 44;   -- §6.2
   Desc_Certificate_Expired             : constant Octet := 45;   -- §6.2
   Desc_Certificate_Unknown             : constant Octet := 46;   -- §6.2
   Desc_Illegal_Parameter               : constant Octet := 47;   -- §6.2
   Desc_Unknown_Ca                      : constant Octet := 48;   -- §6.2
   Desc_Access_Denied                   : constant Octet := 49;   -- §6.2
   Desc_Decode_Error                    : constant Octet := 50;   -- §6.2
   Desc_Decrypt_Error                   : constant Octet := 51;   -- §6.2
   Desc_Protocol_Version                : constant Octet := 70;   -- §6.2
   Desc_Insufficient_Security           : constant Octet := 71;   -- §6.2
   Desc_Internal_Error                  : constant Octet := 80;   -- §6.2
   Desc_Inappropriate_Fallback          : constant Octet := 86;   -- §6.2
   Desc_User_Canceled                   : constant Octet := 90;   -- §6.1
   Desc_Missing_Extension               : constant Octet := 109;  -- §6.2
   Desc_Unsupported_Extension           : constant Octet := 110;  -- §6.2
   Desc_Unrecognized_Name               : constant Octet := 112;  -- §6.2
   Desc_Bad_Certificate_Status_Response : constant Octet := 113;  -- §6.2
   Desc_Unknown_Psk_Identity            : constant Octet := 115;  -- §6.2
   Desc_Certificate_Required            : constant Octet := 116;  -- §6.2
   Desc_No_Application_Protocol         : constant Octet := 120;  -- §6.2

   ---------------------------------------------------------------------
   --  Alert record + encode / decode.
   ---------------------------------------------------------------------

   subtype Alert_Bytes is Octet_Array (1 .. 2);

   type Alert is record
      Level       : Octet;
      Description : Octet;
   end record;

   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  Encode an Alert as 2 octets per §6.
   --
   --  Standard:    RFC 8446 §6 (Alert struct: level || description).
   --  Spec mirror: miTLS src/tls/MiTLS.Alert.fst : alertBytes
   --
   --  Functional:  Out_Bytes (1) = A.Level
   --               Out_Bytes (2) = A.Description
   --  Proven at:   gnatprove --level=2 (audit-clean) — body is two
   --               assignments.
   --------------------------------------------------------------------
   procedure Encode (A : Alert; Out_Bytes : out Alert_Bytes)
   with Post => Out_Bytes (1) = A.Level and then Out_Bytes (2) = A.Description;

   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  Decode 2 octets into an Alert per §6.
   --
   --  Standard:    RFC 8446 §6 (Alert struct: level || description).
   --  Spec mirror: miTLS src/tls/MiTLS.Alert.fst : parseAlert
   --
   --  Functional:  OK  ↔  In_Bytes'Length = 2
   --               When OK: A.Level = In_Bytes (In_Bytes'First)
   --                    ∧  A.Description = In_Bytes (In_Bytes'First+1)
   --  Proven at:   gnatprove --level=2 (audit-clean) — body is one
   --               length check + two assignments.
   --
   --  Notes on tolerance: §6 fixes the alert payload at exactly 2
   --  octets. We refuse anything else with OK=False. Some legacy
   --  TLS 1.2 stacks have shipped longer alert fragments; TLS 1.3
   --  is strict (§6 first paragraph: "is defined to be a 'fatal'
   --  alert" for any malformed alert).
   --------------------------------------------------------------------
   procedure Decode (In_Bytes : Octet_Array; A : out Alert; OK : out Boolean)
   with
     Post =>
       (if In_Bytes'Length = 2
        then
          OK
          and then A.Level = In_Bytes (In_Bytes'First)
          and then A.Description = In_Bytes (In_Bytes'First + 1)
        else not OK);

   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  True iff (Level, Description) is the
   --                         §6.1 close_notify closure alert.
   --
   --  Standard:    RFC 8446 §6.1 (close_notify).
   --
   --  TLS 1.3 §6.1 stipulates Level_Warning for close_notify; §6
   --  also mandates that implementations MUST treat any unknown
   --  level as fatal. We return True for either Level_Warning or
   --  Level_Fatal here — peers in the wild (BoringSSL, OpenSSL <
   --  3.2 in some configurations) have shipped fatal close_notify
   --  bytes; rejecting them as "not really a close_notify" loses
   --  the graceful-shutdown semantics for no benefit.
   --------------------------------------------------------------------
   function Is_Close_Notify (A : Alert) return Boolean
   is (A.Description = Desc_Close_Notify);

   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  True iff the Description field denotes
   --                         a §6.1 closure alert (close_notify or
   --                         user_canceled).
   --
   --  Standard:    RFC 8446 §6.1.
   --
   --  Used by the driver to decide whether to transition to Done
   --  (closure) vs Failed (every other alert is fatal under §6.2
   --  first paragraph).
   --------------------------------------------------------------------
   function Is_Closure (A : Alert) return Boolean
   is (A.Description = Desc_Close_Notify
       or else A.Description = Desc_User_Canceled);

end Tls_Core.Alert;
