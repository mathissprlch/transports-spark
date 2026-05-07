--  Tls_Core.Aead_Channel — variant-record record-layer endpoint
--  that dispatches Send / Receive over the three TLS 1.3
--  cipher-suite-specific Channel modules:
--
--      Chacha20_Poly1305_Sha256 → Tls_Core.Channel
--      Aes_128_Gcm_Sha256       → Tls_Core.Channel_Aes128
--      Aes_256_Gcm_Sha384       → Tls_Core.Channel_Aes256
--
--  Replaces the single hardcoded Tls_Core.Channel reference in
--  Tls_Core.Tls13_Driver so the driver can negotiate any of the
--  three §B.4 production cipher suites at handshake time and route
--  the rest of the record-layer encryption through the chosen
--  AEAD.
--
--  Source: RFC 8446 §B.4 (the cipher-suite registry the driver
--  picks from), §5.2 (record-layer envelope — every Channel module
--  emits the same TLSCiphertext shape modulo AEAD primitive).
--
--  This module owns ZERO new crypto: it is plumbing-only. All
--  three underlying Channel modules are already audit-clean.

with Interfaces;
with Tls_Core.Channel;
with Tls_Core.Channel_Aes128;
with Tls_Core.Channel_Aes256;
with Tls_Core.Key_Schedule;
with Tls_Core.Key_Schedule_Sha384;
with Tls_Core.Record_Layer;
with Tls_Core.Suites;

package Tls_Core.Aead_Channel
with SPARK_Mode
is

   use type Interfaces.Unsigned_64;

   subtype Cipher_Suite_Id is Tls_Core.Suites.Cipher_Suite_Id;
   use all type Tls_Core.Suites.Cipher_Suite_Id;

   --  Inner-content-type bytes per RFC 8446 §5.2 / IANA registry.
   --  The three underlying modules already declare these privately;
   --  re-exporting here so Tls13_Driver only ever names Aead_Channel.
   Inner_Type_Change_Cipher_Spec : constant Octet := 16#14#;
   Inner_Type_Alert              : constant Octet := 16#15#;
   Inner_Type_Handshake          : constant Octet := 16#16#;
   Inner_Type_Application_Data   : constant Octet := 16#17#;

   --  Per-direction state. The discriminant pins which of the
   --  three underlying Direction records is in play. Callers must
   --  Init_* before using Send / Receive.
   type Direction (Suite : Cipher_Suite_Id := Chacha20_Poly1305_Sha256)
     is record
      case Suite is
         when Chacha20_Poly1305_Sha256 =>
            Cha    : Tls_Core.Channel.Direction;
         when Aes_128_Gcm_Sha256 =>
            Aes128 : Tls_Core.Channel_Aes128.Direction;
         when Aes_256_Gcm_Sha384 =>
            Aes256 : Tls_Core.Channel_Aes256.Direction;
      end case;
   end record;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Initialise a Direction for a SHA-256-based
   --                      suite (Chacha20 or AES-128-GCM).
   --
   --  Standard:    RFC 8446 §7.3 (per-direction key/IV derivation)
   --  Spec mirror: miTLS src/tls/MiTLS.KS.fst : derive_keys
   --
   --  Functional:  D.Suite = Suite ∧ D.<inner>.Stream.Seq = 0
   --  Proven at:   gnatprove --level=2 (audit-clean) — body is
   --               case-dispatch only; the underlying Init bodies
   --               are already audit-clean.
   --------------------------------------------------------------------
   procedure Init_Sha256
     (D      : out Direction;
      Suite  : Cipher_Suite_Id;
      Secret : Tls_Core.Key_Schedule.Secret)
   with Pre =>
     (Suite = Chacha20_Poly1305_Sha256
      or else Suite = Aes_128_Gcm_Sha256)
     and then not D'Constrained,
     Post => D.Suite = Suite;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Initialise a Direction for the SHA-384-based
   --                      suite (AES-256-GCM-SHA384).
   --
   --  Standard:    RFC 8446 §7.3 (per-direction key/IV derivation)
   --  Spec mirror: miTLS src/tls/MiTLS.KS.fst : derive_keys
   --
   --  Functional:  D.Suite = Aes_256_Gcm_Sha384 ∧
   --               D.Aes256.Stream.Seq = 0
   --  Proven at:   gnatprove --level=2 (audit-clean) — body is
   --               case-dispatch only; the underlying Init body is
   --               already audit-clean.
   --------------------------------------------------------------------
   procedure Init_Sha384
     (D      : out Direction;
      Secret : Tls_Core.Key_Schedule_Sha384.Secret)
   with Pre  => not D'Constrained,
        Post => D.Suite = Aes_256_Gcm_Sha384;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Encrypt one record. Dispatches to the
   --                      Channel module pinned by D.Suite.
   --
   --  Standard:    RFC 8446 §5.2 (TLSCiphertext envelope).
   --  Spec mirror: miTLS src/tls/MiTLS.StAE.fst : encrypt
   --
   --  Functional:  Out_Buf (1 .. Out_Last) is a TLSCiphertext record
   --               whose AEAD primitive matches D.Suite.
   --  Proven at:   gnatprove --level=2 (audit-clean) — body is
   --               case-dispatch only.
   --------------------------------------------------------------------
   procedure Send
     (D          : in out Direction;
      Plaintext  : Octet_Array;
      Inner_Type : Octet;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural)
   with Pre =>
     Plaintext'Length in 0 .. 16384
     and then Out_Buf'Length >= 5 + Plaintext'Length + 1 + 16
     and then Out_Buf'First = 1
     and then (case D.Suite is
                 when Chacha20_Poly1305_Sha256 => True,
                 when Aes_128_Gcm_Sha256 =>
                   Tls_Core.Record_Layer.Seq_Of (D.Aes128.Stream)
                     < Tls_Core.Record_Layer.Seq_Number'Last,
                 when Aes_256_Gcm_Sha384 =>
                   Tls_Core.Record_Layer.Seq_Of (D.Aes256.Stream)
                     < Tls_Core.Record_Layer.Seq_Number'Last);

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Decrypt one record. Dispatches on D.Suite.
   --
   --  Standard:    RFC 8446 §5.2 (TLSCiphertext envelope).
   --  Spec mirror: miTLS src/tls/MiTLS.StAE.fst : decrypt
   --
   --  Functional:  When OK = True, Out_Buf (1 .. Out_Last) is the
   --               TLSInnerPlaintext content stripped of its trailing
   --               type byte (returned as Inner_Type).
   --  Proven at:   gnatprove --level=2 (audit-clean) — body is
   --               case-dispatch only.
   --------------------------------------------------------------------
   procedure Receive
     (D          : in out Direction;
      In_Buf     : Octet_Array;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural;
      Inner_Type : out Octet;
      OK         : out Boolean)
   with Pre =>
     In_Buf'Length >= 5 + 1 + 16
     and then In_Buf'First = 1
     and then Out_Buf'First = 1
     and then Out_Buf'Length + 5 + 1 + 16 >= In_Buf'Length
     and then Out_Buf'Length >= In_Buf'Length
     and then (case D.Suite is
                 when Chacha20_Poly1305_Sha256 => True,
                 when Aes_128_Gcm_Sha256 =>
                   Tls_Core.Record_Layer.Seq_Of (D.Aes128.Stream)
                     < Tls_Core.Record_Layer.Seq_Number'Last,
                 when Aes_256_Gcm_Sha384 =>
                   Tls_Core.Record_Layer.Seq_Of (D.Aes256.Stream)
                     < Tls_Core.Record_Layer.Seq_Number'Last);

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Rotate a SHA-256-suite Direction in place
   --                      with a freshly-derived traffic secret.
   --
   --  Standard:    RFC 8446 §7.2 (next traffic secret) + §5.3
   --               (sequence number reset on key change). The
   --               §4.6.3 KeyUpdate handler calls this after
   --               sending / receiving a KeyUpdate message.
   --  Spec mirror: miTLS src/tls/MiTLS.KS.fst : ks_client_13_kbu
   --
   --  Functional:  D.Suite is preserved; the new (key, iv) pair is
   --               re-derived from New_Secret per RFC 8446 §7.3
   --               (`HKDF-Expand-Label("key" / "iv", ...)`); the
   --               record-layer Stream's Seq counter is reset to 0
   --               so the very first record after rotation reuses
   --               nonce_0 — which is fresh under the new IV.
   --  Proven at:   gnatprove --level=2 (audit-clean) — body is
   --               a Tls_Core.Channel.Init / Tls_Core.Channel_Aes128.Init
   --               case-dispatch.
   --
   --  Pre rules out the SHA-384 variant: the Secret type for SHA-384
   --  suites is 48 bytes — call Rotate_Sha384 for that.
   --------------------------------------------------------------------
   procedure Rotate_Sha256
     (D          : in out Direction;
      New_Secret : Tls_Core.Key_Schedule.Secret)
   with
     Pre  =>
       (D.Suite = Chacha20_Poly1305_Sha256
          or else D.Suite = Aes_128_Gcm_Sha256),
     Post =>
       D.Suite = D.Suite'Old;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Rotate a SHA-384-suite Direction in place.
   --
   --  Standard:    RFC 8446 §7.2 + §5.3 — see Rotate_Sha256.
   --
   --  Functional:  D.Suite preserved at Aes_256_Gcm_Sha384;
   --               (key, iv) re-derived from New_Secret;
   --               Stream.Seq reset to 0.
   --  Proven at:   gnatprove --level=2 (audit-clean) — body is
   --               a Tls_Core.Channel_Aes256.Init call.
   --------------------------------------------------------------------
   procedure Rotate_Sha384
     (D          : in out Direction;
      New_Secret : Tls_Core.Key_Schedule_Sha384.Secret)
   with
     Pre  => D.Suite = Aes_256_Gcm_Sha384,
     Post => D.Suite = D.Suite'Old;

   --------------------------------------------------------------------
   --  Cross-suite Seq accessor — needed by Tls13_Driver.Send_Key_Update
   --  which must gate its Send call on the underlying Stream.Seq.
   --
   --  Returns the Stream.Seq of the active variant. The Chacha variant
   --  exposes the seq counter via Tls_Core.Channel.Seq_Of (added below
   --  for parity); the AES variants expose the .Aes128 / .Aes256
   --  Stream component publicly so Record_Layer.Seq_Of works directly.
   --------------------------------------------------------------------
   function Seq_Of (D : Direction) return Tls_Core.Record_Layer.Seq_Number
   is (case D.Suite is
         when Chacha20_Poly1305_Sha256 =>
           Tls_Core.Channel.Seq_Of (D.Cha),
         when Aes_128_Gcm_Sha256 =>
           Tls_Core.Record_Layer.Seq_Of (D.Aes128.Stream),
         when Aes_256_Gcm_Sha384 =>
           Tls_Core.Record_Layer.Seq_Of (D.Aes256.Stream))
   with Ghost;

end Tls_Core.Aead_Channel;
