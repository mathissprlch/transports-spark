--  Tls_Core.Channel_Aes128 — TLS 1.3 record-layer endpoint
--  specialised to TLS_AES_128_GCM_SHA256.
--
--  Same Send/Receive shape as Tls_Core.Channel (which is hardcoded
--  to ChaCha20-Poly1305). v0.5 cipher-suite negotiation needs
--  three parallel Channel_X packages, one per cipher suite the
--  driver may select. v0.6 task: variant-record dispatch so a
--  single Channel type can hold any of the three.

with Tls_Core.Aead_Aes128_Gcm;
with Tls_Core.Record_Layer;
with Tls_Core.Traffic_Keys_Aes128;
with Tls_Core.Key_Schedule;
with Interfaces;

package Tls_Core.Channel_Aes128
with SPARK_Mode
is

   use type Interfaces.Unsigned_64;

   subtype Key_Type is Tls_Core.Traffic_Keys_Aes128.Aead_Key;
   subtype Tag_Type is Tls_Core.Aead_Aes128_Gcm.Tag_Array;

   --  TLS 1.3 inner content types per RFC 8446 §5.2.
   Inner_Type_Change_Cipher_Spec : constant Octet := 16#14#;
   Inner_Type_Alert              : constant Octet := 16#15#;
   Inner_Type_Handshake          : constant Octet := 16#16#;
   Inner_Type_Application_Data   : constant Octet := 16#17#;

   type Direction is record
      Stream : Tls_Core.Record_Layer.Stream;
      Key    : Key_Type := (others => 0);
   end record;

   procedure Init
     (D      : out Direction;
      Secret : Tls_Core.Key_Schedule.Secret);

   --  Following miTLS' StAE pattern: every encrypt/decrypt call requires
   --  the per-stream sequence number to be below max (else nonce reuse).
   --  miTLS reference: src/tls/MiTLS.StAE.fst — `encrypt`/`decrypt` Pre.
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
     and then Tls_Core.Record_Layer.Seq_Of (D.Stream)
              < Tls_Core.Record_Layer.Seq_Number'Last;

   procedure Receive
     (D          : in out Direction;
      In_Buf     : Octet_Array;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural;
      Inner_Type : out Octet;
      OK         : out Boolean)
   with Pre =>
     In_Buf'Length >= 5
     and then In_Buf'First = 1
     and then Out_Buf'First = 1
     and then Out_Buf'Length >= In_Buf'Length
     and then Tls_Core.Record_Layer.Seq_Of (D.Stream)
              < Tls_Core.Record_Layer.Seq_Number'Last;

end Tls_Core.Channel_Aes128;
