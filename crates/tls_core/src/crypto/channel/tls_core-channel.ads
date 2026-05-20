--  Tls_Core.Channel — connected TLS 1.3 record-layer endpoint.
--
--  After Init_Sender / Init_Receiver with a traffic secret, Send
--  encrypts a plaintext as a single TLS 1.3 record (RFC 8446 §5.2:
--  TLSCiphertext envelope of opaque_type Application_Data, holding
--  the AEAD-protected fragment), and Receive consumes one record
--  and returns the plaintext.
--
--  The Stream sequence counter is bumped on every Send/Receive,
--  so per RFC §5.3 + Lemma_Bump_Fresh_Nonce no nonce is reused
--  inside a single Channel direction.
--
--  This is the upper-side TLS API analogous to miTLS' StAE layer:
--  the AEAD primitive's nonce-uniqueness premise is supplied by
--  Stream's monotonic sequence + the lemmas in Record_Layer.
--
--  No I/O. The Channel works in terms of Octet_Array buffers.
--  Wrapping it over a real Transport (TCP, in-memory) is one
--  small adapter layer.

with Interfaces;
with Tls_Core.Key_Schedule;
with Tls_Core.Record_Layer;
with Tls_Core.Traffic_Keys;

package Tls_Core.Channel
  with SPARK_Mode
is

   use type Interfaces.Unsigned_64;

   --  Per-direction state: AEAD key+IV plus the record-layer Stream.
   type Direction is private;

   function Stream_Seq (D : Direction) return Tls_Core.Record_Layer.Seq_Number
   with Ghost;
   --  Ghost accessor for the per-direction Stream sequence — used
   --  by callers' Posts to assert Seq=0 after initialisation while
   --  Direction stays private.

   --  Initialise a Direction from a traffic secret. Derives
   --  (write_key, write_iv) per RFC 8446 §7.3 and resets Seq=0.
   procedure Init (D : out Direction; Secret : Tls_Core.Key_Schedule.Secret)
   with Post => Stream_Seq (D) = 0;

   --  TLS 1.3 inner content types per RFC 8446 §5.2 / IANA registry.
   Inner_Type_Change_Cipher_Spec : constant Octet := 16#14#;
   Inner_Type_Alert              : constant Octet := 16#15#;
   Inner_Type_Handshake          : constant Octet := 16#16#;
   Inner_Type_Application_Data   : constant Octet := 16#17#;

   --  Encrypt one record. Out_Buf receives the wire bytes (5-byte
   --  TLSCiphertext header + ciphertext + 16-byte AEAD tag).
   --  Inner_Type goes into the TLSInnerPlaintext trailer per RFC 8446
   --  §5.2: the encrypted plaintext is `Plaintext || Inner_Type`,
   --  and the AAD-protected outer header always claims
   --  application_data (0x17).
   procedure Send
     (D          : in out Direction;
      Plaintext  : Octet_Array;
      Inner_Type : Octet;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural)
   with
     Pre =>
       Plaintext'Length in 0 .. 16384
       and then Out_Buf'Length >= 5 + Plaintext'Length + 1 + 16
       and then Out_Buf'First = 1;

   --  Backward-compat shim: defaults Inner_Type to application_data.
   procedure Send
     (D         : in out Direction;
      Plaintext : Octet_Array;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   with
     Pre =>
       Plaintext'Length in 1 .. 16384
       and then Out_Buf'Length >= 5 + Plaintext'Length + 1 + 16
       and then Out_Buf'First = 1;

   --  Decrypt one record. Inner_Type reports the content-type byte
   --  that was at the tail of the TLSInnerPlaintext (§5.2) — caller
   --  dispatches on app data / handshake / alert.
   procedure Receive
     (D          : in out Direction;
      In_Buf     : Octet_Array;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural;
      Inner_Type : out Octet;
      OK         : out Boolean)
   with
     Pre =>
       In_Buf'Length >= 5 + 1 + 16
       and then Out_Buf'Length + 5 + 1 + 16 >= In_Buf'Length
       and then Out_Buf'First = 1;

   --  Backward-compat shim that asserts inner content type =
   --  application_data (0x17) and discards the type out.
   procedure Receive
     (D        : in out Direction;
      In_Buf   : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural;
      OK       : out Boolean)
   with
     Pre =>
       In_Buf'Length >= 5 + 1 + 16
       and then Out_Buf'Length + 5 + 1 + 16 >= In_Buf'Length
       and then Out_Buf'First = 1;

   --  Public accessor for the per-direction Stream sequence counter.
   --  Used by Aead_Channel.Seq_Of so the variant-record dispatcher
   --  can expose a uniform Seq across all three suites without
   --  exposing the private Direction record. Ghost — for use in
   --  contracts only (matches Record_Layer.Seq_Of's ghost mode).
   function Seq_Of (D : Direction) return Tls_Core.Record_Layer.Seq_Number
   with Ghost;

private

   subtype Key_Type is Tls_Core.Traffic_Keys.Aead_Key;

   type Direction is record
      Stream : Tls_Core.Record_Layer.Stream;
      Key    : Key_Type := [others => 0];
   end record;

   function Stream_Seq (D : Direction) return Tls_Core.Record_Layer.Seq_Number
   is (Tls_Core.Record_Layer.Seq_Of (D.Stream));

end Tls_Core.Channel;
