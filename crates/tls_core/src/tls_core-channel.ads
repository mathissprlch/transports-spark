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

with Tls_Core.Key_Schedule;
with Tls_Core.Record_Layer;
with Tls_Core.Traffic_Keys;

package Tls_Core.Channel
with SPARK_Mode => Off
is

   --  Per-direction state: AEAD key+IV plus the record-layer Stream.
   type Direction is private;

   --  Initialise a Direction from a traffic secret. Derives
   --  (write_key, write_iv) per RFC 8446 §7.3 and resets Seq=0.
   procedure Init
     (D      : out Direction;
      Secret : Tls_Core.Key_Schedule.Secret);

   --  Encrypt one record. Out_Buf receives the wire bytes
   --  (5-byte TLSCiphertext header + 16 bytes of AEAD tag +
   --   Plaintext'Length bytes ciphertext).
   procedure Send
     (D         : in out Direction;
      Plaintext : Octet_Array;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   with Pre =>
       Plaintext'Length in 1 .. 16384
       and then Out_Buf'Length >= 5 + Plaintext'Length + 16
       and then Out_Buf'First = 1;

   --  Decrypt one record from the head of In_Buf. Returns the
   --  plaintext in Out_Buf. Sets OK := False on AEAD-tag mismatch
   --  or malformed wire bytes.
   procedure Receive
     (D        : in out Direction;
      In_Buf   : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural;
      OK       : out Boolean)
   with Pre =>
       In_Buf'Length >= 5 + 16
       and then Out_Buf'Length + 5 + 16 >= In_Buf'Length
       and then Out_Buf'First = 1;

private

   subtype Key_Type is Tls_Core.Traffic_Keys.Aead_Key;

   type Direction is record
      Stream : Tls_Core.Record_Layer.Stream;
      Key    : Key_Type := (others => 0);
   end record;

end Tls_Core.Channel;
