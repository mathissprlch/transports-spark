--  Tls_Core.Traffic_Keys_Aes128 — derive (write_key, write_iv) for
--  TLS_AES_128_GCM_SHA256 (16-byte key, 12-byte IV, SHA-256 HKDF).
--
--  Same shape as Tls_Core.Traffic_Keys (which is hard-coded to a
--  32-byte AEAD key for ChaCha20-Poly1305).

with Tls_Core.Key_Schedule;
with Tls_Core.Record_Layer;

package Tls_Core.Traffic_Keys_Aes128
  with SPARK_Mode
is

   subtype Aead_Key is Octet_Array (1 .. 16);
   subtype Aead_Iv is Tls_Core.Record_Layer.IV_Array;

   --  RFC 8446 §7.3 traffic-key derivation; functionally checked
   --  via end-to-end RFC 8448 vectors at the channel level.
   procedure Derive
     (Secret_In : Tls_Core.Key_Schedule.Secret;
      Out_Key   : out Aead_Key;
      Out_IV    : out Aead_Iv);

end Tls_Core.Traffic_Keys_Aes128;
