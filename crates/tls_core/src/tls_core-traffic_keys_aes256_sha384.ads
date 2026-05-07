--  Tls_Core.Traffic_Keys_Aes256_Sha384 — derive (write_key, write_iv)
--  for TLS_AES_256_GCM_SHA384 (32-byte key, 12-byte IV, SHA-384 HKDF).

with Tls_Core.Key_Schedule_Sha384;
with Tls_Core.Record_Layer;

package Tls_Core.Traffic_Keys_Aes256_Sha384
with SPARK_Mode
is

   subtype Aead_Key is Octet_Array (1 .. 32);
   subtype Aead_Iv  is Tls_Core.Record_Layer.IV_Array;

   --  RFC 8446 §7.3 traffic-key derivation; functionally checked
   --  via end-to-end RFC 8448 vectors at the channel level.
   procedure Derive
     (Secret_In : Tls_Core.Key_Schedule_Sha384.Secret;
      Out_Key   : out Aead_Key;
      Out_IV    : out Aead_Iv);

end Tls_Core.Traffic_Keys_Aes256_Sha384;
