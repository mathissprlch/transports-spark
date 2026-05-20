--  Tls_Core.Traffic_Keys — derive AEAD key + write_iv from a
--  TLS 1.3 traffic secret per RFC 8446 §7.3.
--
--      [sender]_write_key  = HKDF-Expand-Label(secret, "key", "", key_length)
--      [sender]_write_iv   = HKDF-Expand-Label(secret, "iv",  "", iv_length)
--
--  For TLS_CHACHA20_POLY1305_SHA256 the key is 32 bytes and the
--  IV is 12 bytes.
--
--  miTLS reference: src/tls/MiTLS.KS.fst — `derive_keys` does the
--  same two HKDF calls to project a traffic secret into (key, IV).

with Tls_Core.Key_Schedule;
with Tls_Core.Record_Layer;

package Tls_Core.Traffic_Keys
  with SPARK_Mode
is

   subtype Aead_Key is Octet_Array (1 .. 32);
   subtype Aead_Iv is Tls_Core.Record_Layer.IV_Array;

   --  Compute (write_key, write_iv) for a single direction from
   --  the corresponding traffic secret. RFC 8446 §7.3 derivation
   --  is exercised via end-to-end RFC 8448 vectors at the channel
   --  level; no functional Post is asserted here.
   procedure Derive
     (Secret_In : Tls_Core.Key_Schedule.Secret;
      Out_Key   : out Aead_Key;
      Out_IV    : out Aead_Iv);

end Tls_Core.Traffic_Keys;
