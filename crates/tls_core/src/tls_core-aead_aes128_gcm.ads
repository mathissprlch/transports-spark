--  Tls_Core.Aead_Aes128_Gcm — AES-128-GCM AEAD (NIST SP 800-38D /
--  RFC 5288). Cipher suite TLS_AES_128_GCM_SHA256 (RFC 8446 §B.4).
--
--  AEAD_AES_128_GCM in TLS 1.3 uses a 12-byte nonce. Construction:
--
--    H        = AES-128(K, 0^128)
--    J0       = nonce ‖ 0x00000001
--    counter  = J0
--    counter[15..16] = INC32(counter[15..16])
--    Ciphertext = AES-CTR(K, counter, plaintext)
--    Tag      = GHASH(H, AAD ‖ pad ‖ Ciphertext ‖ pad ‖
--                       u64_BE(|AAD|·8) ‖ u64_BE(|Ciphertext|·8))
--               XOR AES-128(K, J0)
--
--  Same Seal/Open shape as Tls_Core.Aead_Chacha20_Poly1305; both
--  plug into the generic Tls_Core.Record_Layer.Aead.

with Tls_Core.Aes128;

package Tls_Core.Aead_Aes128_Gcm
with SPARK_Mode
is

   subtype Key_Array   is Tls_Core.Aes128.Key_Array;
   subtype Nonce_Array is Octet_Array (1 .. 12);
   subtype Tag_Array   is Octet_Array (1 .. 16);

   --  Spec functions for the platinum pinning pattern.
   function Spec_Seal_Ct
     (Key : Key_Array; Nonce : Nonce_Array;
      AAD, Plaintext : Octet_Array)
     return Octet_Array
   with Ghost,
        Post => Spec_Seal_Ct'Result'Length = Plaintext'Length;

   function Spec_Seal_Tag
     (Key : Key_Array; Nonce : Nonce_Array;
      AAD, Plaintext : Octet_Array)
     return Tag_Array
   with Ghost;

   function Spec_Open_OK
     (Key : Key_Array; Nonce : Nonce_Array;
      AAD, Ciphertext : Octet_Array; Tag : Tag_Array)
     return Boolean
   with Ghost;

   procedure Seal
     (Key        : Key_Array;
      Nonce      : Nonce_Array;
      AAD        : Octet_Array;
      Plaintext  : Octet_Array;
      Ciphertext : out Octet_Array;
      Tag        : out Tag_Array)
   with
     Pre =>
       Ciphertext'Length = Plaintext'Length
       and then AAD'Length <= 16640
       and then Plaintext'Length <= 16640
       and then AAD'Last < Integer'Last - 16640
       and then Plaintext'Last < Integer'Last - 16640
       and then Ciphertext'Last < Integer'Last - 16640,
     Post =>
       Ciphertext = Spec_Seal_Ct (Key, Nonce, AAD, Plaintext)
       and then Tag = Spec_Seal_Tag (Key, Nonce, AAD, Plaintext);

   procedure Open
     (Key        : Key_Array;
      Nonce      : Nonce_Array;
      AAD        : Octet_Array;
      Ciphertext : Octet_Array;
      Tag        : Tag_Array;
      Plaintext  : out Octet_Array;
      OK         : out Boolean)
   with
     Pre =>
       Plaintext'Length = Ciphertext'Length
       and then AAD'Length <= 16640
       and then Ciphertext'Length <= 16640
       and then AAD'Last < Integer'Last - 16640
       and then Ciphertext'Last < Integer'Last - 16640
       and then Plaintext'Last < Integer'Last - 16640,
     Post => OK = Spec_Open_OK (Key, Nonce, AAD, Ciphertext, Tag);

end Tls_Core.Aead_Aes128_Gcm;
