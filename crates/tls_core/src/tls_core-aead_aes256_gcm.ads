--  Tls_Core.Aead_Aes256_Gcm — AES-256-GCM AEAD (NIST SP 800-38D /
--  RFC 5288). Cipher suite TLS_AES_256_GCM_SHA384 (RFC 8446 §B.4).
--
--  Same construction as AES-128-GCM (12-byte nonce, J0 = nonce||1):
--
--    H        = AES-256(K, 0^128)
--    J0       = nonce ‖ 0x00000001
--    Ciphertext = AES-CTR(K, INC32(J0), plaintext)
--    Tag      = GHASH(H, AAD‖pad‖CT‖pad‖u64_BE(|AAD|·8)‖u64_BE(|CT|·8))
--               XOR AES-256(K, J0)
--
--  Same Seal/Open shape as Tls_Core.Aead_Aes128_Gcm.

with Tls_Core.Aes256;

package Tls_Core.Aead_Aes256_Gcm
with SPARK_Mode
is

   subtype Key_Array   is Tls_Core.Aes256.Key_Array;
   subtype Nonce_Array is Octet_Array (1 .. 12);
   subtype Tag_Array   is Octet_Array (1 .. 16);

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

end Tls_Core.Aead_Aes256_Gcm;
