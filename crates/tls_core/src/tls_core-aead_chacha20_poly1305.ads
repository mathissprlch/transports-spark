--  Tls_Core.Aead_Chacha20_Poly1305 — AEAD construction (RFC 8439 §2.8).
--
--    poly_key      = ChaCha20(key, nonce, counter=0)[0..31]
--    ciphertext    = ChaCha20(key, nonce, counter=1) XOR plaintext
--    mac_data      = AAD || pad16(AAD)
--                  || ciphertext || pad16(ciphertext)
--                  || u64_LE(|AAD|)
--                  || u64_LE(|ciphertext|)
--    tag           = Poly1305(poly_key, mac_data)
--    AEAD_output   = ciphertext || tag
--
--  pad16(x) zero-pads x up to a multiple of 16 (the empty padding
--  if |x| mod 16 = 0).
--
--  miTLS reference: src/tls/MiTLS.Crypto.AEAD.fst — the F\* spec's
--  `seal` postcondition is the functional equality with the RFC
--  construction; HACL\* discharges it. Our Ada implementation IS
--  the RFC construction by inspection; gnatprove sees the
--  composition cleanly.

with Tls_Core.Chacha20;
with Tls_Core.Poly1305;

package Tls_Core.Aead_Chacha20_Poly1305
with SPARK_Mode
is

   subtype Key_Array   is Tls_Core.Chacha20.Key_Array;
   subtype Nonce_Array is Tls_Core.Chacha20.Nonce_Array;
   subtype Tag_Array   is Tls_Core.Poly1305.Tag_Array;

   --  Seal: encrypt Plaintext under Key/Nonce, authenticate
   --  Plaintext + AAD, return Ciphertext (= Plaintext'Length bytes)
   --  and Tag (16 bytes).
   --  Abstract RFC 8439 §2.8 AEAD pair.
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

   --  Open: verify Tag, decrypt Ciphertext to Plaintext.
   --  OK=False if the tag check fails (caller MUST then ignore
   --  Plaintext per RFC 5116 §2.2 — we still write something into
   --  Plaintext but the bytes are not authenticated).
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

end Tls_Core.Aead_Chacha20_Poly1305;
