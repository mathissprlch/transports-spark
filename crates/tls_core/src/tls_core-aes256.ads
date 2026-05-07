--  Tls_Core.Aes256 — AES-256 block cipher (FIPS 197).
--
--  16-byte block, 256-bit key, 14 rounds. Same SubBytes / ShiftRows
--  / MixColumns / AddRoundKey machinery as AES-128; the only
--  differences are:
--    - key is 32 bytes (Nk = 8 words)
--    - 15 round keys (224 bytes total)
--    - one extra SubWord step every 4th word (i mod Nk = 4)
--
--  Test vector: FIPS 197 §C.3
--    Key   = 000102030405060708090A0B0C0D0E0F
--            101112131415161718191A1B1C1D1E1F
--    Pt    = 00112233445566778899AABBCCDDEEFF
--    Ct    = 8EA2B7CA516745BFEAFC49904B496089
--
--  Used by AES-256-GCM (TLS_AES_256_GCM_SHA384, RFC 8446 §B.4).

package Tls_Core.Aes256
with SPARK_Mode
is

   Block_Length      : constant := 16;
   Key_Length        : constant := 32;
   Round_Keys_Length : constant := 15 * Block_Length;  --  240

   subtype Block      is Octet_Array (1 .. Block_Length);
   subtype Key_Array  is Octet_Array (1 .. Key_Length);
   subtype Round_Keys is Octet_Array (1 .. Round_Keys_Length);

   --  No functional Posts. FIPS 197 §C.3 test vector exercises
   --  Expand_Key and Encrypt_Block end-to-end.
   procedure Expand_Key
     (Key    : Key_Array;
      Out_RK : out Round_Keys);

   procedure Encrypt_Block
     (RK        : Round_Keys;
      Plaintext : Block;
      Out_Block : out Block);

end Tls_Core.Aes256;
