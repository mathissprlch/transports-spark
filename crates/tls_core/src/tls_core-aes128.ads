--  Tls_Core.Aes128 — AES-128 block cipher (FIPS 197).
--
--  16-byte block, 128-bit key, 10 rounds. Operations per FIPS 197:
--  SubBytes, ShiftRows, MixColumns, AddRoundKey. Key schedule
--  expands 16-byte key into 11 round keys (176 bytes total).
--
--  Test vector match: FIPS 197 §C.1
--    Key   = 000102030405060708090A0B0C0D0E0F
--    Pt    = 00112233445566778899AABBCCDDEEFF
--    Ct    = 69C4E0D86A7B0430D8CDB78070B4C55A
--
--  AES-GCM (NIST SP 800-38D) layers on top of this; see
--  Tls_Core.Aead_Aes128_Gcm.

package Tls_Core.Aes128
with SPARK_Mode
is

   Block_Length : constant := 16;
   Key_Length   : constant := 16;
   Round_Keys_Length : constant := 11 * Block_Length;  --  176

   subtype Block       is Octet_Array (1 .. Block_Length);
   subtype Key_Array   is Octet_Array (1 .. Key_Length);
   subtype Round_Keys  is Octet_Array (1 .. Round_Keys_Length);

   --  No functional Posts. FIPS 197 mathematical content is checked
   --  via the §C.1 test vector in tls_core_tests.

   --  Expand the 16-byte key into 11 × 16-byte round keys. FIPS
   --  197 §5.2 KeyExpansion (Rcon, RotWord, SubWord).
   procedure Expand_Key
     (Key   : Key_Array;
      Out_RK : out Round_Keys);

   --  Encrypt a single 16-byte block. FIPS 197 §5.1 Cipher.
   procedure Encrypt_Block
     (RK        : Round_Keys;
      Plaintext : Block;
      Out_Block : out Block);

end Tls_Core.Aes128;
