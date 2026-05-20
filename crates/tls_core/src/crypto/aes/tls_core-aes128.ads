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
--
--  Platinum spec pinning (HACL\* `specs/Spec.AES.fst` port —
--  Tls_Core.Aes_Spec):
--
--    * Expand_Key carries an unconditional functional Post tying
--      the round-key array to Aes_Spec.Aes128_Key_Expansion.  The
--      body simply calls that spec function, so the Post discharges
--      by construction.
--    * Encrypt_Block / Decrypt_Block carry a functional Post tying
--      the result to Aes_Spec.Aes128_Encrypt_Block /
--      Aes128_Decrypt_Block.  When Tls_Core_Config.T_Tables_Enabled
--      = False the body invokes the spec directly; the Post
--      discharges by construction. When T_Tables_Enabled = True the
--      Post is gated off; the equivalence
--           T-tables-output = Aes_Spec.Aes128_Encrypt_Block
--      is a v0.6 follow-up lemma (per the v0.5 AES investigation).
--
--  The structure mirrors the established "spec is the body" pattern
--  used for SHA-256 / SHA-512 / Spec.HKDF / etc. — the spec lives
--  in a sibling Tls_Core.Aes_Spec package, the public procedures
--  here are thin entry points whose Post is the byte-equality with
--  the spec's output.

with Tls_Core_Config;
with Tls_Core.Aes_Spec;

package Tls_Core.Aes128
  with SPARK_Mode
is

   Block_Length      : constant := 16;
   Key_Length        : constant := 16;
   Round_Keys_Length : constant := 11 * Block_Length;  --  176

   subtype Block is Octet_Array (1 .. Block_Length);
   subtype Key_Array is Octet_Array (1 .. Key_Length);
   subtype Round_Keys is Octet_Array (1 .. Round_Keys_Length);

   --  Expand the 16-byte key into 11 × 16-byte round keys.  FIPS
   --  197 §5.2 KeyExpansion (Rcon, RotWord, SubWord).  Mirrors
   --  HACL\* `aes128_key_expansion` (Spec.AES.fst:250).
   procedure Expand_Key (Key : Key_Array; Out_RK : out Round_Keys)
   with Post => Out_RK = Aes_Spec.Aes128_Key_Expansion (Key);

   --  Encrypt a single 16-byte block. FIPS 197 §5.1 Cipher.  Mirrors
   --  HACL\* `aes_encrypt_block AES128` (Spec.AES.fst:306).
   --
   --  The functional Post is gated by Tls_Core_Config.T_Tables_Enabled
   --  per the v0.5 AES investigation: T-tables fold three round
   --  transforms into one lookup, and proving table-output =
   --  spec-round-by-round is a separate lemma deferred to v0.6.
   procedure Encrypt_Block
     (RK : Round_Keys; Plaintext : Block; Out_Block : out Block)
   with
     Post =>
       (if not Tls_Core_Config.T_Tables_Enabled
        then Out_Block = Aes_Spec.Aes128_Encrypt_Block (Plaintext, RK));

   --  Decrypt a single 16-byte block. FIPS 197 §5.3 InvCipher
   --  (direct form — round keys consumed in reverse order, no
   --  inv-mixed key schedule needed). Mirrors HACL\*
   --  `aes_decrypt_block AES128` (Spec.AES.fst:319).
   --
   --  Decrypt_Block goes through the round-by-round spec path
   --  unconditionally (no T-tables variant ships in v0.5 for the
   --  inverse direction), so the Post is unconditional.
   procedure Decrypt_Block
     (RK : Round_Keys; Ciphertext : Block; Out_Block : out Block)
   with Post => Out_Block = Aes_Spec.Aes128_Decrypt_Block (Ciphertext, RK);

end Tls_Core.Aes128;
