--  Tls_Core.Chacha20 — ChaCha20 stream cipher (RFC 8439 / RFC 7539).
--
--  Source: RFC 8439 §2.3 (block function) + §2.4 (encryption).
--
--  ChaCha20 is a 256-bit-key stream cipher built from a 16-word
--  (16 × 32-bit) state. Each block-function call takes a key, a
--  nonce (96 bits in TLS 1.3), and a 32-bit counter, runs 20
--  rounds (10 double-rounds), and outputs a 64-byte keystream.
--  Encryption is plaintext XOR keystream with the counter
--  incremented per block.
--
--  Spec mirror: HACL*  specs/Spec.Chacha20.fst
--  (chacha20_init / quarter_round / column_round / diagonal_round
--   / double_round / rounds / chacha20_core / chacha20_encrypt_block
--   / chacha20_encrypt_bytes).
--
--  The SPARK ghost functions Spec_Block_Bytes and Spec_Chacha20
--  below are line-for-line ports of those F* let-definitions.
--  Both procedures' Post-conditions reference these ghost specs
--  so functional correctness — not just AoRTE — is established.

with Interfaces;

package Tls_Core.Chacha20
  with SPARK_Mode
is

   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_8;

   subtype Word is Interfaces.Unsigned_32;

   Key_Length   : constant := 32;
   Nonce_Length : constant := 12;
   Block_Length : constant := 64;

   subtype Key_Array is Octet_Array (1 .. Key_Length);
   subtype Nonce_Array is Octet_Array (1 .. Nonce_Length);
   subtype Block_Array is Octet_Array (1 .. Block_Length);

   --------------------------------------------------------------------
   --  Ghost specification — pure executable mirror of HACL* spec.
   --
   --  These functions re-derive the keystream / ciphertext from
   --  scratch in the simplest possible way. They are the reference
   --  against which the imperative Block / Encrypt bodies are proven.
   --
   --  We expose the inner 32-bit-word state mirror Spec_State_Word
   --  so Spec_Block_Bytes' Post can name it directly. This avoids a
   --  per-call inlining problem — the Post equates each result byte
   --  with a little-endian projection of Spec_State_Word.
   --------------------------------------------------------------------

   --  I-th 32-bit word of the post-mix ChaCha20 state (i.e. the
   --  scalar value that is then split into 4 little-endian bytes).
   --  Mirrors HACL*  chacha20_core (return value, indexed).
   function Spec_State_Word
     (Key : Key_Array; Nonce : Nonce_Array; Counter : Word; I : Natural)
      return Word
   with Ghost, Pre => I <= 15;

   --  Single ChaCha20 keystream block (64 bytes).
   --  Spec mirror: Spec.Chacha20.fst : chacha20_core + uints_to_bytes_le.
   function Spec_Block_Bytes
     (Key : Key_Array; Nonce : Nonce_Array; Counter : Word) return Block_Array
   with
     Ghost,
     Post =>
       (for all J in 0 .. 15 =>
          Spec_Block_Bytes'Result (4 * J + 1)
          = Octet (Spec_State_Word (Key, Nonce, Counter, J) and 16#FF#)
          and then Spec_Block_Bytes'Result (4 * J + 2)
                   = Octet
                       (Interfaces.Shift_Right
                          (Spec_State_Word (Key, Nonce, Counter, J), 8)
                        and 16#FF#)
          and then Spec_Block_Bytes'Result (4 * J + 3)
                   = Octet
                       (Interfaces.Shift_Right
                          (Spec_State_Word (Key, Nonce, Counter, J), 16)
                        and 16#FF#)
          and then Spec_Block_Bytes'Result (4 * J + 4)
                   = Octet
                       (Interfaces.Shift_Right
                          (Spec_State_Word (Key, Nonce, Counter, J), 24)
                        and 16#FF#));

   --  XOR keystream with Input starting at the given block counter.
   --  Mirrors Spec.Chacha20.fst : chacha20_encrypt_bytes (init >>
   --  chacha20_update >> map_blocks). Written byte-by-byte: the j-th
   --  output byte is the j-th input byte XOR with the corresponding
   --  byte of the keystream block at counter + (j-1)/Block_Length.
   --  This is the unfolded Lib.Sequence.map_blocks equation that
   --  HACL* proves about its recursive formulation.
   function Spec_Chacha20
     (Key     : Key_Array;
      Nonce   : Nonce_Array;
      Counter : Word;
      Input   : Octet_Array) return Octet_Array
   with
     Ghost,
     Pre  => Input'Last < Integer'Last - Block_Length,
     Post =>
       Spec_Chacha20'Result'First = 1
       and then Spec_Chacha20'Result'Length = Input'Length
       and then (for all J in 1 .. Input'Length =>
                   Spec_Chacha20'Result (J)
                   = (Input (Input'First + J - 1)
                      xor Spec_Block_Bytes
                            (Key,
                             Nonce,
                             Counter + Word ((J - 1) / Block_Length))
                               (((J - 1) mod Block_Length) + 1)));

   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  ChaCha20 block function (RFC 8439 §2.3).
   --
   --  Standard:    RFC 8439 / RFC 7539 §2.3
   --  Spec mirror: HACL*  specs/Spec.Chacha20.fst : chacha20_core
   --
   --  Functional: Out_Block = Spec_Block_Bytes (Key, Nonce, Counter)
   --  Proven at:  gnatprove --level=2 (audit-clean)
   --------------------------------------------------------------------
   procedure Block
     (Key       : Key_Array;
      Nonce     : Nonce_Array;
      Counter   : Word;
      Out_Block : out Block_Array)
   with Post => Out_Block = Spec_Block_Bytes (Key, Nonce, Counter);

   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  ChaCha20 stream encryption (RFC 8439 §2.4).
   --
   --  Standard:    RFC 8439 / RFC 7539 §2.4
   --  Spec mirror: HACL*  specs/Spec.Chacha20.fst : chacha20_encrypt_bytes
   --
   --  Functional: Output = Spec_Chacha20 (Key, Nonce, Initial_Counter, Input)
   --  Proven at:  gnatprove --level=2 (audit-clean)
   --
   --  ChaCha20 is its own inverse (XOR with keystream), so this
   --  routine is used for both encryption and decryption.
   --------------------------------------------------------------------
   procedure Encrypt
     (Key             : Key_Array;
      Nonce           : Nonce_Array;
      Initial_Counter : Word;
      Input           : Octet_Array;
      Output          : out Octet_Array)
   with
     Pre  =>
       Output'Length = Input'Length
       and then Input'Last < Integer'Last - Block_Length
       and then Output'Last < Integer'Last - Block_Length,
     Post => Output = Spec_Chacha20 (Key, Nonce, Initial_Counter, Input);

end Tls_Core.Chacha20;
