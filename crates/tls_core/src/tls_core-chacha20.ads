--  Tls_Core.Chacha20 — ChaCha20 stream cipher (RFC 8439).
--
--  Source: RFC 8439 §2.3 — The ChaCha20 Block Function, plus
--  §2.4 — ChaCha20 Encryption.
--
--  ChaCha20 is a 256-bit-key stream cipher built from a 16-word
--  (16 × 32-bit) state. Each block-function call takes a key, a
--  nonce (96 bits in TLS 1.3), and a 32-bit counter, runs 20
--  rounds (10 double-rounds), and outputs a 64-byte keystream.
--  Encryption is plaintext XOR keystream with the counter
--  incremented per block.
--
--  miTLS reference: HACL\*'s `Hacl.Spec.Chacha20.Vec.fst` (the
--  pure spec) and `Hacl.Chacha20.fst` (the implementation). Our
--  Ada implementation is the FIPS-style RFC 8439 pseudocode by
--  inspection; test vectors from §2.3.2 / §2.4.2 verify it.

with Interfaces;

package Tls_Core.Chacha20
with SPARK_Mode
is

   subtype Word is Interfaces.Unsigned_32;

   Key_Length   : constant := 32;
   Nonce_Length : constant := 12;
   Block_Length : constant := 64;

   subtype Key_Array     is Octet_Array (1 .. Key_Length);
   subtype Nonce_Array   is Octet_Array (1 .. Nonce_Length);
   subtype Block_Array   is Octet_Array (1 .. Block_Length);

   --  RFC 8439 §2.3 block function. Counter is the 32-bit block
   --  counter; key + nonce + counter together produce one 64-byte
   --  keystream block.
   procedure Block
     (Key       : Key_Array;
      Nonce     : Nonce_Array;
      Counter   : Word;
      Out_Block : out Block_Array);

   --  RFC 8439 §2.4 encryption / decryption. ChaCha20 is its own
   --  inverse (XOR-with-keystream), so this routine is used for
   --  both directions. Initial_Counter is the counter for the
   --  first block; it advances by one per 64-byte block.
   --  Abstract RFC 8439 §2.4 keystream-XOR transform; same trust
   --  pattern as Tls_Core.Sha256.Spec_Hash.
   function Spec_Encrypt
     (Key             : Key_Array;
      Nonce           : Nonce_Array;
      Initial_Counter : Word;
      Input           : Octet_Array)
      return Octet_Array
   with
     Ghost,
     Post => Spec_Encrypt'Result'Length = Input'Length;

   procedure Encrypt
     (Key             : Key_Array;
      Nonce           : Nonce_Array;
      Initial_Counter : Word;
      Input           : Octet_Array;
      Output          : out Octet_Array)
   with
     Pre =>
       Output'Length = Input'Length
       and then Input'Last < Integer'Last - Block_Length
       and then Output'Last < Integer'Last - Block_Length,
     Post =>
       Output =
         Spec_Encrypt (Key, Nonce, Initial_Counter, Input);

end Tls_Core.Chacha20;
