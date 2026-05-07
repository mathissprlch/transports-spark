--  Tls_Core.Gcm_Core — shared GCM primitives (NIST SP 800-38D).
--
--  Both Aead_Aes128_Gcm and Aead_Aes256_Gcm need the same set of
--  building blocks:
--      INC32 (32-bit big-endian counter increment)
--      Build_J0 (initial counter from 12-byte nonce)
--      Pad_Len (16-byte alignment padding)
--      Build_Mac_Data (AAD || pad || CT || pad || len_AAD || len_CT)
--      GHASH_Mul (GF(2^128) multiply with the 0xE1...0 polynomial)
--      GHASH (iterative XOR-and-multiply)
--      AES-CTR (counter-mode encrypt; generic over Encrypt_Block)
--
--  None of these depend on AES *key length*, so they all live here
--  once and Aes_Ctr is a generic procedure parameterised on the
--  per-suite AES Encrypt_Block primitive. Each helper is its own
--  top-level SPARK entity → parallel proof.
--
--  Source: NIST SP 800-38D §6.3 (GHASH_Mul), §6.4 (GHASH),
--          §7.1 (Build_J0 + AES-CTR + Build_Mac_Data layout).

package Tls_Core.Gcm_Core
with SPARK_Mode
is

   subtype Block_16 is Octet_Array (1 .. 16);

   --  INC32 — increment the lower 32 bits big-endian. NIST SP
   --  800-38D §6.2 inc_32(X) = X[1..96] || (X[97..128] + 1 mod 2^32).
   function Spec_Increment_Counter (Counter : Block_16) return Block_16
   with Ghost;
   procedure Increment_Counter (Counter : in out Block_16)
   with Post => Counter = Spec_Increment_Counter (Counter'Old);

   --  J0 = nonce ‖ 0x00000001 (12-byte nonce path; NIST §7.1).
   function Spec_Build_J0
     (Nonce : Octet_Array) return Block_16
   with Ghost,
        Pre => Nonce'Length = 12;
   procedure Build_J0
     (Nonce  : Octet_Array;
      Out_J0 : out Block_16)
   with Pre => Nonce'Length = 12,
        Post => Out_J0 = Spec_Build_J0 (Nonce);

   --  Pad to next 16-byte boundary.
   function Pad_Len (L : Natural) return Natural
   is (if L mod 16 = 0 then 0 else 16 - (L mod 16));

   function Spec_Build_Mac_Data
     (AAD, Ciphertext : Octet_Array) return Octet_Array
   with Ghost,
        Pre => AAD'Length <= 16640
               and then Ciphertext'Length <= 16640;

   procedure Build_Mac_Data
     (AAD        : Octet_Array;
      Ciphertext : Octet_Array;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural)
   with
     Pre  => AAD'Length <= 16640
             and then Ciphertext'Length <= 16640
             and then Out_Buf'First = 1
             and then Out_Buf'Length >=
               AAD'Length + Pad_Len (AAD'Length)
               + Ciphertext'Length + Pad_Len (Ciphertext'Length)
               + 16,
     Post => Out_Last =
               AAD'Length + Pad_Len (AAD'Length)
               + Ciphertext'Length + Pad_Len (Ciphertext'Length)
               + 16;

   --  GHASH GF(2^128) multiply (NIST §6.3). Bits ordered MSB-first
   --  per byte; reduction polynomial R = 0xE1 || 0^120.
   function Spec_Ghash_Mul (X, Y : Block_16) return Block_16
   with Ghost;
   procedure Ghash_Mul (X : in out Block_16; Y : Block_16)
   with Post => X = Spec_Ghash_Mul (X'Old, Y);

   --  GHASH iteration over a multi-block input (NIST §6.4).
   --  Y_0 = 0; Y_i = (Y_{i-1} XOR X_i) · H. Out_X is initially Y_0
   --  (caller can use this to chain or restart).
   --
   --  Bound: Data'Length <= 33326 covers the worst-case Mac_Buf
   --  built from AAD ≤ 16640 + Ciphertext ≤ 16640 (RFC 8446 max
   --  TLSCiphertext) — i.e. 16640 + 15 + 16640 + 15 + 16 = 33326.
   procedure Ghash
     (H     : Block_16;
      Data  : Octet_Array;
      Out_X : in out Block_16)
   with
     Pre =>
       Data'Length <= 33326
       and then Data'Last < Integer'Last - 16640;

   --  AES-CTR encryption — generic over the AES Encrypt primitive.
   --  Encrypt_Block is the per-suite AES variant: Aes128.Encrypt_Block
   --  for AES-128-GCM, Aes256.Encrypt_Block for AES-256-GCM. The
   --  formal Round_Keys is the matching round-key array type.
   generic
      type Round_Keys is private;
      with procedure Encrypt_Block
        (RK        : Round_Keys;
         Plaintext : Block_16;
         Out_Block : out Block_16);
   procedure Aes_Ctr_G
     (RK        : Round_Keys;
      Initial_J : Block_16;
      Input     : Octet_Array;
      Output    : out Octet_Array)
   with
     Pre =>
       Output'Length = Input'Length
       and then Input'Length <= 16640
       and then Input'Last < Integer'Last - 16640
       and then Output'Last < Integer'Last - 16640;

end Tls_Core.Gcm_Core;
