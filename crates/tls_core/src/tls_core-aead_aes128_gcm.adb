with Tls_Core.Aes_Core;
with Tls_Core.Gcm_Core;

package body Tls_Core.Aead_Aes128_Gcm
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;

   subtype Block_16 is Tls_Core.Aes_Core.Block;

   --  Spec ghost — placeholder for the day Aes128.Encrypt_Block
   --  gains a portable HACL\* / FIPS 197 functional spec. Until then
   --  this body computes the same value as the imperative procedure
   --  (deterministic by signature: same inputs → same output). It is
   --  computable, not a stub. See CLAUDE.md §0b.
   function Spec_Aes128_Encrypt_Block
     (RK        : Tls_Core.Aes128.Round_Keys;
      Plaintext : Block_16) return Block_16
   with Ghost;

   function Spec_Aes128_Encrypt_Block
     (RK        : Tls_Core.Aes128.Round_Keys;
      Plaintext : Block_16) return Block_16
   is
      Out_Block : Block_16;
   begin
      Tls_Core.Aes128.Encrypt_Block (RK, Plaintext, Out_Block);
      return Out_Block;
   end Spec_Aes128_Encrypt_Block;

   --  Local pass-through. No functional Post is attached because
   --  Aes_Ctr_Pkg's Aes_Ctr is itself AoRTE-only (the §0b OPEN GAP).
   --  When the AES agent lands a functional Post, the bridge here
   --  becomes one line.
   procedure Aes128_Encrypt
     (RK        : Tls_Core.Aes128.Round_Keys;
      Plaintext : Block_16;
      Out_Block : out Block_16);
   procedure Aes128_Encrypt
     (RK        : Tls_Core.Aes128.Round_Keys;
      Plaintext : Block_16;
      Out_Block : out Block_16)
   is
   begin
      Tls_Core.Aes128.Encrypt_Block (RK, Plaintext, Out_Block);
   end Aes128_Encrypt;

   package Aes128_Ctr is new Tls_Core.Gcm_Core.Aes_Ctr_Pkg
     (Round_Keys          => Tls_Core.Aes128.Round_Keys,
      Spec_Encrypt_Block  => Spec_Aes128_Encrypt_Block,
      Encrypt_Block       => Aes128_Encrypt);

   procedure Seal
     (Key        : Key_Array;
      Nonce      : Nonce_Array;
      AAD        : Octet_Array;
      Plaintext  : Octet_Array;
      Ciphertext : out Octet_Array;
      Tag        : out Tag_Array)
   is
      RK     : Tls_Core.Aes128.Round_Keys;
      H      : Block_16;
      Zero_Block : constant Block_16 := (others => 0);
      J0     : Block_16;
      J1     : Block_16;
      E_J0   : Block_16;

      Mac_Buf : Octet_Array
        (1 .. AAD'Length + Tls_Core.Gcm_Core.Pad_Len (AAD'Length)
              + Plaintext'Length + Tls_Core.Gcm_Core.Pad_Len (Plaintext'Length)
              + 16);
      Mac_Last : Natural;
      X : Block_16 := (others => 0);
   begin
      Tls_Core.Aes128.Expand_Key (Key, RK);
      Tls_Core.Aes128.Encrypt_Block (RK, Zero_Block, H);

      Tls_Core.Gcm_Core.Build_J0 (Nonce, J0);

      J1 := J0;
      Tls_Core.Gcm_Core.Increment_Counter (J1);
      Aes128_Ctr.Aes_Ctr (RK, J1, Plaintext, Ciphertext);

      Tls_Core.Gcm_Core.Build_Mac_Data
        (AAD, Ciphertext, Mac_Buf, Mac_Last);
      Tls_Core.Gcm_Core.Ghash (H, Mac_Buf (1 .. Mac_Last), X);
      Tls_Core.Aes128.Encrypt_Block (RK, J0, E_J0);
      for I in 1 .. 16 loop
         Tag (I) := X (I) xor E_J0 (I);
      end loop;
   end Seal;

   procedure Open
     (Key        : Key_Array;
      Nonce      : Nonce_Array;
      AAD        : Octet_Array;
      Ciphertext : Octet_Array;
      Tag        : Tag_Array;
      Plaintext  : out Octet_Array;
      OK         : out Boolean)
   is
      RK     : Tls_Core.Aes128.Round_Keys;
      H      : Block_16;
      Zero_Block : constant Block_16 := (others => 0);
      J0     : Block_16;
      J1     : Block_16;
      E_J0   : Block_16;
      Got_Tag : Tag_Array := (others => 0);

      Mac_Buf : Octet_Array
        (1 .. AAD'Length + Tls_Core.Gcm_Core.Pad_Len (AAD'Length)
              + Ciphertext'Length + Tls_Core.Gcm_Core.Pad_Len (Ciphertext'Length)
              + 16);
      Mac_Last : Natural;
      X : Block_16 := (others => 0);
      Diff : Octet := 0;
   begin
      Plaintext := (others => 0);
      Tls_Core.Aes128.Expand_Key (Key, RK);
      Tls_Core.Aes128.Encrypt_Block (RK, Zero_Block, H);
      Tls_Core.Gcm_Core.Build_J0 (Nonce, J0);

      Tls_Core.Gcm_Core.Build_Mac_Data
        (AAD, Ciphertext, Mac_Buf, Mac_Last);
      Tls_Core.Gcm_Core.Ghash (H, Mac_Buf (1 .. Mac_Last), X);
      Tls_Core.Aes128.Encrypt_Block (RK, J0, E_J0);
      for I in 1 .. 16 loop
         Got_Tag (I) := X (I) xor E_J0 (I);
         Diff := Diff or (Got_Tag (I) xor Tag (I));
      end loop;
      OK := (Diff = 0);

      J1 := J0;
      Tls_Core.Gcm_Core.Increment_Counter (J1);
      Aes128_Ctr.Aes_Ctr (RK, J1, Ciphertext, Plaintext);
   end Open;

end Tls_Core.Aead_Aes128_Gcm;
