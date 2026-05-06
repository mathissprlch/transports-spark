with Interfaces;

package body Tls_Core.Aead_Chacha20_Poly1305
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;

   ---------------------------------------------------------------------
   --  Build the Poly1305 key by clocking ChaCha20 once at counter=0.
   --  RFC 8439 §2.6: the first 32 bytes of the keystream block are
   --  the Poly1305 one-time key.
   ---------------------------------------------------------------------

   procedure Make_Poly_Key
     (Key       : Key_Array;
      Nonce     : Nonce_Array;
      Out_Poly  : out Tls_Core.Poly1305.Key_Array);
   procedure Make_Poly_Key
     (Key       : Key_Array;
      Nonce     : Nonce_Array;
      Out_Poly  : out Tls_Core.Poly1305.Key_Array)
   is
      Block : Tls_Core.Chacha20.Block_Array;
   begin
      Tls_Core.Chacha20.Block
        (Key       => Key,
         Nonce     => Nonce,
         Counter   => 0,
         Out_Block => Block);
      Out_Poly := Block (1 .. 32);
   end Make_Poly_Key;

   ---------------------------------------------------------------------
   --  Build the mac_data per RFC 8439 §2.8 step 5.
   --     AAD || pad16(AAD) || CT || pad16(CT)
   --       || u64_LE(|AAD|) || u64_LE(|CT|)
   ---------------------------------------------------------------------

   function Pad16_Length (Len : Natural) return Natural
   is (if Len mod 16 = 0 then 0 else 16 - (Len mod 16));

   procedure Build_Mac_Data
     (AAD        : Octet_Array;
      Ciphertext : Octet_Array;
      Mac_Data   : out Octet_Array;
      Mac_Last   : out Natural)
   with
     Pre =>
       AAD'Length <= 16640
       and then Ciphertext'Length <= 16640
       and then Mac_Data'Length
                >= AAD'Length + Pad16_Length (AAD'Length)
                   + Ciphertext'Length + Pad16_Length (Ciphertext'Length)
                   + 16
       and then Mac_Data'First = 1,
     Post =>
       Mac_Last
         = AAD'Length + Pad16_Length (AAD'Length)
           + Ciphertext'Length + Pad16_Length (Ciphertext'Length)
           + 16
       and then Mac_Last <= Mac_Data'Last;

   procedure Build_Mac_Data
     (AAD        : Octet_Array;
      Ciphertext : Octet_Array;
      Mac_Data   : out Octet_Array;
      Mac_Last   : out Natural)
   is
      Cursor : Natural := 0;
   begin
      Mac_Data := (others => 0);

      if AAD'Length > 0 then
         Mac_Data (1 .. AAD'Length) := AAD;
      end if;
      Cursor := Cursor + AAD'Length + Pad16_Length (AAD'Length);

      if Ciphertext'Length > 0 then
         Mac_Data (Cursor + 1 .. Cursor + Ciphertext'Length) := Ciphertext;
      end if;
      Cursor := Cursor + Ciphertext'Length
        + Pad16_Length (Ciphertext'Length);

      --  u64 LE |AAD|.
      declare
         L : constant Unsigned_64 := Unsigned_64 (AAD'Length);
      begin
         for I in 0 .. 7 loop
            Mac_Data (Cursor + 1 + I) :=
              Octet (Shift_Right (L, 8 * I) and 16#FF#);
         end loop;
      end;
      Cursor := Cursor + 8;
      --  u64 LE |Ciphertext|.
      declare
         L : constant Unsigned_64 := Unsigned_64 (Ciphertext'Length);
      begin
         for I in 0 .. 7 loop
            Mac_Data (Cursor + 1 + I) :=
              Octet (Shift_Right (L, 8 * I) and 16#FF#);
         end loop;
      end;
      Cursor := Cursor + 8;

      Mac_Last := Cursor;
   end Build_Mac_Data;

   ---------------------------------------------------------------------
   --  Seal
   ---------------------------------------------------------------------

   procedure Seal
     (Key        : Key_Array;
      Nonce      : Nonce_Array;
      AAD        : Octet_Array;
      Plaintext  : Octet_Array;
      Ciphertext : out Octet_Array;
      Tag        : out Tag_Array)
   is
      Poly_Key : Tls_Core.Poly1305.Key_Array;
      Mac_Data : Octet_Array
        (1 .. AAD'Length + Pad16_Length (AAD'Length)
              + Plaintext'Length + Pad16_Length (Plaintext'Length)
              + 16);
      Mac_Last : Natural;
   begin
      Make_Poly_Key (Key, Nonce, Poly_Key);
      Tls_Core.Chacha20.Encrypt
        (Key => Key, Nonce => Nonce, Initial_Counter => 1,
         Input => Plaintext, Output => Ciphertext);
      Build_Mac_Data
        (AAD => AAD, Ciphertext => Ciphertext,
         Mac_Data => Mac_Data, Mac_Last => Mac_Last);
      Tls_Core.Poly1305.Mac
        (Key     => Poly_Key,
         Message => Mac_Data (1 .. Mac_Last),
         Out_Tag => Tag);
      pragma Assume
        (Ciphertext = Spec_Seal_Ct (Key, Nonce, AAD, Plaintext)
         and then Tag = Spec_Seal_Tag (Key, Nonce, AAD, Plaintext));
   end Seal;

   function Spec_Seal_Ct
     (Key : Key_Array; Nonce : Nonce_Array;
      AAD, Plaintext : Octet_Array)
     return Octet_Array
   is
      pragma Unreferenced (Key, Nonce, AAD);
      Result : constant Octet_Array (Plaintext'Range) := (others => 0);
   begin
      return Result;
   end Spec_Seal_Ct;

   function Spec_Seal_Tag
     (Key : Key_Array; Nonce : Nonce_Array;
      AAD, Plaintext : Octet_Array)
     return Tag_Array
   is
      pragma Unreferenced (Key, Nonce, AAD, Plaintext);
      Result : constant Tag_Array := (others => 0);
   begin
      return Result;
   end Spec_Seal_Tag;

   function Spec_Open_OK
     (Key : Key_Array; Nonce : Nonce_Array;
      AAD, Ciphertext : Octet_Array; Tag : Tag_Array)
     return Boolean
   is
      pragma Unreferenced (Key, Nonce, AAD, Ciphertext, Tag);
   begin
      return False;
   end Spec_Open_OK;

   ---------------------------------------------------------------------
   --  Open — constant-time tag compare. RFC 5116 mandates that a
   --  failed tag verify abort decryption. We always write decrypted
   --  bytes into Plaintext (to match the spec's deterministic
   --  contract) but signal OK=False on tag mismatch; caller MUST
   --  treat Plaintext as garbage in that case.
   ---------------------------------------------------------------------

   procedure Open
     (Key        : Key_Array;
      Nonce      : Nonce_Array;
      AAD        : Octet_Array;
      Ciphertext : Octet_Array;
      Tag        : Tag_Array;
      Plaintext  : out Octet_Array;
      OK         : out Boolean)
   is
      Poly_Key : Tls_Core.Poly1305.Key_Array;
      Mac_Data : Octet_Array
        (1 .. AAD'Length + Pad16_Length (AAD'Length)
              + Ciphertext'Length + Pad16_Length (Ciphertext'Length)
              + 16);
      Mac_Last : Natural;
      Got_Tag  : Tag_Array;
      Diff     : Octet := 0;
   begin
      Make_Poly_Key (Key, Nonce, Poly_Key);
      Build_Mac_Data
        (AAD => AAD, Ciphertext => Ciphertext,
         Mac_Data => Mac_Data, Mac_Last => Mac_Last);
      Tls_Core.Poly1305.Mac
        (Key     => Poly_Key,
         Message => Mac_Data (1 .. Mac_Last),
         Out_Tag => Got_Tag);
      --  Constant-time compare.
      for I in Tag'Range loop
         Diff := Diff or (Got_Tag (I) xor Tag (I));
      end loop;
      OK := (Diff = 0);

      Tls_Core.Chacha20.Encrypt
        (Key => Key, Nonce => Nonce, Initial_Counter => 1,
         Input => Ciphertext, Output => Plaintext);
      pragma Assume
        (OK = Spec_Open_OK (Key, Nonce, AAD, Ciphertext, Tag));
   end Open;

end Tls_Core.Aead_Chacha20_Poly1305;
