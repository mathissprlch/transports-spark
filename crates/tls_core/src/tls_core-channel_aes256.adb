with Interfaces;

package body Tls_Core.Channel_Aes256
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;
   use type Tls_Core.Octet;

   Application_Data  : constant Octet := 16#17#;
   Legacy_Version_Hi : constant Octet := 16#03#;
   Legacy_Version_Lo : constant Octet := 16#03#;

   procedure Aes_Seal
     (Key        : Key_Type;
      Nonce      : Tls_Core.Record_Layer.IV_Array;
      AAD        : Octet_Array;
      Plaintext  : Octet_Array;
      Ciphertext : out Octet_Array;
      Tag        : out Tag_Type)
   with Pre =>
     Ciphertext'Length = Plaintext'Length
     and then AAD'Length <= 16640
     and then Plaintext'Length <= 16640
     and then AAD'Last < Integer'Last - 16640
     and then Plaintext'Last < Integer'Last - 16640
     and then Ciphertext'Last < Integer'Last - 16640;
   procedure Aes_Seal
     (Key        : Key_Type;
      Nonce      : Tls_Core.Record_Layer.IV_Array;
      AAD        : Octet_Array;
      Plaintext  : Octet_Array;
      Ciphertext : out Octet_Array;
      Tag        : out Tag_Type)
   is
   begin
      Tls_Core.Aead_Aes256_Gcm.Seal
        (Key        => Key,
         Nonce      => Nonce,
         AAD        => AAD,
         Plaintext  => Plaintext,
         Ciphertext => Ciphertext,
         Tag        => Tag);
   end Aes_Seal;

   procedure Aes_Open
     (Key        : Key_Type;
      Nonce      : Tls_Core.Record_Layer.IV_Array;
      AAD        : Octet_Array;
      Ciphertext : Octet_Array;
      Tag        : Tag_Type;
      Plaintext  : out Octet_Array;
      OK         : out Boolean)
   with Pre =>
     Plaintext'Length = Ciphertext'Length
     and then AAD'Length <= 16640
     and then Ciphertext'Length <= 16640
     and then AAD'Last < Integer'Last - 16640
     and then Ciphertext'Last < Integer'Last - 16640
     and then Plaintext'Last < Integer'Last - 16640;
   procedure Aes_Open
     (Key        : Key_Type;
      Nonce      : Tls_Core.Record_Layer.IV_Array;
      AAD        : Octet_Array;
      Ciphertext : Octet_Array;
      Tag        : Tag_Type;
      Plaintext  : out Octet_Array;
      OK         : out Boolean)
   is
   begin
      Tls_Core.Aead_Aes256_Gcm.Open
        (Key        => Key,
         Nonce      => Nonce,
         AAD        => AAD,
         Ciphertext => Ciphertext,
         Tag        => Tag,
         Plaintext  => Plaintext,
         OK         => OK);
   end Aes_Open;

   package Aead is new Tls_Core.Record_Layer.Aead
     (Key_Type => Key_Type,
      Tag_Type => Tag_Type,
      Seal     => Aes_Seal,
      Open     => Aes_Open);

   procedure Init
     (D      : out Direction;
      Secret : Tls_Core.Key_Schedule_Sha384.Secret)
   is
      Iv : Tls_Core.Record_Layer.IV_Array;
   begin
      Tls_Core.Traffic_Keys_Aes256_Sha384.Derive
        (Secret_In => Secret,
         Out_Key   => D.Key,
         Out_IV    => Iv);
      Tls_Core.Record_Layer.Init (D.Stream, Iv);
   end Init;

   procedure Send
     (D          : in out Direction;
      Plaintext  : Octet_Array;
      Inner_Type : Octet;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural)
   is
      Inner : Octet_Array (1 .. Plaintext'Length + 1) := (others => 0);
      Encrypted_Len : constant Natural := Inner'Length + 16;
      AAD : constant Octet_Array (1 .. 5) :=
        (Application_Data,
         Legacy_Version_Hi, Legacy_Version_Lo,
         Octet (Unsigned_16 (Encrypted_Len) / 256),
         Octet (Unsigned_16 (Encrypted_Len) mod 256));
      Ct  : Octet_Array (1 .. Inner'Length);
      Tag : Tag_Type;
   begin
      Out_Buf := (others => 0);
      if Plaintext'Length > 0 then
         Inner (1 .. Plaintext'Length) := Plaintext;
      end if;
      Inner (Inner'Last) := Inner_Type;
      Aead.Seal_Record
        (S          => D.Stream,
         Key        => D.Key,
         AAD        => AAD,
         Plaintext  => Inner,
         Ciphertext => Ct,
         Tag        => Tag);
      Out_Buf (1 .. 5) := AAD;
      Out_Buf (6 .. 5 + Inner'Length) := Ct;
      Out_Buf
        (5 + Inner'Length + 1 .. 5 + Inner'Length + 16) := Tag;
      Out_Last := 5 + Inner'Length + 16;
   end Send;

   procedure Receive
     (D          : in out Direction;
      In_Buf     : Octet_Array;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural;
      Inner_Type : out Octet;
      OK         : out Boolean)
   is
      F : constant Positive := In_Buf'First;
   begin
      Out_Buf := (others => 0);
      Out_Last := 0;
      Inner_Type := 0;
      OK := False;

      if In_Buf'Length < 5 then return; end if;
      if In_Buf (F) /= Application_Data then return; end if;

      declare
         Length_Hi : constant Natural := Natural (In_Buf (F + 3));
         Length_Lo : constant Natural := Natural (In_Buf (F + 4));
         Enc_Len   : constant Natural := Length_Hi * 256 + Length_Lo;
      begin
         if Enc_Len < 17 then return; end if;
         if In_Buf'Length < 5 + Enc_Len then return; end if;
         declare
            Inner_Len : constant Natural := Enc_Len - 16;
            AAD : constant Octet_Array (1 .. 5) := In_Buf (F .. F + 4);
            Ct  : constant Octet_Array (1 .. Inner_Len) :=
              In_Buf (F + 5 .. F + 5 + Inner_Len - 1);
            Tag : Tag_Type;
            Plain : Octet_Array (1 .. Inner_Len);
            Got_OK : Boolean;
         begin
            for I in 1 .. 16 loop
               Tag (I) := In_Buf (F + 5 + Inner_Len + I - 1);
            end loop;
            Aead.Open_Record
              (S          => D.Stream,
               Key        => D.Key,
               AAD        => AAD,
               Ciphertext => Ct,
               Tag        => Tag,
               Plaintext  => Plain,
               OK         => Got_OK);
            if not Got_OK then return; end if;
            pragma Assert (Inner_Len >= 1);
            declare
               Last : Natural := Inner_Len;
            begin
               while Last > 0 and then Plain (Last) = 0 loop
                  pragma Loop_Invariant (Last in 1 .. Inner_Len);
                  Last := Last - 1;
               end loop;
               if Last = 0 then return; end if;
               Inner_Type := Plain (Last);
               Out_Last := Last - 1;
               if Out_Last > 0 then
                  Out_Buf (1 .. Out_Last) := Plain (1 .. Last - 1);
               end if;
               OK := True;
            end;
         end;
      end;
   end Receive;

end Tls_Core.Channel_Aes256;
