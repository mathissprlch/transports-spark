with Interfaces;
with Tls_Core.Aead_Chacha20_Poly1305;

package body Tls_Core.Channel
with SPARK_Mode => Off
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;

   --  TLS 1.3 §5.2 record-layer envelope opaque_type values.
   Application_Data : constant Octet := 16#17#;
   --  Legacy version field on the wire is always 0x0303 in TLS 1.3.
   Legacy_Version_Hi : constant Octet := 16#03#;
   Legacy_Version_Lo : constant Octet := 16#03#;

   subtype Tag_Bytes is Octet_Array (1 .. 16);

   ---------------------------------------------------------------------
   --  Aead instantiation
   ---------------------------------------------------------------------

   procedure Cha_Seal
     (Key        : Key_Type;
      Nonce      : Tls_Core.Record_Layer.IV_Array;
      AAD        : Octet_Array;
      Plaintext  : Octet_Array;
      Ciphertext : out Octet_Array;
      Tag        : out Tag_Bytes);
   procedure Cha_Seal
     (Key        : Key_Type;
      Nonce      : Tls_Core.Record_Layer.IV_Array;
      AAD        : Octet_Array;
      Plaintext  : Octet_Array;
      Ciphertext : out Octet_Array;
      Tag        : out Tag_Bytes)
   is
   begin
      Tls_Core.Aead_Chacha20_Poly1305.Seal
        (Key        => Key,
         Nonce      => Nonce,
         AAD        => AAD,
         Plaintext  => Plaintext,
         Ciphertext => Ciphertext,
         Tag        => Tag);
   end Cha_Seal;

   procedure Cha_Open
     (Key        : Key_Type;
      Nonce      : Tls_Core.Record_Layer.IV_Array;
      AAD        : Octet_Array;
      Ciphertext : Octet_Array;
      Tag        : Tag_Bytes;
      Plaintext  : out Octet_Array;
      OK         : out Boolean);
   procedure Cha_Open
     (Key        : Key_Type;
      Nonce      : Tls_Core.Record_Layer.IV_Array;
      AAD        : Octet_Array;
      Ciphertext : Octet_Array;
      Tag        : Tag_Bytes;
      Plaintext  : out Octet_Array;
      OK         : out Boolean)
   is
   begin
      Tls_Core.Aead_Chacha20_Poly1305.Open
        (Key        => Key,
         Nonce      => Nonce,
         AAD        => AAD,
         Ciphertext => Ciphertext,
         Tag        => Tag,
         Plaintext  => Plaintext,
         OK         => OK);
   end Cha_Open;

   package Aead is new Tls_Core.Record_Layer.Aead
     (Key_Type => Key_Type,
      Tag_Type => Tag_Bytes,
      Seal     => Cha_Seal,
      Open     => Cha_Open);

   ---------------------------------------------------------------------
   --  Init
   ---------------------------------------------------------------------

   procedure Init
     (D      : out Direction;
      Secret : Tls_Core.Key_Schedule.Secret)
   is
      Iv : Tls_Core.Record_Layer.IV_Array;
   begin
      Tls_Core.Traffic_Keys.Derive
        (Secret_In => Secret,
         Out_Key   => D.Key,
         Out_IV    => Iv);
      Tls_Core.Record_Layer.Init (D.Stream, Iv);
   end Init;

   ---------------------------------------------------------------------
   --  Send — TLSCiphertext envelope:
   --      opaque_type     uint8  (always 0x17 = application_data)
   --      legacy_version  uint16 (0x0303)
   --      length          uint16 (length of encrypted payload + 16 tag)
   --      encrypted_record  opaque[length]
   ---------------------------------------------------------------------

   procedure Send
     (D          : in out Direction;
      Plaintext  : Octet_Array;
      Inner_Type : Octet;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural)
   is
      --  TLSInnerPlaintext = content || type (no padding for now).
      Inner : Octet_Array (1 .. Plaintext'Length + 1) := (others => 0);
      Encrypted_Len : constant Natural := Inner'Length + 16;
      AAD : constant Octet_Array (1 .. 5) :=
        (Application_Data,
         Legacy_Version_Hi, Legacy_Version_Lo,
         Octet (Unsigned_16 (Encrypted_Len) / 256),
         Octet (Unsigned_16 (Encrypted_Len) mod 256));
      Ct  : Octet_Array (1 .. Inner'Length);
      Tag : Tag_Bytes;
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

   procedure Send
     (D         : in out Direction;
      Plaintext : Octet_Array;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   is
   begin
      Send (D, Plaintext, Inner_Type_Application_Data, Out_Buf, Out_Last);
   end Send;

   ---------------------------------------------------------------------
   --  Receive — parse one record off the head of In_Buf, decrypt.
   ---------------------------------------------------------------------

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

      if In_Buf'Length < 5 + 1 + 16 then
         return;
      end if;

      declare
         Op_Type   : constant Octet := In_Buf (F);
         Ver_Hi    : constant Octet := In_Buf (F + 1);
         Ver_Lo    : constant Octet := In_Buf (F + 2);
         Len_Hi    : constant Natural := Natural (In_Buf (F + 3));
         Len_Lo    : constant Natural := Natural (In_Buf (F + 4));
         Frag_Len  : constant Natural := Len_Hi * 256 + Len_Lo;
         Inner_Len : Integer;
         AAD       : Octet_Array (1 .. 5);
      begin
         if Op_Type /= Application_Data
           or else Ver_Hi /= Legacy_Version_Hi
           or else Ver_Lo /= Legacy_Version_Lo
           or else Frag_Len < 1 + 16
           or else In_Buf'Length < 5 + Frag_Len
         then
            return;
         end if;
         Inner_Len := Frag_Len - 16;
         if Inner_Len <= 0 or else Out_Buf'Length + 1 < Inner_Len then
            return;
         end if;
         AAD := (Op_Type, Ver_Hi, Ver_Lo,
                 In_Buf (F + 3), In_Buf (F + 4));
         declare
            Ct  : constant Octet_Array := In_Buf (F + 5 .. F + 4 + Inner_Len);
            Tag : Tag_Bytes;
            Pt  : Octet_Array (1 .. Inner_Len);
            OK_Local : Boolean;
         begin
            Tag := In_Buf
              (F + 5 + Inner_Len .. F + 4 + Inner_Len + 16);
            Aead.Open_Record
              (S          => D.Stream,
               Key        => D.Key,
               AAD        => AAD,
               Ciphertext => Ct,
               Tag        => Tag,
               Plaintext  => Pt,
               OK         => OK_Local);
            if OK_Local and then Inner_Len > 0 then
               --  Strip TLSInnerPlaintext trailer per RFC 8446 §5.2:
               --  scan from end skipping zero padding bytes; the
               --  last non-zero byte is the content type.
               declare
                  Tail : Integer := Inner_Len;
               begin
                  while Tail >= 1 and then Pt (Tail) = 0 loop
                     Tail := Tail - 1;
                  end loop;
                  if Tail >= 1 then
                     Inner_Type := Pt (Tail);
                     if Tail > 1 then
                        Out_Buf (1 .. Tail - 1) := Pt (1 .. Tail - 1);
                        Out_Last := Tail - 1;
                     else
                        Out_Last := 0;
                     end if;
                     OK := True;
                  end if;
               end;
            end if;
         end;
      end;
   end Receive;

   procedure Receive
     (D        : in out Direction;
      In_Buf   : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural;
      OK       : out Boolean)
   is
      Inner_Type : Octet;
   begin
      Receive (D, In_Buf, Out_Buf, Out_Last, Inner_Type, OK);
      if OK and then Inner_Type /= Inner_Type_Application_Data then
         OK := False;
         Out_Last := 0;
      end if;
   end Receive;

end Tls_Core.Channel;
