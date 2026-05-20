separate (Tls_Core.Hello)
procedure Encode_Client_Hello
  (CH        : Client_Hello;
   Out_Buf   : out Octet_Array;
   Out_Last  : out Natural)
is
   Cursor   : Natural := 0;
   Ext_Len_Pos : Natural;
   Ext_Body_Start : Natural;
begin
   Out_Buf := (others => 0);

   --  legacy_version 0x0303
   W_U8 (Out_Buf, Cursor, 16#03#);
   W_U8 (Out_Buf, Cursor, 16#03#);
   --  random
   W_Bytes (Out_Buf, Cursor, CH.Random);
   --  legacy_session_id (u8 len + N bytes)
   W_U8 (Out_Buf, Cursor, Octet (CH.Session_Id_Len));
   if CH.Session_Id_Len > 0 then
      W_Bytes
        (Out_Buf, Cursor,
         CH.Session_Id_Bytes (1 .. CH.Session_Id_Len));
   end if;
   --  cipher_suites (u16 len = 2, then one suite)
   W_U16 (Out_Buf, Cursor, 2);
   W_U8 (Out_Buf, Cursor, Cipher_Suite_Hi);
   W_U8 (Out_Buf, Cursor, Cipher_Suite_Lo);
   --  legacy_compression_methods = 01 00
   W_U8 (Out_Buf, Cursor, 1);
   W_U8 (Out_Buf, Cursor, 0);

   --  Extensions (u16 length, then body). Patch length after.
   Cursor := Cursor + 1;
   Ext_Len_Pos := Cursor;
   Cursor := Cursor + 1;  --  reserve 2 bytes for u16 length
   Ext_Body_Start := Cursor + 1;

   --  supported_versions: u8 list_len + N u16 versions
   declare
      Body_Bytes : constant Octet_Array (1 .. 3) :=
        (3 => 16#04#, 2 => 16#03#, 1 => 16#02#);
      --  Body: 0x02 0x03 0x04 (list-of-1: TLS 1.3 = 0x0304)
   begin
      Encode_Extension (Out_Buf, Cursor, Ext_Supported_Versions, Body_Bytes);
   end;

   --  supported_groups: u16 list_len + N u16 groups
   declare
      Body_Bytes : constant Octet_Array (1 .. 4) :=
        (1 => 16#00#, 2 => 16#02#, 3 => Named_Group_Hi, 4 => Named_Group_Lo);
   begin
      Encode_Extension (Out_Buf, Cursor, Ext_Supported_Groups, Body_Bytes);
   end;

   --  signature_algorithms: u16 list_len + N u16 schemes
   declare
      Body_Bytes : constant Octet_Array (1 .. 4) :=
        (1 => 16#00#, 2 => 16#02#, 3 => Sig_Alg_Hi, 4 => Sig_Alg_Lo);
   begin
      Encode_Extension (Out_Buf, Cursor, Ext_Signature_Algorithms, Body_Bytes);
   end;

   --  key_share: u16 client_shares_len + KeyShareEntry { u16 group, u16 key_exch_len, key_exch }
   declare
      Body_Bytes : Octet_Array (1 .. 2 + 2 + 2 + 32) := (others => 0);
   begin
      Body_Bytes (1) := 16#00#;
      Body_Bytes (2) := 16#24#;  --  client_shares total length = 38
      Body_Bytes (3) := Named_Group_Hi;
      Body_Bytes (4) := Named_Group_Lo;
      Body_Bytes (5) := 16#00#;
      Body_Bytes (6) := 16#20#;  --  key_exchange length = 32
      Body_Bytes (7 .. 38) := CH.Key_Share;
      Encode_Extension (Out_Buf, Cursor, Ext_Key_Share, Body_Bytes);
   end;

   --  Patch extensions length.
   Patch_U16 (Out_Buf, Ext_Len_Pos, Cursor - Ext_Body_Start + 1);

   Out_Last := Cursor;
end Encode_Client_Hello;
