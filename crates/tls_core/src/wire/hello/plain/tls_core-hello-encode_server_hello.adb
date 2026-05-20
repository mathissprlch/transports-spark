separate (Tls_Core.Hello)
procedure Encode_Server_Hello
  (SH : Server_Hello; Out_Buf : out Octet_Array; Out_Last : out Natural)
is
   Cursor         : Natural := 0;
   Ext_Len_Pos    : Natural;
   Ext_Body_Start : Natural;
begin
   Out_Buf := [others => 0];

   W_U8 (Out_Buf, Cursor, 16#03#);
   W_U8 (Out_Buf, Cursor, 16#03#);
   W_Bytes (Out_Buf, Cursor, SH.Random);
   W_U8 (Out_Buf, Cursor, Octet (SH.Session_Id_Len));
   if SH.Session_Id_Len > 0 then
      W_Bytes (Out_Buf, Cursor, SH.Session_Id_Bytes (1 .. SH.Session_Id_Len));
   end if;
   W_U8 (Out_Buf, Cursor, Cipher_Suite_Hi);
   W_U8 (Out_Buf, Cursor, Cipher_Suite_Lo);
   W_U8 (Out_Buf, Cursor, 0);  --  legacy_compression_method = 0

   Cursor := Cursor + 1;
   Ext_Len_Pos := Cursor;
   Cursor := Cursor + 1;
   Ext_Body_Start := Cursor + 1;

   --  supported_versions in ServerHello: just the single u16 version.
   declare
      Body_Bytes : constant Octet_Array (1 .. 2) := [1 => 16#03#, 2 => 16#04#];
   begin
      Encode_Extension (Out_Buf, Cursor, Ext_Supported_Versions, Body_Bytes);
   end;

   --  key_share in ServerHello: single KeyShareEntry, no list_len prefix.
   declare
      Body_Bytes : Octet_Array (1 .. 2 + 2 + 32) := [others => 0];
   begin
      Body_Bytes (1) := Named_Group_Hi;
      Body_Bytes (2) := Named_Group_Lo;
      Body_Bytes (3) := 16#00#;
      Body_Bytes (4) := 16#20#;
      Body_Bytes (5 .. 36) := SH.Key_Share;
      Encode_Extension (Out_Buf, Cursor, Ext_Key_Share, Body_Bytes);
   end;

   Patch_U16 (Out_Buf, Ext_Len_Pos, Cursor - Ext_Body_Start + 1);

   Out_Last := Cursor;
end Encode_Server_Hello;
