separate (Tls_Core.Hello)
procedure Encode_Server_Hello_Psk
  (Random          : Random_Bytes;
   Session_Id_Echo : Octet_Array;
   Selected_Suite  : Tls_Core.Suites.U16;
   Key_Share       : Public_Key;
   Out_Buf         : out Octet_Array;
   Out_Last        : out Natural)
is
   use type Tls_Core.Suites.U16;
   Cursor         : Natural := 0;
   Ext_Len_Pos    : Natural;
   Ext_Body_Start : Natural;
   Suite_Hi       : constant Octet := Octet (Selected_Suite / 16#0100#);
   Suite_Lo       : constant Octet := Octet (Selected_Suite mod 16#0100#);
begin
   Out_Buf := [others => 0];
   W_U8 (Out_Buf, Cursor, 16#03#);
   W_U8 (Out_Buf, Cursor, 16#03#);
   W_Bytes (Out_Buf, Cursor, Random);
   --  legacy_session_id_echo — MUST verbatim mirror the
   --  client's legacy_session_id (RFC 8446 §4.1.3).
   W_U8 (Out_Buf, Cursor, Octet (Session_Id_Echo'Length));
   if Session_Id_Echo'Length > 0 then
      W_Bytes (Out_Buf, Cursor, Session_Id_Echo);
   end if;
   W_U8 (Out_Buf, Cursor, Suite_Hi);       -- selected cipher suite
   W_U8 (Out_Buf, Cursor, Suite_Lo);
   W_U8 (Out_Buf, Cursor, 0);              -- compression_method
   Cursor := Cursor + 1;
   Ext_Len_Pos := Cursor;
   Cursor := Cursor + 1;
   Ext_Body_Start := Cursor + 1;

   --  supported_versions = TLS 1.3.
   declare
      Body_Bytes : constant Octet_Array (1 .. 2) := [1 => 16#03#, 2 => 16#04#];
   begin
      Encode_Extension (Out_Buf, Cursor, Ext_Supported_Versions, Body_Bytes);
   end;

   --  key_share — RFC 8446 §4.2.8 SH layout (no list_len prefix —
   --  exactly one KeyShareEntry):
   --      u16 group, u16 key_exch_len, key_exch
   declare
      Body_Bytes : Octet_Array (1 .. 2 + 2 + 32) := [others => 0];
   begin
      Body_Bytes (1) := Named_Group_Hi;
      Body_Bytes (2) := Named_Group_Lo;
      Body_Bytes (3) := 16#00#;
      Body_Bytes (4) := 16#20#;
      Body_Bytes (5 .. 36) := Key_Share;
      Encode_Extension (Out_Buf, Cursor, Ext_Key_Share, Body_Bytes);
   end;

   --  pre_shared_key = u16 selected_identity = 0.
   declare
      Body_Bytes : constant Octet_Array (1 .. 2) := [1 => 16#00#, 2 => 16#00#];
   begin
      Encode_Extension (Out_Buf, Cursor, Ext_Pre_Shared_Key, Body_Bytes);
   end;

   Patch_U16 (Out_Buf, Ext_Len_Pos, Cursor - Ext_Body_Start + 1);
   Out_Last := Cursor;
end Encode_Server_Hello_Psk;
