separate (Tls_Core.Hello)
procedure Encode_Client_Hello_Psk_With_Cookie
  (Random         : Random_Bytes;
   Identity       : Octet_Array;
   Key_Share      : Public_Key;
   Cookie         : Octet_Array;
   Server_Name    : Octet_Array;
   Alpn_Offers    : Octet_Array;
   Out_Buf        : out Octet_Array;
   Out_Last       : out Natural;
   Truncated_Last : out Natural)
is
   Cursor         : Natural := 0;
   Ext_Len_Pos    : Natural;
   Ext_Body_Start : Natural;
begin
   Out_Buf := [others => 0];
   Truncated_Last := 0;

   W_U8 (Out_Buf, Cursor, 16#03#);
   W_U8 (Out_Buf, Cursor, 16#03#);
   W_Bytes (Out_Buf, Cursor, Random);
   W_U8 (Out_Buf, Cursor, 0);
   W_U16 (Out_Buf, Cursor, 6);
   W_U8 (Out_Buf, Cursor, 16#13#);
   W_U8 (Out_Buf, Cursor, 16#03#);
   W_U8 (Out_Buf, Cursor, 16#13#);
   W_U8 (Out_Buf, Cursor, 16#01#);
   W_U8 (Out_Buf, Cursor, 16#13#);
   W_U8 (Out_Buf, Cursor, 16#02#);
   W_U8 (Out_Buf, Cursor, 1);
   W_U8 (Out_Buf, Cursor, 0);

   Cursor := Cursor + 1;
   Ext_Len_Pos := Cursor;
   Cursor := Cursor + 1;
   Ext_Body_Start := Cursor + 1;

   declare
      Body_Bytes : constant Octet_Array (1 .. 3) :=
        [1 => 16#02#, 2 => 16#03#, 3 => 16#04#];
   begin
      Encode_Extension (Out_Buf, Cursor, Ext_Supported_Versions, Body_Bytes);
   end;

   --  supported_groups = [x25519].
   declare
      Body_Bytes : constant Octet_Array (1 .. 4) :=
        [1 => 16#00#, 2 => 16#02#, 3 => Named_Group_Hi, 4 => Named_Group_Lo];
   begin
      Encode_Extension (Out_Buf, Cursor, Ext_Supported_Groups, Body_Bytes);
   end;

   --  server_name (RFC 6066 §3) — emit only when non-empty.
   if Server_Name'Length > 0 then
      declare
         Sni_Body      : Octet_Array (1 .. 5 + Server_Name'Length) :=
           (others => 0);
         Sni_Body_Last : Natural;
      begin
         Tls_Core.Extensions.Encode_Server_Name
           (Server_Name, Sni_Body, Sni_Body_Last);
         Encode_Extension
           (Out_Buf, Cursor, Ext_Server_Name, Sni_Body (1 .. Sni_Body_Last));
      end;
   end if;

   --  ALPN (RFC 7301 / RFC 8446 §4.2).
   if Alpn_Offers'Length > 0 then
      declare
         Alpn_Body      : Octet_Array (1 .. 2 + Alpn_Offers'Length) :=
           (others => 0);
         Alpn_Body_Last : Natural;
      begin
         Tls_Core.Extensions.Encode_Alpn
           (Alpn_Offers, Alpn_Body, Alpn_Body_Last);
         Encode_Extension
           (Out_Buf, Cursor, Ext_Alpn, Alpn_Body (1 .. Alpn_Body_Last));
      end;
   end if;

   --  key_share = [{x25519, 32-byte u-coord}].
   declare
      Body_Bytes : Octet_Array (1 .. 2 + 2 + 2 + 32) := [others => 0];
   begin
      Body_Bytes (1) := 16#00#;
      Body_Bytes (2) := 16#24#;
      Body_Bytes (3) := Named_Group_Hi;
      Body_Bytes (4) := Named_Group_Lo;
      Body_Bytes (5) := 16#00#;
      Body_Bytes (6) := 16#20#;
      Body_Bytes (7 .. 38) := Key_Share;
      Encode_Extension (Out_Buf, Cursor, Ext_Key_Share, Body_Bytes);
   end;

   --  psk_key_exchange_modes = [psk_dhe_ke (1)].
   declare
      Body_Bytes : constant Octet_Array (1 .. 2) := [1 => 16#01#, 2 => 16#01#];
   begin
      Encode_Extension
        (Out_Buf, Cursor, Ext_Psk_Key_Exchange_Modes, Body_Bytes);
   end;

   --  cookie extension (RFC 8446 §4.2.2). Body = u16 cookie_len +
   --  cookie_bytes. Omit the entire extension if Cookie is empty.
   if Cookie'Length > 0 then
      declare
         Cookie_Body : Octet_Array (1 .. 2 + Cookie'Length) := (others => 0);
      begin
         Cookie_Body (1) := Octet (Cookie'Length / 256);
         Cookie_Body (2) := Octet (Cookie'Length mod 256);
         Cookie_Body (3 .. 2 + Cookie'Length) := Cookie;
         Encode_Extension (Out_Buf, Cursor, Ext_Cookie, Cookie_Body);
      end;
   end if;

   --  pre_shared_key — MUST BE LAST.
   W_U16 (Out_Buf, Cursor, Ext_Pre_Shared_Key);
   declare
      Identities_Section_Len : constant Natural := 2 + 2 + Identity'Length + 4;
      Binders_Section_Len    : constant Natural := 2 + 1 + 32;
      Ext_Data_Len           : constant Natural :=
        Identities_Section_Len + Binders_Section_Len;
   begin
      W_U16 (Out_Buf, Cursor, Ext_Data_Len);
      W_U16 (Out_Buf, Cursor, 2 + Identity'Length + 4);
      W_U16 (Out_Buf, Cursor, Identity'Length);
      W_Bytes (Out_Buf, Cursor, Identity);
      W_U8 (Out_Buf, Cursor, 0);
      W_U8 (Out_Buf, Cursor, 0);
      W_U8 (Out_Buf, Cursor, 0);
      W_U8 (Out_Buf, Cursor, 0);
      --  RFC 8446 §4.2.11.2: binder hash covers CH up to and
      --  including .identities, excluding the entire .binders<>
      --  field (length prefix + entries).
      Truncated_Last := Cursor;
      W_U16 (Out_Buf, Cursor, 1 + 32);
      W_U8 (Out_Buf, Cursor, 32);
      Cursor := Cursor + 32;
   end;

   Patch_U16 (Out_Buf, Ext_Len_Pos, Cursor - Ext_Body_Start + 1);
   Out_Last := Cursor;
end Encode_Client_Hello_Psk_With_Cookie;
