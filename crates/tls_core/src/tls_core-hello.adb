with Tls_Core.Extensions;

package body Tls_Core.Hello
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;

   --  Constants for the cipher suite + named group we negotiate.
   Cipher_Suite_Hi : constant Octet := 16#13#;
   Cipher_Suite_Lo : constant Octet := 16#03#;  --  TLS_CHACHA20_POLY1305_SHA256

   Named_Group_Hi  : constant Octet := 16#00#;
   Named_Group_Lo  : constant Octet := 16#1D#;  --  x25519

   Sig_Alg_Hi      : constant Octet := 16#08#;
   Sig_Alg_Lo      : constant Octet := 16#07#;  --  ed25519

   Ext_Supported_Versions    : constant := 16#002B#;
   Ext_Key_Share             : constant := 16#0033#;
   Ext_Supported_Groups      : constant := 16#000A#;
   Ext_Signature_Algorithms  : constant := 16#000D#;
   Ext_Server_Name           : constant := 16#0000#;  --  RFC 6066 §3
   Ext_Alpn                  : constant := 16#0010#;  --  RFC 7301

   ---------------------------------------------------------------------
   --  Small writer helpers: append byte / u16 / a buffer of bytes
   --  into Out_Buf, advancing Cursor.
   ---------------------------------------------------------------------

   procedure W_U8
     (Out_Buf : in out Octet_Array;
      Cursor  : in out Natural;
      Value   : Octet);
   procedure W_U8
     (Out_Buf : in out Octet_Array;
      Cursor  : in out Natural;
      Value   : Octet) is
   begin
      Cursor := Cursor + 1;
      Out_Buf (Cursor) := Value;
   end W_U8;

   procedure W_U16
     (Out_Buf : in out Octet_Array;
      Cursor  : in out Natural;
      Value   : Natural);
   procedure W_U16
     (Out_Buf : in out Octet_Array;
      Cursor  : in out Natural;
      Value   : Natural) is
   begin
      Cursor := Cursor + 1;
      Out_Buf (Cursor) := Octet (Value / 256);
      Cursor := Cursor + 1;
      Out_Buf (Cursor) := Octet (Value mod 256);
   end W_U16;

   procedure W_Bytes
     (Out_Buf : in out Octet_Array;
      Cursor  : in out Natural;
      Bytes   : Octet_Array);
   procedure W_Bytes
     (Out_Buf : in out Octet_Array;
      Cursor  : in out Natural;
      Bytes   : Octet_Array)
   is
   begin
      if Bytes'Length > 0 then
         Out_Buf (Cursor + 1 .. Cursor + Bytes'Length) := Bytes;
         Cursor := Cursor + Bytes'Length;
      end if;
   end W_Bytes;

   ---------------------------------------------------------------------
   --  Patch a u16 length-prefix at a remembered position.
   ---------------------------------------------------------------------

   procedure Patch_U16
     (Out_Buf : in out Octet_Array;
      At_Pos  : Natural;
      Value   : Natural);
   procedure Patch_U16
     (Out_Buf : in out Octet_Array;
      At_Pos  : Natural;
      Value   : Natural) is
   begin
      Out_Buf (At_Pos)     := Octet (Value / 256);
      Out_Buf (At_Pos + 1) := Octet (Value mod 256);
   end Patch_U16;

   ---------------------------------------------------------------------
   --  Encode a single Extension {u16 type, u16 len, body}.
   ---------------------------------------------------------------------

   procedure Encode_Extension
     (Out_Buf : in out Octet_Array;
      Cursor  : in out Natural;
      Ext_Type : Natural;
      Body_Bytes : Octet_Array);
   procedure Encode_Extension
     (Out_Buf : in out Octet_Array;
      Cursor  : in out Natural;
      Ext_Type : Natural;
      Body_Bytes : Octet_Array)
   is
   begin
      W_U16 (Out_Buf, Cursor, Ext_Type);
      W_U16 (Out_Buf, Cursor, Body_Bytes'Length);
      W_Bytes (Out_Buf, Cursor, Body_Bytes);
   end Encode_Extension;

   ---------------------------------------------------------------------
   --  Encode_Client_Hello
   ---------------------------------------------------------------------

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
         Body_Bytes (2) := 16#26#;  --  client_shares total length = 38
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

   ---------------------------------------------------------------------
   --  Encode_Server_Hello
   ---------------------------------------------------------------------

   procedure Encode_Server_Hello
     (SH        : Server_Hello;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   is
      Cursor   : Natural := 0;
      Ext_Len_Pos : Natural;
      Ext_Body_Start : Natural;
   begin
      Out_Buf := (others => 0);

      W_U8 (Out_Buf, Cursor, 16#03#);
      W_U8 (Out_Buf, Cursor, 16#03#);
      W_Bytes (Out_Buf, Cursor, SH.Random);
      W_U8 (Out_Buf, Cursor, Octet (SH.Session_Id_Len));
      if SH.Session_Id_Len > 0 then
         W_Bytes
           (Out_Buf, Cursor,
            SH.Session_Id_Bytes (1 .. SH.Session_Id_Len));
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
         Body_Bytes : constant Octet_Array (1 .. 2) :=
           (1 => 16#03#, 2 => 16#04#);
      begin
         Encode_Extension (Out_Buf, Cursor, Ext_Supported_Versions, Body_Bytes);
      end;

      --  key_share in ServerHello: single KeyShareEntry, no list_len prefix.
      declare
         Body_Bytes : Octet_Array (1 .. 2 + 2 + 32) := (others => 0);
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

   ---------------------------------------------------------------------
   --  Reader helpers — consume from In_Bytes at Pos, advance Pos.
   ---------------------------------------------------------------------

   procedure R_U8
     (In_Bytes : Octet_Array;
      Pos      : in out Natural;
      Value    : out Octet;
      OK       : in out Boolean);
   procedure R_U8
     (In_Bytes : Octet_Array;
      Pos      : in out Natural;
      Value    : out Octet;
      OK       : in out Boolean) is
   begin
      Value := 0;
      if not OK then
         return;
      end if;
      if Pos > In_Bytes'Last then
         OK := False;
         return;
      end if;
      Value := In_Bytes (Pos);
      Pos := Pos + 1;
   end R_U8;

   procedure R_U16
     (In_Bytes : Octet_Array;
      Pos      : in out Natural;
      Value    : out Natural;
      OK       : in out Boolean);
   procedure R_U16
     (In_Bytes : Octet_Array;
      Pos      : in out Natural;
      Value    : out Natural;
      OK       : in out Boolean) is
   begin
      Value := 0;
      if not OK then
         return;
      end if;
      if Pos + 1 > In_Bytes'Last then
         OK := False;
         return;
      end if;
      Value := Natural (In_Bytes (Pos)) * 256 + Natural (In_Bytes (Pos + 1));
      Pos := Pos + 2;
   end R_U16;

   ---------------------------------------------------------------------
   --  Find an extension of given type inside an extensions block,
   --  return its body slice indices [first..last] in In_Bytes.
   ---------------------------------------------------------------------

   procedure Find_Extension
     (In_Bytes  : Octet_Array;
      Pos       : Natural;     --  start of extensions block (after u16 len)
      End_Pos   : Natural;     --  one past last byte of extensions block
      Ext_Type  : Natural;
      Body_First : out Natural;
      Body_Last  : out Natural;
      OK        : out Boolean);
   procedure Find_Extension
     (In_Bytes  : Octet_Array;
      Pos       : Natural;
      End_Pos   : Natural;
      Ext_Type  : Natural;
      Body_First : out Natural;
      Body_Last  : out Natural;
      OK        : out Boolean)
   is
      P : Natural := Pos;
      T : Natural;
      L : Natural;
      Read_OK : Boolean := True;
   begin
      Body_First := 0;
      Body_Last := 0;
      OK := False;
      while P + 3 < End_Pos loop
         R_U16 (In_Bytes, P, T, Read_OK);
         R_U16 (In_Bytes, P, L, Read_OK);
         if not Read_OK or else P + L - 1 >= End_Pos then
            return;
         end if;
         if T = Ext_Type then
            Body_First := P;
            Body_Last := P + L - 1;
            OK := True;
            return;
         end if;
         P := P + L;
      end loop;
   end Find_Extension;

   ---------------------------------------------------------------------
   --  Decode_Client_Hello
   ---------------------------------------------------------------------

   procedure Decode_Client_Hello
     (In_Bytes : Octet_Array;
      CH       : out Client_Hello;
      OK       : out Boolean)
   is
      P : Natural := In_Bytes'First;
      Read_OK : Boolean := True;
      U8_Val : Octet;
      U16_Val : Natural;
      Ext_Total_Len : Natural;
      Ext_Block_Start : Natural;
      Body_F, Body_L : Natural;
      Find_OK : Boolean;
   begin
      CH.Random := (others => 0);
      CH.Session_Id_Len := 0;
      CH.Session_Id_Bytes := (others => 0);
      CH.Key_Share := (others => 0);
      OK := False;

      --  legacy_version (skip — must equal 0x0303)
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      if not Read_OK then return; end if;
      --  random
      if P + 31 > In_Bytes'Last then return; end if;
      CH.Random := In_Bytes (P .. P + 31);
      P := P + 32;
      --  legacy_session_id
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      if not Read_OK then return; end if;
      CH.Session_Id_Len := Natural (U8_Val);
      if CH.Session_Id_Len > 32 then return; end if;
      if CH.Session_Id_Len > 0 then
         if P + CH.Session_Id_Len - 1 > In_Bytes'Last then return; end if;
         CH.Session_Id_Bytes (1 .. CH.Session_Id_Len) :=
           In_Bytes (P .. P + CH.Session_Id_Len - 1);
         P := P + CH.Session_Id_Len;
      end if;
      --  cipher_suites (u16 len, must include 0x1303)
      R_U16 (In_Bytes, P, U16_Val, Read_OK);
      if not Read_OK or else U16_Val < 2 or else U16_Val mod 2 /= 0 then return; end if;
      if P + U16_Val - 1 > In_Bytes'Last then return; end if;
      P := P + U16_Val;
      --  legacy_compression_methods (u8 len + N)
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      if not Read_OK then return; end if;
      if P + Natural (U8_Val) - 1 > In_Bytes'Last then return; end if;
      P := P + Natural (U8_Val);
      --  Extensions (u16 len + body)
      R_U16 (In_Bytes, P, Ext_Total_Len, Read_OK);
      if not Read_OK then return; end if;
      Ext_Block_Start := P;
      if Ext_Block_Start + Ext_Total_Len - 1 > In_Bytes'Last then return; end if;

      --  Find key_share extension and extract the X25519 public key.
      Find_Extension
        (In_Bytes => In_Bytes,
         Pos => Ext_Block_Start,
         End_Pos => Ext_Block_Start + Ext_Total_Len,
         Ext_Type => Ext_Key_Share,
         Body_First => Body_F,
         Body_Last => Body_L,
         OK => Find_OK);
      if not Find_OK then return; end if;
      --  CH key_share body:
      --    u16 client_shares_len
      --    KeyShareEntry { u16 group, u16 key_exch_len, key_exch }
      if Body_L - Body_F + 1 < 2 + 4 + 32 then return; end if;
      --  Skip client_shares_len u16, group u16, key_exch_len u16; copy 32 bytes.
      CH.Key_Share := In_Bytes (Body_F + 6 .. Body_F + 6 + 31);

      OK := True;
   end Decode_Client_Hello;

   ---------------------------------------------------------------------
   --  Decode_Server_Hello
   ---------------------------------------------------------------------

   procedure Decode_Server_Hello
     (In_Bytes : Octet_Array;
      SH       : out Server_Hello;
      OK       : out Boolean)
   is
      P : Natural := In_Bytes'First;
      Read_OK : Boolean := True;
      U8_Val : Octet;
      Ext_Total_Len : Natural;
      Ext_Block_Start : Natural;
      Body_F, Body_L : Natural;
      Find_OK : Boolean;
   begin
      SH.Random := (others => 0);
      SH.Session_Id_Len := 0;
      SH.Session_Id_Bytes := (others => 0);
      SH.Key_Share := (others => 0);
      OK := False;

      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      if not Read_OK then return; end if;
      if P + 31 > In_Bytes'Last then return; end if;
      SH.Random := In_Bytes (P .. P + 31);
      P := P + 32;
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      if not Read_OK then return; end if;
      SH.Session_Id_Len := Natural (U8_Val);
      if SH.Session_Id_Len > 32 then return; end if;
      if SH.Session_Id_Len > 0 then
         if P + SH.Session_Id_Len - 1 > In_Bytes'Last then return; end if;
         SH.Session_Id_Bytes (1 .. SH.Session_Id_Len) :=
           In_Bytes (P .. P + SH.Session_Id_Len - 1);
         P := P + SH.Session_Id_Len;
      end if;
      --  cipher_suite (u16, fixed)
      if P + 1 > In_Bytes'Last then return; end if;
      P := P + 2;
      --  legacy_compression_method (u8)
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      if not Read_OK then return; end if;
      --  Extensions
      R_U16 (In_Bytes, P, Ext_Total_Len, Read_OK);
      if not Read_OK then return; end if;
      Ext_Block_Start := P;
      if Ext_Block_Start + Ext_Total_Len - 1 > In_Bytes'Last then return; end if;

      Find_Extension
        (In_Bytes => In_Bytes,
         Pos => Ext_Block_Start,
         End_Pos => Ext_Block_Start + Ext_Total_Len,
         Ext_Type => Ext_Key_Share,
         Body_First => Body_F,
         Body_Last => Body_L,
         OK => Find_OK);
      if not Find_OK then return; end if;
      --  ServerHello key_share body:
      --    KeyShareEntry { u16 group, u16 key_exch_len, key_exch[32] }
      if Body_L - Body_F + 1 < 4 + 32 then return; end if;
      SH.Key_Share := In_Bytes (Body_F + 4 .. Body_F + 4 + 31);

      OK := True;
   end Decode_Server_Hello;

   ------------------------------------------------------------------
   --  PSK-profile encode/decode
   ------------------------------------------------------------------

   Ext_Psk_Key_Exchange_Modes : constant := 16#002D#;
   Ext_Pre_Shared_Key         : constant := 16#0029#;

   procedure Encode_Client_Hello_Psk
     (Random          : Random_Bytes;
      Identity        : Octet_Array;
      Key_Share       : Public_Key;
      Server_Name     : Octet_Array;
      Alpn_Offers     : Octet_Array;
      Out_Buf         : out Octet_Array;
      Out_Last        : out Natural;
      Truncated_Last  : out Natural)
   is
      Cursor          : Natural := 0;
      Ext_Len_Pos     : Natural;
      Ext_Body_Start  : Natural;
   begin
      Out_Buf := (others => 0);
      Truncated_Last := 0;

      --  legacy_version, random, session_id (empty), cipher_suites,
      --  legacy_compression_methods.
      W_U8 (Out_Buf, Cursor, 16#03#);
      W_U8 (Out_Buf, Cursor, 16#03#);
      W_Bytes (Out_Buf, Cursor, Random);
      W_U8 (Out_Buf, Cursor, 0);                  -- session_id_len
      --  Cipher suites: offer all three v0.5 production suites in
      --  RFC-recommended preference order (chacha20 first per RFC
      --  8446 §B.4 ordering, then AES-128, then AES-256). Server
      --  picks one — see Decode_Client_Hello_Psk + Tls13_Driver.
      W_U16 (Out_Buf, Cursor, 6);                 -- 3 suites × 2 bytes
      W_U8 (Out_Buf, Cursor, 16#13#);             -- TLS_CHACHA20_POLY1305_SHA256
      W_U8 (Out_Buf, Cursor, 16#03#);
      W_U8 (Out_Buf, Cursor, 16#13#);             -- TLS_AES_128_GCM_SHA256
      W_U8 (Out_Buf, Cursor, 16#01#);
      W_U8 (Out_Buf, Cursor, 16#13#);             -- TLS_AES_256_GCM_SHA384
      W_U8 (Out_Buf, Cursor, 16#02#);
      W_U8 (Out_Buf, Cursor, 1);                  -- compression_methods length
      W_U8 (Out_Buf, Cursor, 0);                  -- compression null

      --  Extensions block — patch length after.
      Cursor := Cursor + 1;
      Ext_Len_Pos := Cursor;
      Cursor := Cursor + 1;
      Ext_Body_Start := Cursor + 1;

      --  supported_versions = TLS 1.3.
      declare
         Body_Bytes : constant Octet_Array (1 .. 3) :=
           (1 => 16#02#, 2 => 16#03#, 3 => 16#04#);
      begin
         Encode_Extension
           (Out_Buf, Cursor, Ext_Supported_Versions, Body_Bytes);
      end;

      --  supported_groups = [x25519]. RFC 8446 §4.2.7.
      declare
         Body_Bytes : constant Octet_Array (1 .. 4) :=
           (1 => 16#00#, 2 => 16#02#,
            3 => Named_Group_Hi, 4 => Named_Group_Lo);
      begin
         Encode_Extension
           (Out_Buf, Cursor, Ext_Supported_Groups, Body_Bytes);
      end;

      --  server_name (RFC 6066 §3 / RFC 8446 §4.2.10) — host_name
      --  only.  Emitted only when Server_Name is non-empty;
      --  Tls_Core.Extensions.Encode_Server_Name builds the
      --  ServerNameList body (5 + N bytes), we wrap it with the
      --  extension_type + extension_data length via Encode_Extension.
      if Server_Name'Length > 0 then
         declare
            Sni_Body : Octet_Array (1 .. 5 + Server_Name'Length) :=
              (others => 0);
            Sni_Body_Last : Natural;
         begin
            Tls_Core.Extensions.Encode_Server_Name
              (Server_Name, Sni_Body, Sni_Body_Last);
            Encode_Extension
              (Out_Buf, Cursor, Ext_Server_Name,
               Sni_Body (1 .. Sni_Body_Last));
         end;
      end if;

      --  application_layer_protocol_negotiation (RFC 7301 / RFC 8446
      --  §4.2).  Encode_Alpn wraps the caller-flattened Names_Buf
      --  with the u16 list_length; we wrap that with the
      --  extension_type + extension_data length.
      if Alpn_Offers'Length > 0 then
         declare
            Alpn_Body : Octet_Array (1 .. 2 + Alpn_Offers'Length) :=
              (others => 0);
            Alpn_Body_Last : Natural;
         begin
            Tls_Core.Extensions.Encode_Alpn
              (Alpn_Offers, Alpn_Body, Alpn_Body_Last);
            Encode_Extension
              (Out_Buf, Cursor, Ext_Alpn,
               Alpn_Body (1 .. Alpn_Body_Last));
         end;
      end if;

      --  key_share = [{x25519, 32-byte u-coord}]. RFC 8446 §4.2.8.
      --  CH layout: u16 client_shares_len + KeyShareEntry{
      --      u16 group, u16 key_exch_len, key_exch (32 bytes for x25519)
      --  }.
      declare
         Body_Bytes : Octet_Array (1 .. 2 + 2 + 2 + 32) := (others => 0);
      begin
         Body_Bytes (1) := 16#00#;
         Body_Bytes (2) := 16#26#;        --  client_shares total = 38
         Body_Bytes (3) := Named_Group_Hi;
         Body_Bytes (4) := Named_Group_Lo;
         Body_Bytes (5) := 16#00#;
         Body_Bytes (6) := 16#20#;        --  key_exchange length = 32
         Body_Bytes (7 .. 38) := Key_Share;
         Encode_Extension (Out_Buf, Cursor, Ext_Key_Share, Body_Bytes);
      end;

      --  psk_key_exchange_modes = [psk_dhe_ke (1)]. RFC 8446 §4.2.9.
      --  Mode 0 (psk_ke) is RFC-discouraged + production-rejected;
      --  v0.5 advertises mode 1 only (CLAUDE.md §0a).
      declare
         Body_Bytes : constant Octet_Array (1 .. 2) :=
           (1 => 16#01#, 2 => 16#01#);  --  modes_len = 1, mode = 1 (psk_dhe_ke)
      begin
         Encode_Extension
           (Out_Buf, Cursor, Ext_Psk_Key_Exchange_Modes, Body_Bytes);
      end;

      --  pre_shared_key — MUST BE LAST. Layout:
      --    u16 ext_data_len
      --    u16 identities_total_len
      --    u16 identity_len; identity_bytes; u32 obfuscated_ticket_age
      --    u16 binders_total_len
      --    u8  binder_len = 32; 32 binder bytes (filled by caller)
      W_U16 (Out_Buf, Cursor, Ext_Pre_Shared_Key);
      declare
         Identities_Section_Len : constant Natural :=
           2 + 2 + Identity'Length + 4;  --  list_len_field + id_len + id + age
         Binders_Section_Len    : constant Natural :=
           2 + 1 + 32;                   --  list_len_field + binder_len + 32 bytes
         Ext_Data_Len           : constant Natural :=
           Identities_Section_Len + Binders_Section_Len;
      begin
         W_U16 (Out_Buf, Cursor, Ext_Data_Len);
         --  identities
         W_U16 (Out_Buf, Cursor, 2 + Identity'Length + 4);
         W_U16 (Out_Buf, Cursor, Identity'Length);
         W_Bytes (Out_Buf, Cursor, Identity);
         --  obfuscated_ticket_age = 0
         W_U8 (Out_Buf, Cursor, 0);
         W_U8 (Out_Buf, Cursor, 0);
         W_U8 (Out_Buf, Cursor, 0);
         W_U8 (Out_Buf, Cursor, 0);
         --  binders length field — Truncate(ClientHello) ends here.
         W_U16 (Out_Buf, Cursor, 1 + 32);
         Truncated_Last := Cursor;
         --  binder placeholder: u8 len + 32 zero bytes for caller to overwrite.
         W_U8 (Out_Buf, Cursor, 32);
         Cursor := Cursor + 32;
      end;

      --  Patch extensions-block length.
      Patch_U16 (Out_Buf, Ext_Len_Pos, Cursor - Ext_Body_Start + 1);
      Out_Last := Cursor;
   end Encode_Client_Hello_Psk;

   ---------------------------------------------------------------------
   --  Encode_Client_Hello_Psk_With_Cookie — RFC 8446 §4.1.4 / §4.2.2
   --  CH2 emission after HRR. Same shape as Encode_Client_Hello_Psk
   --  with one additional cookie extension inserted between
   --  psk_key_exchange_modes and the (mandatory-last) pre_shared_key.
   ---------------------------------------------------------------------

   Ext_Cookie : constant := 16#002C#;

   procedure Encode_Client_Hello_Psk_With_Cookie
     (Random          : Random_Bytes;
      Identity        : Octet_Array;
      Key_Share       : Public_Key;
      Cookie          : Octet_Array;
      Server_Name     : Octet_Array;
      Alpn_Offers     : Octet_Array;
      Out_Buf         : out Octet_Array;
      Out_Last        : out Natural;
      Truncated_Last  : out Natural)
   is
      Cursor          : Natural := 0;
      Ext_Len_Pos     : Natural;
      Ext_Body_Start  : Natural;
   begin
      Out_Buf := (others => 0);
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
           (1 => 16#02#, 2 => 16#03#, 3 => 16#04#);
      begin
         Encode_Extension
           (Out_Buf, Cursor, Ext_Supported_Versions, Body_Bytes);
      end;

      --  supported_groups = [x25519].
      declare
         Body_Bytes : constant Octet_Array (1 .. 4) :=
           (1 => 16#00#, 2 => 16#02#,
            3 => Named_Group_Hi, 4 => Named_Group_Lo);
      begin
         Encode_Extension
           (Out_Buf, Cursor, Ext_Supported_Groups, Body_Bytes);
      end;

      --  server_name (RFC 6066 §3) — emit only when non-empty.
      if Server_Name'Length > 0 then
         declare
            Sni_Body : Octet_Array (1 .. 5 + Server_Name'Length) :=
              (others => 0);
            Sni_Body_Last : Natural;
         begin
            Tls_Core.Extensions.Encode_Server_Name
              (Server_Name, Sni_Body, Sni_Body_Last);
            Encode_Extension
              (Out_Buf, Cursor, Ext_Server_Name,
               Sni_Body (1 .. Sni_Body_Last));
         end;
      end if;

      --  ALPN (RFC 7301 / RFC 8446 §4.2).
      if Alpn_Offers'Length > 0 then
         declare
            Alpn_Body : Octet_Array (1 .. 2 + Alpn_Offers'Length) :=
              (others => 0);
            Alpn_Body_Last : Natural;
         begin
            Tls_Core.Extensions.Encode_Alpn
              (Alpn_Offers, Alpn_Body, Alpn_Body_Last);
            Encode_Extension
              (Out_Buf, Cursor, Ext_Alpn,
               Alpn_Body (1 .. Alpn_Body_Last));
         end;
      end if;

      --  key_share = [{x25519, 32-byte u-coord}].
      declare
         Body_Bytes : Octet_Array (1 .. 2 + 2 + 2 + 32) := (others => 0);
      begin
         Body_Bytes (1) := 16#00#;
         Body_Bytes (2) := 16#26#;
         Body_Bytes (3) := Named_Group_Hi;
         Body_Bytes (4) := Named_Group_Lo;
         Body_Bytes (5) := 16#00#;
         Body_Bytes (6) := 16#20#;
         Body_Bytes (7 .. 38) := Key_Share;
         Encode_Extension (Out_Buf, Cursor, Ext_Key_Share, Body_Bytes);
      end;

      --  psk_key_exchange_modes = [psk_dhe_ke (1)].
      declare
         Body_Bytes : constant Octet_Array (1 .. 2) :=
           (1 => 16#01#, 2 => 16#01#);
      begin
         Encode_Extension
           (Out_Buf, Cursor, Ext_Psk_Key_Exchange_Modes, Body_Bytes);
      end;

      --  cookie extension (RFC 8446 §4.2.2). Body = u16 cookie_len +
      --  cookie_bytes. Omit the entire extension if Cookie is empty.
      if Cookie'Length > 0 then
         declare
            Cookie_Body : Octet_Array (1 .. 2 + Cookie'Length) :=
              (others => 0);
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
         Identities_Section_Len : constant Natural :=
           2 + 2 + Identity'Length + 4;
         Binders_Section_Len    : constant Natural :=
           2 + 1 + 32;
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
         W_U16 (Out_Buf, Cursor, 1 + 32);
         Truncated_Last := Cursor;
         W_U8 (Out_Buf, Cursor, 32);
         Cursor := Cursor + 32;
      end;

      Patch_U16 (Out_Buf, Ext_Len_Pos, Cursor - Ext_Body_Start + 1);
      Out_Last := Cursor;
   end Encode_Client_Hello_Psk_With_Cookie;

   procedure Decode_Client_Hello_Psk
     (In_Bytes        : Octet_Array;
      Random          : out Random_Bytes;
      Suites_First    : out Natural;
      Suites_Last     : out Natural;
      Identity_First  : out Natural;
      Identity_Last   : out Natural;
      Binder_First    : out Natural;
      Binder_Last     : out Natural;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      Truncated_Last  : out Natural;
      OK              : out Boolean)
   is
      P : Natural := In_Bytes'First;
      Read_OK : Boolean := True;
      U8_Val : Octet;
      U16_Val : Natural;
      Ext_Total_Len : Natural;
      Ext_Block_Start : Natural;
      Body_F, Body_L : Natural;
      Find_OK : Boolean;
   begin
      Random := (others => 0);
      Suites_First := 0;
      Suites_Last := 0;
      Identity_First := 0;
      Identity_Last := 0;
      Binder_First := 0;
      Binder_Last := 0;
      Key_Share_First := 0;
      Key_Share_Last := 0;
      Truncated_Last := 0;
      OK := False;

      --  legacy_version
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      if not Read_OK then return; end if;
      --  random
      if P + 31 > In_Bytes'Last then return; end if;
      Random := In_Bytes (P .. P + 31);
      P := P + 32;
      --  legacy_session_id
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      if not Read_OK then return; end if;
      if P + Natural (U8_Val) - 1 > In_Bytes'Last then return; end if;
      P := P + Natural (U8_Val);
      --  cipher_suites — record the slice bounds so the caller can
      --  pick a suite. RFC 8446 §4.1.2: u16 length (must be even,
      --  >= 2), then N flat-packed u16 codepoints.
      R_U16 (In_Bytes, P, U16_Val, Read_OK);
      if not Read_OK then return; end if;
      if U16_Val < 2 or else U16_Val mod 2 /= 0 then return; end if;
      if P + U16_Val - 1 > In_Bytes'Last then return; end if;
      Suites_First := P;
      Suites_Last  := P + U16_Val - 1;
      P := P + U16_Val;
      --  legacy_compression_methods
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      if not Read_OK then return; end if;
      if P + Natural (U8_Val) - 1 > In_Bytes'Last then return; end if;
      P := P + Natural (U8_Val);
      --  Extensions length
      R_U16 (In_Bytes, P, Ext_Total_Len, Read_OK);
      if not Read_OK then return; end if;
      Ext_Block_Start := P;
      if Ext_Block_Start + Ext_Total_Len - 1 > In_Bytes'Last then return; end if;

      --  Find pre_shared_key extension — MUST be last in CH.
      Find_Extension
        (In_Bytes => In_Bytes,
         Pos => Ext_Block_Start,
         End_Pos => Ext_Block_Start + Ext_Total_Len,
         Ext_Type => Ext_Pre_Shared_Key,
         Body_First => Body_F,
         Body_Last => Body_L,
         OK => Find_OK);
      if not Find_OK then return; end if;

      --  Body layout:
      --    u16 identities_total_len
      --    one identity: u16 id_len + id + u32 age
      --    u16 binders_total_len
      --    one binder: u8 binder_len + N
      declare
         Q : Natural := Body_F;
         Identities_Total : Natural;
         Identity_Length  : Natural;
         Binders_Total    : Natural;
         Binder_Length    : Natural;
      begin
         if Q + 1 > Body_L then return; end if;
         Identities_Total := Natural (In_Bytes (Q)) * 256 + Natural (In_Bytes (Q + 1));
         Q := Q + 2;
         if Q + 1 > Body_L then return; end if;
         Identity_Length := Natural (In_Bytes (Q)) * 256 + Natural (In_Bytes (Q + 1));
         Q := Q + 2;
         if Identity_Length = 0
           or else Identity_Length > Body_L - Q + 1
         then return; end if;
         Identity_First := Q;
         Identity_Last := Q + Identity_Length - 1;
         Q := Q + Identity_Length;
         --  obfuscated_ticket_age (u32)
         if Q + 3 > Body_L then return; end if;
         Q := Q + 4;
         pragma Unreferenced (Identities_Total);
         --  Truncated CH ends just before the binders array — i.e.
         --  after the binders_total_len u16 has been read, we're at
         --  the first binder byte. The truncation point is one byte
         --  BEFORE the first binder's len byte.
         if Q + 1 > Body_L then return; end if;
         Binders_Total := Natural (In_Bytes (Q)) * 256 + Natural (In_Bytes (Q + 1));
         Q := Q + 2;
         Truncated_Last := Q - 1;
         pragma Unreferenced (Binders_Total);
         if Q > Body_L then return; end if;
         Binder_Length := Natural (In_Bytes (Q));
         Q := Q + 1;
         if Binder_Length /= 32 then return; end if;
         if Q + 31 > Body_L then return; end if;
         Binder_First := Q;
         Binder_Last := Q + 31;
      end;

      --  Locate key_share extension. RFC 8446 §4.2.8 — CH layout:
      --    u16 client_shares_len
      --    KeyShareEntry { u16 group, u16 key_exch_len, key_exch }*
      --  We accept the first entry whose group matches x25519
      --  (0x001D) and key_exch_len = 32.
      declare
         Ks_Body_F, Ks_Body_L : Natural;
         Ks_Find_OK : Boolean;
         Q : Natural;
         Group_Code : Natural;
         Key_Exch_Len : Natural;
         End_Body : Natural;
         Found : Boolean := False;
      begin
         Find_Extension
           (In_Bytes   => In_Bytes,
            Pos        => Ext_Block_Start,
            End_Pos    => Ext_Block_Start + Ext_Total_Len,
            Ext_Type   => Ext_Key_Share,
            Body_First => Ks_Body_F,
            Body_Last  => Ks_Body_L,
            OK         => Ks_Find_OK);
         if not Ks_Find_OK then return; end if;
         --  Skip the u16 client_shares_len.
         if Ks_Body_F + 1 > Ks_Body_L then return; end if;
         Q := Ks_Body_F + 2;
         End_Body := Ks_Body_L;
         while Q + 3 <= End_Body loop
            pragma Loop_Invariant (Q in Ks_Body_F .. End_Body + 1);
            Group_Code := Natural (In_Bytes (Q)) * 256
                          + Natural (In_Bytes (Q + 1));
            Key_Exch_Len := Natural (In_Bytes (Q + 2)) * 256
                            + Natural (In_Bytes (Q + 3));
            if Q + 3 + Key_Exch_Len > End_Body then return; end if;
            if Group_Code = 16#001D# and then Key_Exch_Len = 32 then
               Key_Share_First := Q + 4;
               Key_Share_Last  := Q + 4 + 31;
               Found := True;
               exit;
            end if;
            Q := Q + 4 + Key_Exch_Len;
         end loop;
         if not Found then return; end if;
      end;

      --  Validate psk_key_exchange_modes contains psk_dhe_ke (= 1).
      --  Mode 0 (psk_ke) is not accepted; if the client only offers
      --  mode 0 the server returns OK = False (caller fails the
      --  handshake — illegal_parameter equivalent).
      declare
         Modes_Body_F, Modes_Body_L : Natural;
         Modes_Find_OK : Boolean;
         Modes_Len : Natural;
         I : Natural;
         Has_Dhe : Boolean := False;
      begin
         Find_Extension
           (In_Bytes   => In_Bytes,
            Pos        => Ext_Block_Start,
            End_Pos    => Ext_Block_Start + Ext_Total_Len,
            Ext_Type   => Ext_Psk_Key_Exchange_Modes,
            Body_First => Modes_Body_F,
            Body_Last  => Modes_Body_L,
            OK         => Modes_Find_OK);
         if not Modes_Find_OK then return; end if;
         if Modes_Body_F > Modes_Body_L then return; end if;
         Modes_Len := Natural (In_Bytes (Modes_Body_F));
         if Modes_Len = 0
           or else Modes_Body_F + Modes_Len > Modes_Body_L
         then
            return;
         end if;
         I := Modes_Body_F + 1;
         while I <= Modes_Body_F + Modes_Len loop
            pragma Loop_Invariant
              (I in Modes_Body_F + 1 .. Modes_Body_F + Modes_Len + 1);
            if In_Bytes (I) = 16#01# then
               Has_Dhe := True;
               exit;
            end if;
            I := I + 1;
         end loop;
         if not Has_Dhe then return; end if;
      end;

      OK := True;
   end Decode_Client_Hello_Psk;

   procedure Encode_Server_Hello_Psk
     (Random         : Random_Bytes;
      Selected_Suite : Tls_Core.Suites.U16;
      Key_Share      : Public_Key;
      Out_Buf        : out Octet_Array;
      Out_Last       : out Natural)
   is
      use type Tls_Core.Suites.U16;
      Cursor          : Natural := 0;
      Ext_Len_Pos     : Natural;
      Ext_Body_Start  : Natural;
      Suite_Hi        : constant Octet :=
        Octet (Selected_Suite / 16#0100#);
      Suite_Lo        : constant Octet :=
        Octet (Selected_Suite mod 16#0100#);
   begin
      Out_Buf := (others => 0);
      W_U8 (Out_Buf, Cursor, 16#03#);
      W_U8 (Out_Buf, Cursor, 16#03#);
      W_Bytes (Out_Buf, Cursor, Random);
      W_U8 (Out_Buf, Cursor, 0);              -- session_id_len
      W_U8 (Out_Buf, Cursor, Suite_Hi);       -- selected cipher suite
      W_U8 (Out_Buf, Cursor, Suite_Lo);
      W_U8 (Out_Buf, Cursor, 0);              -- compression_method
      Cursor := Cursor + 1;
      Ext_Len_Pos := Cursor;
      Cursor := Cursor + 1;
      Ext_Body_Start := Cursor + 1;

      --  supported_versions = TLS 1.3.
      declare
         Body_Bytes : constant Octet_Array (1 .. 2) :=
           (1 => 16#03#, 2 => 16#04#);
      begin
         Encode_Extension
           (Out_Buf, Cursor, Ext_Supported_Versions, Body_Bytes);
      end;

      --  key_share — RFC 8446 §4.2.8 SH layout (no list_len prefix —
      --  exactly one KeyShareEntry):
      --      u16 group, u16 key_exch_len, key_exch
      declare
         Body_Bytes : Octet_Array (1 .. 2 + 2 + 32) := (others => 0);
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
         Body_Bytes : constant Octet_Array (1 .. 2) :=
           (1 => 16#00#, 2 => 16#00#);
      begin
         Encode_Extension
           (Out_Buf, Cursor, Ext_Pre_Shared_Key, Body_Bytes);
      end;

      Patch_U16 (Out_Buf, Ext_Len_Pos, Cursor - Ext_Body_Start + 1);
      Out_Last := Cursor;
   end Encode_Server_Hello_Psk;

   ---------------------------------------------------------------------
   --  Encode_Client_Hello_Cert (RFC 8446 §4.1.2 cert-mode CH —
   --  no pre_shared_key, no psk_key_exchange_modes, plus
   --  signature_algorithms per §4.2.3).
   ---------------------------------------------------------------------

   procedure Encode_Client_Hello_Cert
     (Random          : Random_Bytes;
      Key_Share       : Public_Key;
      Server_Name     : Octet_Array;
      Alpn_Offers     : Octet_Array;
      Out_Buf         : out Octet_Array;
      Out_Last        : out Natural)
   is
      Cursor          : Natural := 0;
      Ext_Len_Pos     : Natural;
      Ext_Body_Start  : Natural;
   begin
      Out_Buf := (others => 0);

      --  legacy_version, random, session_id, cipher_suites,
      --  legacy_compression_methods.
      W_U8 (Out_Buf, Cursor, 16#03#);
      W_U8 (Out_Buf, Cursor, 16#03#);
      W_Bytes (Out_Buf, Cursor, Random);
      W_U8 (Out_Buf, Cursor, 0);                  -- session_id_len
      W_U16 (Out_Buf, Cursor, 6);                 -- 3 suites × 2 bytes
      W_U8 (Out_Buf, Cursor, 16#13#);             -- TLS_CHACHA20_POLY1305_SHA256
      W_U8 (Out_Buf, Cursor, 16#03#);
      W_U8 (Out_Buf, Cursor, 16#13#);             -- TLS_AES_128_GCM_SHA256
      W_U8 (Out_Buf, Cursor, 16#01#);
      W_U8 (Out_Buf, Cursor, 16#13#);             -- TLS_AES_256_GCM_SHA384
      W_U8 (Out_Buf, Cursor, 16#02#);
      W_U8 (Out_Buf, Cursor, 1);                  -- compression_methods length
      W_U8 (Out_Buf, Cursor, 0);                  -- compression null

      --  Extensions block — patch length after.
      Cursor := Cursor + 1;
      Ext_Len_Pos := Cursor;
      Cursor := Cursor + 1;
      Ext_Body_Start := Cursor + 1;

      --  supported_versions = TLS 1.3.
      declare
         Body_Bytes : constant Octet_Array (1 .. 3) :=
           (1 => 16#02#, 2 => 16#03#, 3 => 16#04#);
      begin
         Encode_Extension
           (Out_Buf, Cursor, Ext_Supported_Versions, Body_Bytes);
      end;

      --  supported_groups = [x25519]. RFC 8446 §4.2.7.
      declare
         Body_Bytes : constant Octet_Array (1 .. 4) :=
           (1 => 16#00#, 2 => 16#02#,
            3 => Named_Group_Hi, 4 => Named_Group_Lo);
      begin
         Encode_Extension
           (Out_Buf, Cursor, Ext_Supported_Groups, Body_Bytes);
      end;

      --  server_name (RFC 6066 §3 / RFC 8446 §4.2.10).
      if Server_Name'Length > 0 then
         declare
            Sni_Body : Octet_Array (1 .. 5 + Server_Name'Length) :=
              (others => 0);
            Sni_Body_Last : Natural;
         begin
            Tls_Core.Extensions.Encode_Server_Name
              (Server_Name, Sni_Body, Sni_Body_Last);
            Encode_Extension
              (Out_Buf, Cursor, Ext_Server_Name,
               Sni_Body (1 .. Sni_Body_Last));
         end;
      end if;

      --  application_layer_protocol_negotiation (RFC 7301).
      if Alpn_Offers'Length > 0 then
         declare
            Alpn_Body : Octet_Array (1 .. 2 + Alpn_Offers'Length) :=
              (others => 0);
            Alpn_Body_Last : Natural;
         begin
            Tls_Core.Extensions.Encode_Alpn
              (Alpn_Offers, Alpn_Body, Alpn_Body_Last);
            Encode_Extension
              (Out_Buf, Cursor, Ext_Alpn,
               Alpn_Body (1 .. Alpn_Body_Last));
         end;
      end if;

      --  key_share = [{x25519, 32-byte u-coord}]. RFC 8446 §4.2.8.
      declare
         Body_Bytes : Octet_Array (1 .. 2 + 2 + 2 + 32) := (others => 0);
      begin
         Body_Bytes (1) := 16#00#;
         Body_Bytes (2) := 16#26#;        --  client_shares total = 38
         Body_Bytes (3) := Named_Group_Hi;
         Body_Bytes (4) := Named_Group_Lo;
         Body_Bytes (5) := 16#00#;
         Body_Bytes (6) := 16#20#;        --  key_exchange length = 32
         Body_Bytes (7 .. 38) := Key_Share;
         Encode_Extension (Out_Buf, Cursor, Ext_Key_Share, Body_Bytes);
      end;

      --  signature_algorithms (RFC 8446 §4.2.3).
      --  v0.5 advertises ecdsa_secp256r1_sha256 (0x0403) +
      --  rsa_pss_rsae_sha256 (0x0804). list_len = 4 (2 schemes × 2B).
      declare
         Body_Bytes : constant Octet_Array (1 .. 6) :=
           (1 => 16#00#, 2 => 16#04#,            --  list_length = 4
            3 => 16#04#, 4 => 16#03#,            --  ecdsa_secp256r1_sha256
            5 => 16#08#, 6 => 16#04#);           --  rsa_pss_rsae_sha256
      begin
         Encode_Extension
           (Out_Buf, Cursor, Ext_Signature_Algorithms, Body_Bytes);
      end;

      --  Patch extensions-block length.
      Patch_U16 (Out_Buf, Ext_Len_Pos, Cursor - Ext_Body_Start + 1);
      Out_Last := Cursor;
   end Encode_Client_Hello_Cert;

   ---------------------------------------------------------------------
   --  Decode_Client_Hello_Cert (RFC 8446 §4.1.2 cert-mode CH —
   --  no pre_shared_key, no psk_key_exchange_modes; require
   --  signature_algorithms presence per §4.2.3).
   ---------------------------------------------------------------------

   procedure Decode_Client_Hello_Cert
     (In_Bytes        : Octet_Array;
      Random          : out Random_Bytes;
      Suites_First    : out Natural;
      Suites_Last     : out Natural;
      Sig_Algs_First  : out Natural;
      Sig_Algs_Last   : out Natural;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      OK              : out Boolean)
   is
      P : Natural := In_Bytes'First;
      Read_OK : Boolean := True;
      U8_Val : Octet;
      U16_Val : Natural;
      Ext_Total_Len : Natural;
      Ext_Block_Start : Natural;
   begin
      Random := (others => 0);
      Suites_First := 0;
      Suites_Last := 0;
      Sig_Algs_First := 0;
      Sig_Algs_Last := 0;
      Key_Share_First := 0;
      Key_Share_Last := 0;
      OK := False;

      --  legacy_version + random + session_id + cipher_suites +
      --  legacy_compression_methods (same shape as PSK CH).
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      if not Read_OK then return; end if;
      if P + 31 > In_Bytes'Last then return; end if;
      Random := In_Bytes (P .. P + 31);
      P := P + 32;
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      if not Read_OK then return; end if;
      if P + Natural (U8_Val) - 1 > In_Bytes'Last then return; end if;
      P := P + Natural (U8_Val);
      R_U16 (In_Bytes, P, U16_Val, Read_OK);
      if not Read_OK then return; end if;
      if U16_Val < 2 or else U16_Val mod 2 /= 0 then return; end if;
      if P + U16_Val - 1 > In_Bytes'Last then return; end if;
      Suites_First := P;
      Suites_Last  := P + U16_Val - 1;
      P := P + U16_Val;
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      if not Read_OK then return; end if;
      if P + Natural (U8_Val) - 1 > In_Bytes'Last then return; end if;
      P := P + Natural (U8_Val);
      R_U16 (In_Bytes, P, Ext_Total_Len, Read_OK);
      if not Read_OK then return; end if;
      Ext_Block_Start := P;
      if Ext_Block_Start + Ext_Total_Len - 1 > In_Bytes'Last then
         return;
      end if;

      --  signature_algorithms (RFC 8446 §4.2.3) — REQUIRED in
      --  cert-mode CH.  Body shape: u16 list_len + N x u16 schemes.
      declare
         Body_F, Body_L : Natural;
         Find_OK : Boolean;
         List_Len : Natural;
      begin
         Find_Extension
           (In_Bytes   => In_Bytes,
            Pos        => Ext_Block_Start,
            End_Pos    => Ext_Block_Start + Ext_Total_Len,
            Ext_Type   => Ext_Signature_Algorithms,
            Body_First => Body_F,
            Body_Last  => Body_L,
            OK         => Find_OK);
         if not Find_OK then return; end if;
         if Body_F + 1 > Body_L then return; end if;
         List_Len := Natural (In_Bytes (Body_F)) * 256
                     + Natural (In_Bytes (Body_F + 1));
         if List_Len < 2
           or else List_Len mod 2 /= 0
           or else Body_F + 1 + List_Len > Body_L
         then
            return;
         end if;
         Sig_Algs_First := Body_F + 2;
         Sig_Algs_Last  := Body_F + 1 + List_Len;
      end;

      --  key_share — same shape and search strategy as the PSK
      --  decoder; accept the first KeyShareEntry whose group is
      --  x25519 (0x001D) and key_exchange length is 32.
      declare
         Ks_Body_F, Ks_Body_L : Natural;
         Ks_Find_OK : Boolean;
         Q : Natural;
         Group_Code : Natural;
         Key_Exch_Len : Natural;
         End_Body : Natural;
         Found : Boolean := False;
      begin
         Find_Extension
           (In_Bytes   => In_Bytes,
            Pos        => Ext_Block_Start,
            End_Pos    => Ext_Block_Start + Ext_Total_Len,
            Ext_Type   => Ext_Key_Share,
            Body_First => Ks_Body_F,
            Body_Last  => Ks_Body_L,
            OK         => Ks_Find_OK);
         if not Ks_Find_OK then return; end if;
         if Ks_Body_F + 1 > Ks_Body_L then return; end if;
         Q := Ks_Body_F + 2;
         End_Body := Ks_Body_L;
         while Q + 3 <= End_Body loop
            pragma Loop_Invariant (Q in Ks_Body_F .. End_Body + 1);
            Group_Code := Natural (In_Bytes (Q)) * 256
                          + Natural (In_Bytes (Q + 1));
            Key_Exch_Len := Natural (In_Bytes (Q + 2)) * 256
                            + Natural (In_Bytes (Q + 3));
            if Q + 3 + Key_Exch_Len > End_Body then return; end if;
            if Group_Code = 16#001D# and then Key_Exch_Len = 32 then
               Key_Share_First := Q + 4;
               Key_Share_Last  := Q + 4 + 31;
               Found := True;
               exit;
            end if;
            Q := Q + 4 + Key_Exch_Len;
         end loop;
         if not Found then return; end if;
      end;

      OK := True;
   end Decode_Client_Hello_Cert;

   ---------------------------------------------------------------------
   --  Encode_Server_Hello_Cert (RFC 8446 §4.1.3 cert-mode SH —
   --  identical to the PSK SH minus the pre_shared_key extension).
   ---------------------------------------------------------------------

   procedure Encode_Server_Hello_Cert
     (Random         : Random_Bytes;
      Selected_Suite : Tls_Core.Suites.U16;
      Key_Share      : Public_Key;
      Out_Buf        : out Octet_Array;
      Out_Last       : out Natural)
   is
      use type Tls_Core.Suites.U16;
      Cursor          : Natural := 0;
      Ext_Len_Pos     : Natural;
      Ext_Body_Start  : Natural;
      Suite_Hi        : constant Octet :=
        Octet (Selected_Suite / 16#0100#);
      Suite_Lo        : constant Octet :=
        Octet (Selected_Suite mod 16#0100#);
   begin
      Out_Buf := (others => 0);
      W_U8 (Out_Buf, Cursor, 16#03#);
      W_U8 (Out_Buf, Cursor, 16#03#);
      W_Bytes (Out_Buf, Cursor, Random);
      W_U8 (Out_Buf, Cursor, 0);              -- session_id_len
      W_U8 (Out_Buf, Cursor, Suite_Hi);       -- selected cipher suite
      W_U8 (Out_Buf, Cursor, Suite_Lo);
      W_U8 (Out_Buf, Cursor, 0);              -- compression_method
      Cursor := Cursor + 1;
      Ext_Len_Pos := Cursor;
      Cursor := Cursor + 1;
      Ext_Body_Start := Cursor + 1;

      --  supported_versions = TLS 1.3.
      declare
         Body_Bytes : constant Octet_Array (1 .. 2) :=
           (1 => 16#03#, 2 => 16#04#);
      begin
         Encode_Extension
           (Out_Buf, Cursor, Ext_Supported_Versions, Body_Bytes);
      end;

      --  key_share — same SH layout as the PSK case (one
      --  KeyShareEntry, no list_len prefix).
      declare
         Body_Bytes : Octet_Array (1 .. 2 + 2 + 32) := (others => 0);
      begin
         Body_Bytes (1) := Named_Group_Hi;
         Body_Bytes (2) := Named_Group_Lo;
         Body_Bytes (3) := 16#00#;
         Body_Bytes (4) := 16#20#;
         Body_Bytes (5 .. 36) := Key_Share;
         Encode_Extension (Out_Buf, Cursor, Ext_Key_Share, Body_Bytes);
      end;

      Patch_U16 (Out_Buf, Ext_Len_Pos, Cursor - Ext_Body_Start + 1);
      Out_Last := Cursor;
   end Encode_Server_Hello_Cert;

   ---------------------------------------------------------------------
   --  Decode_Server_Hello_Psk_Key_Share
   ---------------------------------------------------------------------

   procedure Decode_Server_Hello_Psk_Key_Share
     (In_Bytes        : Octet_Array;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      OK              : out Boolean)
   is
      P : Natural := In_Bytes'First;
      Read_OK : Boolean := True;
      U8_Val : Octet;
      Ext_Total_Len : Natural;
      Ext_Block_Start : Natural;
      Body_F, Body_L : Natural;
      Find_OK : Boolean;
   begin
      Key_Share_First := 0;
      Key_Share_Last := 0;
      OK := False;

      --  legacy_version (2)
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      if not Read_OK then return; end if;
      --  random (32)
      if P + 31 > In_Bytes'Last then return; end if;
      P := P + 32;
      --  legacy_session_id (u8 len + N)
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      if not Read_OK then return; end if;
      if P + Natural (U8_Val) - 1 > In_Bytes'Last then return; end if;
      P := P + Natural (U8_Val);
      --  cipher_suite (u16)
      if P + 1 > In_Bytes'Last then return; end if;
      P := P + 2;
      --  legacy_compression_method (u8)
      R_U8 (In_Bytes, P, U8_Val, Read_OK);
      if not Read_OK then return; end if;
      --  Extensions
      R_U16 (In_Bytes, P, Ext_Total_Len, Read_OK);
      if not Read_OK then return; end if;
      Ext_Block_Start := P;
      if Ext_Block_Start + Ext_Total_Len - 1 > In_Bytes'Last then return; end if;

      Find_Extension
        (In_Bytes => In_Bytes,
         Pos => Ext_Block_Start,
         End_Pos => Ext_Block_Start + Ext_Total_Len,
         Ext_Type => Ext_Key_Share,
         Body_First => Body_F,
         Body_Last => Body_L,
         OK => Find_OK);
      if not Find_OK then return; end if;
      --  SH key_share body: u16 group, u16 key_exch_len, key_exch
      if Body_L - Body_F + 1 < 4 + 32 then return; end if;
      --  Validate group = x25519 (0x001D) and length = 32.
      if In_Bytes (Body_F) /= Named_Group_Hi
        or else In_Bytes (Body_F + 1) /= Named_Group_Lo
        or else In_Bytes (Body_F + 2) /= 16#00#
        or else In_Bytes (Body_F + 3) /= 16#20#
      then
         return;
      end if;
      Key_Share_First := Body_F + 4;
      Key_Share_Last := Body_F + 4 + 31;
      OK := True;
   end Decode_Server_Hello_Psk_Key_Share;

end Tls_Core.Hello;
