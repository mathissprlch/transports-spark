package body Tls_Core.Hello
with SPARK_Mode => Off
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

end Tls_Core.Hello;
