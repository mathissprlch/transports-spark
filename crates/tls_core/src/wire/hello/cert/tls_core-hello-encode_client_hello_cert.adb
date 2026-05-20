separate (Tls_Core.Hello)
procedure Encode_Client_Hello_Cert
  (Random      : Random_Bytes;
   Key_Share   : Public_Key;
   Server_Name : Octet_Array;
   Alpn_Offers : Octet_Array;
   Out_Buf     : out Octet_Array;
   Out_Last    : out Natural)
is
   Cursor         : Natural := 0;
   Ext_Len_Pos    : Natural;
   Ext_Body_Start : Natural;
begin
   Out_Buf := [others => 0];

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
        [1 => 16#02#, 2 => 16#03#, 3 => 16#04#];
   begin
      Encode_Extension (Out_Buf, Cursor, Ext_Supported_Versions, Body_Bytes);
   end;

   --  supported_groups = [x25519]. RFC 8446 §4.2.7.
   declare
      Body_Bytes : constant Octet_Array (1 .. 4) :=
        [1 => 16#00#, 2 => 16#02#, 3 => Named_Group_Hi, 4 => Named_Group_Lo];
   begin
      Encode_Extension (Out_Buf, Cursor, Ext_Supported_Groups, Body_Bytes);
   end;

   --  server_name (RFC 6066 §3 / RFC 8446 §4.2.10).
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

   --  application_layer_protocol_negotiation (RFC 7301).
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

   --  key_share = [{x25519, 32-byte u-coord}]. RFC 8446 §4.2.8.
   declare
      Body_Bytes : Octet_Array (1 .. 2 + 2 + 2 + 32) := [others => 0];
   begin
      Body_Bytes (1) := 16#00#;
      Body_Bytes (2) := 16#24#;        --  client_shares total = 38
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
        [1 => 16#00#,
         2 => 16#04#,
         --  list_length = 4
         3 => 16#04#,
         4 => 16#03#,
         --  ecdsa_secp256r1_sha256
         5 => 16#08#,
         6 => 16#04#];           --  rsa_pss_rsae_sha256
   begin
      Encode_Extension (Out_Buf, Cursor, Ext_Signature_Algorithms, Body_Bytes);
   end;

   --  psk_key_exchange_modes = [psk_dhe_ke (1)]. RFC 8446 §4.2.9.
   --
   --  Strictly conditional in §4.2.9 ("MUST be included when
   --  offering PSK"), so omitting it in a cert-mode CH is
   --  RFC-conformant.  However: every production TLS 1.3 client
   --  (openssl s_client, BoringSSL bssl client, gnutls-cli,
   --  Go crypto/tls, Chromium net stack) emits this extension
   --  unconditionally — it's part of the production CH shape per
   --  docs/conventions.md §0a "production-only scope" rule.  BoringSSL's
   --  `bssl server` example tool refuses to flush its server
   --  flight without it (TCP send queue stays empty despite the
   --  internal state machine reaching send_server_finished);
   --  openssl/gnutls/mbedtls/wolfssl are lenient.  Including it
   --  unconditionally costs 6 bytes and unblocks the bssl c2s
   --  matrix column.
   declare
      Body_Bytes : constant Octet_Array (1 .. 2) :=
        [1 => 16#01#, 2 => 16#01#];  --  modes_len = 1, mode = 1
   begin
      Encode_Extension
        (Out_Buf, Cursor, Ext_Psk_Key_Exchange_Modes, Body_Bytes);
   end;

   --  Patch extensions-block length.
   Patch_U16 (Out_Buf, Ext_Len_Pos, Cursor - Ext_Body_Start + 1);
   Out_Last := Cursor;
end Encode_Client_Hello_Cert;
