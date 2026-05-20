separate (Tls_Core.Hello)
procedure Encode_Client_Hello_Psk
  (Random         : Random_Bytes;
   Identity       : Octet_Array;
   Key_Share      : Public_Key;
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

   --  server_name (RFC 6066 §3 / RFC 8446 §4.2.10) — host_name
   --  only.  Emitted only when Server_Name is non-empty;
   --  Tls_Core.Extensions.Encode_Server_Name builds the
   --  ServerNameList body (5 + N bytes), we wrap it with the
   --  extension_type + extension_data length via Encode_Extension.
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

   --  application_layer_protocol_negotiation (RFC 7301 / RFC 8446
   --  §4.2).  Encode_Alpn wraps the caller-flattened Names_Buf
   --  with the u16 list_length; we wrap that with the
   --  extension_type + extension_data length.
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

   --  signature_algorithms — RFC 8446 §4.2.3 / §9.2 require it
   --  in every CH (incl. resumption-PSK CHs, which openssl
   --  rejects with "missing sigalgs extension" otherwise).  We
   --  list ecdsa_secp256r1_sha256 + rsa_pss_rsae_sha256 to match
   --  the cert-mode CH encoder.
   declare
      Body_Bytes : constant Octet_Array (1 .. 6) :=
        [1 => 16#00#,
         2 => 16#04#,
         3 => 16#04#,
         4 => 16#03#,
         --  ecdsa_secp256r1_sha256
         5 => 16#08#,
         6 => 16#04#];   --  rsa_pss_rsae_sha256
   begin
      Encode_Extension (Out_Buf, Cursor, Ext_Signature_Algorithms, Body_Bytes);
   end;

   --  key_share = [{x25519, 32-byte u-coord}]. RFC 8446 §4.2.8.
   --  CH layout: u16 client_shares_len + KeyShareEntry{
   --      u16 group, u16 key_exch_len, key_exch (32 bytes for x25519)
   --  }.
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

   --  psk_key_exchange_modes = [psk_dhe_ke (1)]. RFC 8446 §4.2.9.
   --  Mode 0 (psk_ke) is RFC-discouraged + production-rejected;
   --  v0.5 advertises mode 1 only (docs/conventions.md §0a).
   declare
      Body_Bytes : constant Octet_Array (1 .. 2) :=
        [1 => 16#01#, 2 => 16#01#];  --  modes_len = 1, mode = 1 (psk_dhe_ke)
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
        2
        + 1
        + 32;                   --  list_len_field + binder_len + 32 bytes
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
      --  RFC 8446 §4.2.11.2: the binder hash covers the CH "up to
      --  and including the PreSharedKeyExtension.identities field"
      --  — i.e. the entire binders<> field (including its u16
      --  length prefix) is excluded.  Truncate point is HERE,
      --  before we write binders_total_len.
      Truncated_Last := Cursor;
      --  binders<> field: u16 binders_total_len + per-binder
      --  { u8 binder_len; binder_bytes }. We emit one binder.
      W_U16 (Out_Buf, Cursor, 1 + 32);
      W_U8 (Out_Buf, Cursor, 32);
      Cursor := Cursor + 32;
   end;

   --  Patch extensions-block length.
   Patch_U16 (Out_Buf, Ext_Len_Pos, Cursor - Ext_Body_Start + 1);
   Out_Last := Cursor;
end Encode_Client_Hello_Psk;
