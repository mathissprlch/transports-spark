with Tls_Core.Extensions;
with Tls_Core.Hello.Prims; use Tls_Core.Hello.Prims;

package body Tls_Core.Hello
  with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;

   --  Constants for the cipher suite + named group we negotiate.
   Cipher_Suite_Hi : constant Octet := 16#13#;
   Cipher_Suite_Lo : constant Octet :=
     16#03#;  --  TLS_CHACHA20_POLY1305_SHA256

   Named_Group_Hi : constant Octet := 16#00#;
   Named_Group_Lo : constant Octet := 16#1D#;  --  x25519

   Sig_Alg_Hi : constant Octet := 16#08#;
   Sig_Alg_Lo : constant Octet := 16#07#;  --  ed25519

   Ext_Supported_Versions   : constant := 16#002B#;
   Ext_Key_Share            : constant := 16#0033#;
   Ext_Supported_Groups     : constant := 16#000A#;
   Ext_Signature_Algorithms : constant := 16#000D#;
   Ext_Server_Name          : constant := 16#0000#;  --  RFC 6066 §3
   Ext_Alpn                 : constant := 16#0010#;  --  RFC 7301

   ---------------------------------------------------------------------
   --  Encode_Client_Hello
   ---------------------------------------------------------------------

   procedure Encode_Client_Hello
     (CH : Client_Hello; Out_Buf : out Octet_Array; Out_Last : out Natural)
   is separate;

   ---------------------------------------------------------------------
   --  Encode_Server_Hello
   ---------------------------------------------------------------------

   procedure Encode_Server_Hello
     (SH : Server_Hello; Out_Buf : out Octet_Array; Out_Last : out Natural)
   is separate;

   ---------------------------------------------------------------------
   --  Decode_Client_Hello
   ---------------------------------------------------------------------

   procedure Decode_Client_Hello
     (In_Bytes : Octet_Array; CH : out Client_Hello; OK : out Boolean)
   is separate;

   ---------------------------------------------------------------------
   --  Decode_Server_Hello
   ---------------------------------------------------------------------

   procedure Decode_Server_Hello
     (In_Bytes : Octet_Array; SH : out Server_Hello; OK : out Boolean)
   is separate;

   ------------------------------------------------------------------
   --  PSK-profile encode/decode
   ------------------------------------------------------------------

   Ext_Psk_Key_Exchange_Modes : constant := 16#002D#;
   Ext_Pre_Shared_Key         : constant := 16#0029#;

   procedure Encode_Client_Hello_Psk
     (Random         : Random_Bytes;
      Identity       : Octet_Array;
      Key_Share      : Public_Key;
      Server_Name    : Octet_Array;
      Alpn_Offers    : Octet_Array;
      Out_Buf        : out Octet_Array;
      Out_Last       : out Natural;
      Truncated_Last : out Natural)
   is separate;

   ---------------------------------------------------------------------
   --  Encode_Client_Hello_Psk_With_Cookie — RFC 8446 §4.1.4 / §4.2.2
   --  CH2 emission after HRR. Same shape as Encode_Client_Hello_Psk
   --  with one additional cookie extension inserted between
   --  psk_key_exchange_modes and the (mandatory-last) pre_shared_key.
   ---------------------------------------------------------------------

   Ext_Cookie : constant := 16#002C#;

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
   is separate;

   procedure Decode_Client_Hello_Psk
     (In_Bytes         : Octet_Array;
      Random           : out Random_Bytes;
      Session_Id_First : out Natural;
      Session_Id_Last  : out Natural;
      Suites_First     : out Natural;
      Suites_Last      : out Natural;
      Identity_First   : out Natural;
      Identity_Last    : out Natural;
      Binder_First     : out Natural;
      Binder_Last      : out Natural;
      Key_Share_First  : out Natural;
      Key_Share_Last   : out Natural;
      Truncated_Last   : out Natural;
      OK               : out Boolean)
   is separate;

   procedure Encode_Server_Hello_Psk
     (Random          : Random_Bytes;
      Session_Id_Echo : Octet_Array;
      Selected_Suite  : Tls_Core.Suites.U16;
      Key_Share       : Public_Key;
      Out_Buf         : out Octet_Array;
      Out_Last        : out Natural)
   is separate;

   ---------------------------------------------------------------------
   --  Encode_Client_Hello_Cert (RFC 8446 §4.1.2 cert-mode CH —
   --  no pre_shared_key, no psk_key_exchange_modes, plus
   --  signature_algorithms per §4.2.3).
   ---------------------------------------------------------------------

   procedure Encode_Client_Hello_Cert
     (Random      : Random_Bytes;
      Key_Share   : Public_Key;
      Server_Name : Octet_Array;
      Alpn_Offers : Octet_Array;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   is separate;

   ---------------------------------------------------------------------
   --  Decode_Client_Hello_Cert (RFC 8446 §4.1.2 cert-mode CH —
   --  no pre_shared_key, no psk_key_exchange_modes; require
   --  signature_algorithms presence per §4.2.3).
   ---------------------------------------------------------------------

   procedure Decode_Client_Hello_Cert
     (In_Bytes         : Octet_Array;
      Random           : out Random_Bytes;
      Session_Id_First : out Natural;
      Session_Id_Last  : out Natural;
      Suites_First     : out Natural;
      Suites_Last      : out Natural;
      Sig_Algs_First   : out Natural;
      Sig_Algs_Last    : out Natural;
      Key_Share_First  : out Natural;
      Key_Share_Last   : out Natural;
      OK               : out Boolean)
   is separate;

   ---------------------------------------------------------------------
   --  Encode_Server_Hello_Cert (RFC 8446 §4.1.3 cert-mode SH —
   --  identical to the PSK SH minus the pre_shared_key extension).
   ---------------------------------------------------------------------

   procedure Encode_Server_Hello_Cert
     (Random          : Random_Bytes;
      Session_Id_Echo : Octet_Array;
      Selected_Suite  : Tls_Core.Suites.U16;
      Key_Share       : Public_Key;
      Out_Buf         : out Octet_Array;
      Out_Last        : out Natural)
   is separate;

   ---------------------------------------------------------------------
   --  Decode_Server_Hello_Psk_Key_Share
   ---------------------------------------------------------------------

   procedure Decode_Server_Hello_Psk_Key_Share
     (In_Bytes        : Octet_Array;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      OK              : out Boolean)
   is separate;

end Tls_Core.Hello;
