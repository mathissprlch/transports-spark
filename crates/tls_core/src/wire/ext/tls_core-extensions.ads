--  Tls_Core.Extensions — SPARK-clean encoders/decoders for the TLS
--  1.3 extensions outside the v0.5 minimal handshake set:
--
--    server_name (RFC 6066 §3 / RFC 8446 §4.2.10) — host_name only
--    application_layer_protocol_negotiation (RFC 7301)
--
--  Each operation encodes/decodes the extension *body* (the bytes
--  inside the `extension_data<0..2^16-1>` field), not the
--  extension_type / outer length wrapper. The caller (handshake
--  driver) prepends `extension_type` (u16) and the outer length
--  (u16). This keeps these helpers reusable across CH / SH / EE.

package Tls_Core.Extensions
  with SPARK_Mode
is

   --  Maximum host name (RFC 1035 §2.3.4 — 255 bytes).
   Max_Host_Name : constant Natural := 255;

   --  Maximum ALPN protocol-name byte (single name <= 255).
   Max_Alpn_Name : constant Natural := 255;

   --  Encode an SNI extension body for a single host_name. The
   --  body layout (RFC 6066 §3):
   --    ServerNameList server_name_list<1..2^16-1>:
   --      u16 list_length      (length of the list bytes that follow)
   --      ServerName:
   --        u8  name_type = 0x00 (host_name)
   --        u16 host_name_length
   --        N   host_name bytes
   --
   --  Imperative Post: Out_Last = the encoded body length.
   procedure Encode_Server_Name
     (Host_Name : Octet_Array;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   with
     Pre  =>
       Host_Name'Length in 1 .. Max_Host_Name
       and then Host_Name'Last < Integer'Last
       and then Out_Buf'First = 1
       and then Out_Buf'Length >= 5 + Host_Name'Length,
     Post => Out_Last = 5 + Host_Name'Length;

   --  Decode an SNI extension body. Returns OK = False on any
   --  parse error or if the only ServerName isn't host_name.
   procedure Decode_Server_Name
     (Buf        : Octet_Array;
      OK         : out Boolean;
      Host_First : out Natural;
      Host_Last  : out Natural)
   with Pre => Buf'First = 1 and then Buf'Length <= 65535;

   --  Encode an ALPN extension body from a "1 || name1 || 1 ||
   --  name2 ..." flat layout: each ProtocolName is preceded by its
   --  u8 length. The full ProtocolNameList<2..2^16-1> wrapper
   --  is computed here.
   --
   --  Body layout (RFC 7301):
   --    ProtocolNameList protocol_name_list<2..2^16-1>:
   --      u16 list_length
   --      ProtocolName names[]:
   --        u8 name_length
   --        N  name bytes
   --
   --  Names_Buf MUST already contain the concatenated u8-prefixed
   --  ProtocolName entries; the caller is responsible for that
   --  layout. We just wrap with the u16 list_length.
   procedure Encode_Alpn
     (Names_Buf : Octet_Array;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   with
     Pre  =>
       Names_Buf'Length in 2 .. 65535
       and then Names_Buf'Last < Integer'Last
       and then Out_Buf'First = 1
       and then Out_Buf'Length >= 2 + Names_Buf'Length,
     Post => Out_Last = 2 + Names_Buf'Length;

   --  Decode an ALPN extension body, returning the slice that
   --  contains the concatenated u8-prefixed ProtocolName entries.
   --  On the server side this is what we'd hand back to the
   --  application policy to pick a single ProtocolName.
   procedure Decode_Alpn
     (Buf         : Octet_Array;
      OK          : out Boolean;
      Names_First : out Natural;
      Names_Last  : out Natural)
   with Pre => Buf'First = 1 and then Buf'Length <= 65535;

   --  Encode a single ProtocolName entry into Out_Buf as `u8 N || N
   --  name bytes`. Useful for building Names_Buf from a list of
   --  protocol-name byte strings.
   procedure Append_Alpn_Name
     (Name    : Octet_Array;
      Out_Buf : in out Octet_Array;
      Cursor  : in out Natural)
   with
     Pre  =>
       Name'Length in 1 .. Max_Alpn_Name
       and then Out_Buf'First = 1
       and then Cursor in 0 .. Out_Buf'Length - 1 - Name'Length,
     Post => Cursor = Cursor'Old + 1 + Name'Length;

end Tls_Core.Extensions;
