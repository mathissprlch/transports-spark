--  Tls_Core.Cert — body. Pure-Ada SPARK DER walker for X.509 v3.
--
--  Same Read_Tlv shape as Tls_Core.X509: a tag + length parser that
--  returns absolute indices and a "next position" cursor. We add
--  inner walkers to find the SubjectAltName extension.
--
--  Lookup: RFC 5280 §4.1 + RFC 5912 OIDs:
--    ecdsa-with-SHA256       30 0A 06 08 2A 86 48 CE 3D 04 03 02
--    rsassaPss               30 ?? 06 09 2A 86 48 86 F7 0D 01 01 0A ...
--    id-ce-subjectAltName    06 03 55 1D 11

package body Tls_Core.Cert
  with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;

   --  ASN.1 DER tag bytes we care about.
   Tag_Sequence   : constant Octet := 16#30#;
   Tag_Bit_String : constant Octet := 16#03#;
   Tag_Octet_Str  : constant Octet := 16#04#;
   Tag_Integer    : constant Octet := 16#02#;
   Tag_Oid        : constant Octet := 16#06#;
   Tag_Boolean    : constant Octet := 16#01#;
   Tag_Context_0  : constant Octet := 16#A0#;
   Tag_Context_3  : constant Octet := 16#A3#;
   Tag_Dns_Name   : constant Octet := 16#82#;  --  GeneralName [2] IMPLICIT

   --  Algorithm OIDs we recognise as the OUTER signature algorithm.
   --
   --  ecdsa-with-SHA256: 1.2.840.10045.4.3.2
   --      OID-only TLV: 06 08 2A 86 48 CE 3D 04 03 02      (10 bytes)
   Oid_Ecdsa_Sha256_Tlv : constant Octet_Array (1 .. 10) :=
     (16#06#,
      16#08#,
      16#2A#,
      16#86#,
      16#48#,
      16#CE#,
      16#3D#,
      16#04#,
      16#03#,
      16#02#);

   --  rsassaPss: 1.2.840.113549.1.1.10
   --      OID-only TLV: 06 09 2A 86 48 86 F7 0D 01 01 0A    (11 bytes)
   Oid_Rsa_Pss_Tlv : constant Octet_Array (1 .. 11) :=
     (16#06#,
      16#09#,
      16#2A#,
      16#86#,
      16#48#,
      16#86#,
      16#F7#,
      16#0D#,
      16#01#,
      16#01#,
      16#0A#);

   --  id-ce-subjectAltName: 2.5.29.17
   --      OID-only TLV: 06 03 55 1D 11
   Oid_San_Tlv : constant Octet_Array (1 .. 5) :=
     (16#06#, 16#03#, 16#55#, 16#1D#, 16#11#);

   ---------------------------------------------------------------------
   --  Read a single ASN.1 DER TLV header at Buf (Pos).
   --
   --    On success:
   --      OK         := True,
   --      Tag        := tag byte,
   --      Value_Pos  := first byte of the TLV value (V),
   --      Value_Len  := length of V in bytes,
   --      Next_Pos   := Value_Pos + Value_Len.
   ---------------------------------------------------------------------
   procedure Read_Tlv
     (Buf       : Octet_Array;
      Pos       : Natural;
      Tag       : out Octet;
      Value_Pos : out Natural;
      Value_Len : out Natural;
      Next_Pos  : out Natural;
      OK        : out Boolean)
   with
     Pre  => Buf'First = 1 and then Buf'Last < Integer'Last - 16,
     Post =>
       (if OK
        then
          Value_Pos > Pos
          and then Value_Pos in Buf'First .. Buf'Last + 1
          and then Value_Len <= Buf'Length
          and then (if Value_Len > 0
                    then
                      Value_Pos in Buf'Range
                      and then Value_Pos + Value_Len - 1 in Buf'Range)
          and then Next_Pos = Value_Pos + Value_Len
          and then Next_Pos in Buf'First .. Buf'Last + 1
          and then Next_Pos > Pos);

   procedure Read_Tlv
     (Buf       : Octet_Array;
      Pos       : Natural;
      Tag       : out Octet;
      Value_Pos : out Natural;
      Value_Len : out Natural;
      Next_Pos  : out Natural;
      OK        : out Boolean)
   is separate;

   ---------------------------------------------------------------------
   --  Slice equality: Buf (Pos .. Pos+Ref'Length-1) = Ref ?
   ---------------------------------------------------------------------
   function Equal_At
     (Buf : Octet_Array; Pos : Natural; Reference : Octet_Array) return Boolean
   with
     Pre =>
       Buf'First = 1
       and then Buf'Last < Integer'Last - 16
       and then Reference'First = 1
       and then Reference'Last < Integer'Last - 16;

   function Equal_At
     (Buf : Octet_Array; Pos : Natural; Reference : Octet_Array) return Boolean
   is
   begin
      if Reference'Length = 0 then
         return True;
      end if;
      if Pos < Buf'First
        or else Pos > Buf'Last
        or else Reference'Length - 1 > Buf'Last - Pos
      then
         return False;
      end if;
      for I in 0 .. Reference'Length - 1 loop
         if Buf (Pos + I) /= Reference (Reference'First + I) then
            return False;
         end if;
      end loop;
      return True;
   end Equal_At;

   ---------------------------------------------------------------------
   --  Find the SubjectAltName extension inside the v3 extensions
   --  list given a cursor pointing at the [3] EXPLICIT context tag.
   --
   --  Sets Found = True and outputs the SAN OCTET STRING body span
   --  if the extension is present. The OCTET STRING body is the
   --  DER-encoded SEQUENCE OF GeneralName.
   ---------------------------------------------------------------------
   procedure Find_SAN_Ext
     (Buf       : Octet_Array;
      Ext_Pos   : Natural;
      Found     : out Boolean;
      San_First : out Natural;
      San_Last  : out Natural)
   with
     Pre  => Buf'First = 1 and then Buf'Last < Integer'Last - 16,
     Post =>
       (if Found
        then
          San_First in Buf'Range
          and then San_Last in Buf'Range
          and then San_First <= San_Last);

   procedure Find_SAN_Ext
     (Buf       : Octet_Array;
      Ext_Pos   : Natural;
      Found     : out Boolean;
      San_First : out Natural;
      San_Last  : out Natural)
   is separate;

   ---------------------------------------------------------------------
   --  Parse — public entry point.
   ---------------------------------------------------------------------
   procedure Parse (Der : Octet_Array; P : out Parsed_Cert; OK : out Boolean)
   is separate;

   ---------------------------------------------------------------------
   --  ASCII case-insensitive byte equality (RFC 6125 §6.4 says DNS
   --  matching is case-insensitive; we apply ASCII tolower on each
   --  byte of both sides; non-ASCII bytes compare exactly).
   ---------------------------------------------------------------------
   function Lower (B : Octet) return Octet
   is (if B in 16#41# .. 16#5A# then B + 16#20# else B);

   function Iequal (A : Octet_Array; B : Octet_Array) return Boolean
   with
     Pre =>
       A'First = 1
       and then B'First = 1
       and then A'Last < Integer'Last - 16
       and then B'Last < Integer'Last - 16;
   function Iequal (A : Octet_Array; B : Octet_Array) return Boolean is
   begin
      if A'Length /= B'Length then
         return False;
      end if;
      for I in 0 .. A'Length - 1 loop
         if Lower (A (A'First + I)) /= Lower (B (B'First + I)) then
            return False;
         end if;
      end loop;
      return True;
   end Iequal;

   ---------------------------------------------------------------------
   --  Match_DNS_SAN — walk a SEQUENCE OF GeneralName looking for a
   --  [2] dNSName whose body equals Hostname (case-insensitive).
   --
   --  San_Body is the body of the SubjectAltName OCTET STRING (per
   --  RFC 5280 §4.2.1.6, that body is itself a DER `SEQUENCE OF
   --  GeneralName`, so it begins with `30 LL`). We descend through
   --  the SEQUENCE header, then iterate the GeneralName entries.
   ---------------------------------------------------------------------
   function Match_DNS_SAN
     (San_Body : Octet_Array; Hostname : Octet_Array) return Boolean
   is separate;

end Tls_Core.Cert;
