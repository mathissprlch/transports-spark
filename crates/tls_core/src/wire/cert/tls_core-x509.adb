--  Tls_Core.X509 — body. Pure Ada DER walker for Ed25519 certs.
--
--  Regenerate the test certificate the tests embed with
--      openssl req -x509 -newkey ed25519 -nodes -days 365 \
--          -subj "/CN=test" -outform DER -out test.der
--  then dump the bytes via `xxd -i test.der`.

package body Tls_Core.X509
  with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;

   --  ASN.1 / DER tag bytes we care about.
   Tag_Sequence   : constant Octet := 16#30#;
   Tag_Bit_String : constant Octet := 16#03#;
   Tag_Context_0  : constant Octet := 16#A0#;

   --  AlgorithmIdentifier for Ed25519 with no parameters
   --  (RFC 8410 §3, OID 1.3.101.112):
   --      SEQUENCE { OID 1.3.101.112 }   ==   30 05 06 03 2B 65 70
   --  We compare this whole 7-byte TLV byte-for-byte; the OID alone
   --  (06 03 2B 65 70) is just the inner contents.
   Alg_Id_Ed25519 : constant Octet_Array (1 .. 7) :=
     (16#30#, 16#05#, 16#06#, 16#03#, 16#2B#, 16#65#, 16#70#);

   ---------------------------------------------------------------------
   --  Parse a single ASN.1 DER TLV header at Buf (Pos).
   --
   --    On success:
   --      OK         := True,
   --      Tag        := tag byte,
   --      Value_Pos  := first byte of the TLV value (V),
   --      Value_Len  := length of V in bytes,
   --      Next_Pos   := Value_Pos + Value_Len  (one past the TLV).
   --
   --    On any malformed input (truncation, indefinite length,
   --    multi-byte length > 3 bytes, length running past Buf'Last,
   --    Pos < Buf'First, etc.) sets OK := False.
   --
   --  We accept short form (length < 0x80) and long form with 1, 2,
   --  or 3 length bytes — that covers values up to 16 MiB, far more
   --  than any cert we will meet here.
   ---------------------------------------------------------------------

   procedure Read_Tlv
     (Buf       : Octet_Array;
      Pos       : Natural;
      Tag       : out Octet;
      Value_Pos : out Natural;
      Value_Len : out Natural;
      Next_Pos  : out Natural;
      OK        : out Boolean);

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
   --  Skip exactly one TLV at Pos and return Next_Pos. Wraps Read_Tlv
   --  for the call sites that don't care about the contents.
   ---------------------------------------------------------------------

   procedure Skip_Tlv
     (Buf      : Octet_Array;
      Pos      : Natural;
      Next_Pos : out Natural;
      OK       : out Boolean);

   procedure Skip_Tlv
     (Buf      : Octet_Array;
      Pos      : Natural;
      Next_Pos : out Natural;
      OK       : out Boolean)
   is
      Tag       : Octet;
      Value_Pos : Natural;
      Value_Len : Natural;
   begin
      Read_Tlv (Buf, Pos, Tag, Value_Pos, Value_Len, Next_Pos, OK);
   end Skip_Tlv;

   ---------------------------------------------------------------------
   --  Slice equality at a specific offset.
   ---------------------------------------------------------------------

   function Equal_At
     (Buf : Octet_Array; Pos : Natural; Reference : Octet_Array)
      return Boolean;

   function Equal_At
     (Buf : Octet_Array; Pos : Natural; Reference : Octet_Array) return Boolean
   is
   begin
      if Pos < Buf'First or else Pos + Reference'Length - 1 > Buf'Last then
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
   --  Parse_Ed25519_Cert — the public entry point.
   ---------------------------------------------------------------------

   procedure Parse_Ed25519_Cert
     (Der       : Octet_Array;
      Tbs_First : out Natural;
      Tbs_Last  : out Natural;
      Pub_Key   : out Public_Key;
      Sig       : out Signature;
      OK        : out Boolean)
   is separate;

end Tls_Core.X509;
