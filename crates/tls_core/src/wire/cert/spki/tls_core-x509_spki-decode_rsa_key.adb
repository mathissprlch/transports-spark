separate (Tls_Core.X509_Spki)
procedure Decode_Rsa_Key
  (Buf       : Octet_Array;
   OK        : out Boolean;
   Mod_First : out Natural;
   Mod_Last  : out Natural;
   Exp_First : out Natural;
   Exp_Last  : out Natural)
is
   Step_OK : Boolean;

   --  Outer RSAPublicKey SEQUENCE
   Outer_BF : Natural;
   Outer_BL : Natural;
   Outer_AF : Natural;

   --  modulus INTEGER
   Mod_BF : Natural;
   Mod_BL : Natural;
   Mod_AF : Natural;

   --  publicExponent INTEGER
   Exp_BF : Natural;
   Exp_BL : Natural;
   Exp_AF : Natural;
begin
   OK := False;
   Mod_First := 0;
   Mod_Last := 0;
   Exp_First := 0;
   Exp_Last := 0;

   --  RSAPublicKey ::= SEQUENCE
   Read_TLV_Header
     (Buf, Buf'First, Tag_Sequence, Outer_BF, Outer_BL, Outer_AF, Step_OK);
   if not Step_OK then
      return;
   end if;

   --  modulus INTEGER (must lie inside outer body)
   Read_TLV_Header
     (Buf, Outer_BF, Tag_Integer, Mod_BF, Mod_BL, Mod_AF, Step_OK);
   if not Step_OK then
      return;
   end if;
   if Mod_BL > Outer_BL or else Mod_BF > Mod_BL then
      return;
   end if;

   --  publicExponent INTEGER (must follow modulus inside outer body)
   Read_TLV_Header (Buf, Mod_AF, Tag_Integer, Exp_BF, Exp_BL, Exp_AF, Step_OK);
   if not Step_OK then
      return;
   end if;
   if Exp_BL > Outer_BL or else Exp_BF > Exp_BL then
      return;
   end if;

   --  DER INTEGER values for X.509 are big-endian, possibly with
   --  a leading 0x00 sign byte to disambiguate from negative.
   --  Caller is responsible for stripping that if it cares.
   Mod_First := Mod_BF;
   Mod_Last := Mod_BL;
   Exp_First := Exp_BF;
   Exp_Last := Exp_BL;
   OK := True;
end Decode_Rsa_Key;
