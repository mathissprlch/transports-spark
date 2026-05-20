separate (Tls_Core.Hello)
procedure Decode_Server_Hello
  (In_Bytes : Octet_Array; SH : out Server_Hello; OK : out Boolean)
is
   P               : Natural := In_Bytes'First;
   Read_OK         : Boolean := True;
   U8_Val          : Octet;
   Ext_Total_Len   : Natural;
   Ext_Block_Start : Natural;
   Body_F, Body_L  : Natural;
   Find_OK         : Boolean;
begin
   SH.Random := (others => 0);
   SH.Session_Id_Len := 0;
   SH.Session_Id_Bytes := (others => 0);
   SH.Key_Share := (others => 0);
   OK := False;

   R_U8 (In_Bytes, P, U8_Val, Read_OK);
   R_U8 (In_Bytes, P, U8_Val, Read_OK);
   if not Read_OK then
      return;
   end if;
   if P + 31 > In_Bytes'Last then
      return;
   end if;
   SH.Random := In_Bytes (P .. P + 31);
   P := P + 32;
   R_U8 (In_Bytes, P, U8_Val, Read_OK);
   if not Read_OK then
      return;
   end if;
   SH.Session_Id_Len := Natural (U8_Val);
   if SH.Session_Id_Len > 32 then
      return;
   end if;
   if SH.Session_Id_Len > 0 then
      if P + SH.Session_Id_Len - 1 > In_Bytes'Last then
         return;
      end if;
      SH.Session_Id_Bytes (1 .. SH.Session_Id_Len) :=
        In_Bytes (P .. P + SH.Session_Id_Len - 1);
      P := P + SH.Session_Id_Len;
   end if;
   --  cipher_suite (u16, fixed)
   if P + 1 > In_Bytes'Last then
      return;
   end if;
   P := P + 2;
   --  legacy_compression_method (u8)
   R_U8 (In_Bytes, P, U8_Val, Read_OK);
   if not Read_OK then
      return;
   end if;
   --  Extensions
   R_U16 (In_Bytes, P, Ext_Total_Len, Read_OK);
   if not Read_OK then
      return;
   end if;
   Ext_Block_Start := P;
   if Ext_Block_Start + Ext_Total_Len - 1 > In_Bytes'Last then
      return;
   end if;

   Find_Extension
     (In_Bytes   => In_Bytes,
      Pos        => Ext_Block_Start,
      End_Pos    => Ext_Block_Start + Ext_Total_Len,
      Ext_Type   => Ext_Key_Share,
      Body_First => Body_F,
      Body_Last  => Body_L,
      OK         => Find_OK);
   if not Find_OK then
      return;
   end if;
   --  ServerHello key_share body:
   --    KeyShareEntry { u16 group, u16 key_exch_len, key_exch[32] }
   if Body_L - Body_F + 1 < 4 + 32 then
      return;
   end if;
   SH.Key_Share := In_Bytes (Body_F + 4 .. Body_F + 4 + 31);

   OK := True;
end Decode_Server_Hello;
