separate (Tls_Core.Hello)
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
