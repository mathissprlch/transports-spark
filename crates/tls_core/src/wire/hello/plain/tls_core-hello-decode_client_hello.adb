separate (Tls_Core.Hello)
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
