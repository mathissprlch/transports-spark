separate (Tls_Core.Hello)
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
is
   P               : Natural := In_Bytes'First;
   Read_OK         : Boolean := True;
   U8_Val          : Octet;
   U16_Val         : Natural;
   Ext_Total_Len   : Natural;
   Ext_Block_Start : Natural;
   Body_F, Body_L  : Natural;
   Find_OK         : Boolean;
begin
   Random := [others => 0];
   Session_Id_First := 0;
   Session_Id_Last := 0;  --  Last < First means empty range
   Suites_First := 0;
   Suites_Last := 0;
   Identity_First := 0;
   Identity_Last := 0;
   Binder_First := 0;
   Binder_Last := 0;
   Key_Share_First := 0;
   Key_Share_Last := 0;
   Truncated_Last := 0;
   OK := False;

   --  legacy_version
   R_U8 (In_Bytes, P, U8_Val, Read_OK);
   R_U8 (In_Bytes, P, U8_Val, Read_OK);
   if not Read_OK then
      return;
   end if;
   --  random
   if P + 31 > In_Bytes'Last then
      return;
   end if;
   Random := In_Bytes (P .. P + 31);
   P := P + 32;
   --  legacy_session_id — RFC 8446 §4.1.2.  Capture the slice
   --  bounds so the server can echo it in its ServerHello
   --  (§4.1.3 mandate; openssl/mbedtls clients abort if missed).
   R_U8 (In_Bytes, P, U8_Val, Read_OK);
   if not Read_OK then
      return;
   end if;
   if Natural (U8_Val) > 32 then
      return;
   end if;  --  §4.1.2: <0..32>
   if P + Natural (U8_Val) - 1 > In_Bytes'Last then
      return;
   end if;
   if Natural (U8_Val) > 0 then
      Session_Id_First := P;
      Session_Id_Last := P + Natural (U8_Val) - 1;
   end if;
   P := P + Natural (U8_Val);
   --  cipher_suites — record the slice bounds so the caller can
   --  pick a suite. RFC 8446 §4.1.2: u16 length (must be even,
   --  >= 2), then N flat-packed u16 codepoints.
   R_U16 (In_Bytes, P, U16_Val, Read_OK);
   if not Read_OK then
      return;
   end if;
   if U16_Val < 2 or else U16_Val mod 2 /= 0 then
      return;
   end if;
   if P + U16_Val - 1 > In_Bytes'Last then
      return;
   end if;
   Suites_First := P;
   Suites_Last := P + U16_Val - 1;
   P := P + U16_Val;
   --  legacy_compression_methods
   R_U8 (In_Bytes, P, U8_Val, Read_OK);
   if not Read_OK then
      return;
   end if;
   if P + Natural (U8_Val) - 1 > In_Bytes'Last then
      return;
   end if;
   P := P + Natural (U8_Val);
   --  Extensions length
   R_U16 (In_Bytes, P, Ext_Total_Len, Read_OK);
   if not Read_OK then
      return;
   end if;
   Ext_Block_Start := P;
   if Ext_Block_Start + Ext_Total_Len - 1 > In_Bytes'Last then
      return;
   end if;

   --  Find pre_shared_key extension — MUST be last in CH.
   Find_Extension
     (In_Bytes   => In_Bytes,
      Pos        => Ext_Block_Start,
      End_Pos    => Ext_Block_Start + Ext_Total_Len,
      Ext_Type   => Ext_Pre_Shared_Key,
      Body_First => Body_F,
      Body_Last  => Body_L,
      OK         => Find_OK);
   if not Find_OK then
      return;
   end if;

   --  Body layout:
   --    u16 identities_total_len
   --    one identity: u16 id_len + id + u32 age
   --    u16 binders_total_len
   --    one binder: u8 binder_len + N
   declare
      Q                : Natural := Body_F;
      Identities_Total : Natural;
      Identity_Length  : Natural;
      Binders_Total    : Natural;
      Binder_Length    : Natural;
   begin
      if Q + 1 > Body_L then
         return;
      end if;
      Identities_Total :=
        Natural (In_Bytes (Q)) * 256 + Natural (In_Bytes (Q + 1));
      Q := Q + 2;
      if Q + 1 > Body_L then
         return;
      end if;
      Identity_Length :=
        Natural (In_Bytes (Q)) * 256 + Natural (In_Bytes (Q + 1));
      Q := Q + 2;
      if Identity_Length = 0 or else Identity_Length > Body_L - Q + 1 then
         return;
      end if;
      Identity_First := Q;
      Identity_Last := Q + Identity_Length - 1;
      Q := Q + Identity_Length;
      --  obfuscated_ticket_age (u32)
      if Q + 3 > Body_L then
         return;
      end if;
      Q := Q + 4;
      pragma Unreferenced (Identities_Total);
      --  RFC 8446 §4.2.11.2 + §4.4.1: Truncate(ClientHello) is
      --  the CH up to and INCLUDING .identities — i.e. the entire
      --  .binders<> field (its u16 length prefix + the entries) is
      --  excluded from the binder hash. So the truncation point is
      --  the byte just before the binders_total_len u16 begins.
      Truncated_Last := Q - 1;
      if Q + 1 > Body_L then
         return;
      end if;
      Binders_Total :=
        Natural (In_Bytes (Q)) * 256 + Natural (In_Bytes (Q + 1));
      Q := Q + 2;
      pragma Unreferenced (Binders_Total);
      if Q > Body_L then
         return;
      end if;
      Binder_Length := Natural (In_Bytes (Q));
      Q := Q + 1;
      if Binder_Length /= 32 then
         return;
      end if;
      if Q + 31 > Body_L then
         return;
      end if;
      Binder_First := Q;
      Binder_Last := Q + 31;
   end;

   --  Locate key_share extension. RFC 8446 §4.2.8 — CH layout:
   --    u16 client_shares_len
   --    KeyShareEntry { u16 group, u16 key_exch_len, key_exch }*
   --  We accept the first entry whose group matches x25519
   --  (0x001D) and key_exch_len = 32.
   declare
      Ks_Body_F, Ks_Body_L : Natural;
      Ks_Find_OK           : Boolean;
      Q                    : Natural;
      Group_Code           : Natural;
      Key_Exch_Len         : Natural;
      End_Body             : Natural;
      Found                : Boolean := False;
   begin
      Find_Extension
        (In_Bytes   => In_Bytes,
         Pos        => Ext_Block_Start,
         End_Pos    => Ext_Block_Start + Ext_Total_Len,
         Ext_Type   => Ext_Key_Share,
         Body_First => Ks_Body_F,
         Body_Last  => Ks_Body_L,
         OK         => Ks_Find_OK);
      if not Ks_Find_OK then
         return;
      end if;
      --  Skip the u16 client_shares_len.
      if Ks_Body_F + 1 > Ks_Body_L then
         return;
      end if;
      Q := Ks_Body_F + 2;
      End_Body := Ks_Body_L;
      while Q + 3 <= End_Body loop
         pragma Loop_Invariant (Q in Ks_Body_F .. End_Body + 1);
         Group_Code :=
           Natural (In_Bytes (Q)) * 256 + Natural (In_Bytes (Q + 1));
         Key_Exch_Len :=
           Natural (In_Bytes (Q + 2)) * 256 + Natural (In_Bytes (Q + 3));
         if Q + 3 + Key_Exch_Len > End_Body then
            return;
         end if;
         if Group_Code = 16#001D# and then Key_Exch_Len = 32 then
            Key_Share_First := Q + 4;
            Key_Share_Last := Q + 4 + 31;
            Found := True;
            exit;
         end if;
         Q := Q + 4 + Key_Exch_Len;
      end loop;
      if not Found then
         return;
      end if;
   end;

   --  Validate psk_key_exchange_modes contains psk_dhe_ke (= 1).
   --  Mode 0 (psk_ke) is not accepted; if the client only offers
   --  mode 0 the server returns OK = False (caller fails the
   --  handshake — illegal_parameter equivalent).
   declare
      Modes_Body_F, Modes_Body_L : Natural;
      Modes_Find_OK              : Boolean;
      Modes_Len                  : Natural;
      I                          : Natural;
      Has_Dhe                    : Boolean := False;
   begin
      Find_Extension
        (In_Bytes   => In_Bytes,
         Pos        => Ext_Block_Start,
         End_Pos    => Ext_Block_Start + Ext_Total_Len,
         Ext_Type   => Ext_Psk_Key_Exchange_Modes,
         Body_First => Modes_Body_F,
         Body_Last  => Modes_Body_L,
         OK         => Modes_Find_OK);
      if not Modes_Find_OK then
         return;
      end if;
      if Modes_Body_F > Modes_Body_L then
         return;
      end if;
      Modes_Len := Natural (In_Bytes (Modes_Body_F));
      if Modes_Len = 0 or else Modes_Body_F + Modes_Len > Modes_Body_L then
         return;
      end if;
      I := Modes_Body_F + 1;
      while I <= Modes_Body_F + Modes_Len loop
         pragma
           Loop_Invariant
             (I in Modes_Body_F + 1 .. Modes_Body_F + Modes_Len + 1);
         if In_Bytes (I) = 16#01# then
            Has_Dhe := True;
            exit;
         end if;
         I := I + 1;
      end loop;
      if not Has_Dhe then
         return;
      end if;
   end;

   OK := True;
end Decode_Client_Hello_Psk;
