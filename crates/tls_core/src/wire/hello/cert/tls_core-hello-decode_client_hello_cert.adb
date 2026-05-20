separate (Tls_Core.Hello)
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
is
   P               : Natural := In_Bytes'First;
   Read_OK         : Boolean := True;
   U8_Val          : Octet;
   U16_Val         : Natural;
   Ext_Total_Len   : Natural;
   Ext_Block_Start : Natural;
begin
   Random := [others => 0];
   Session_Id_First := 0;
   Session_Id_Last := 0;
   Suites_First := 0;
   Suites_Last := 0;
   Sig_Algs_First := 0;
   Sig_Algs_Last := 0;
   Key_Share_First := 0;
   Key_Share_Last := 0;
   OK := False;

   --  legacy_version + random + session_id + cipher_suites +
   --  legacy_compression_methods (same shape as PSK CH).
   R_U8 (In_Bytes, P, U8_Val, Read_OK);
   R_U8 (In_Bytes, P, U8_Val, Read_OK);
   if not Read_OK then
      return;
   end if;
   if P + 31 > In_Bytes'Last then
      return;
   end if;
   Random := In_Bytes (P .. P + 31);
   P := P + 32;
   --  legacy_session_id — RFC 8446 §4.1.2; capture for SH echo (§4.1.3).
   R_U8 (In_Bytes, P, U8_Val, Read_OK);
   if not Read_OK then
      return;
   end if;
   if Natural (U8_Val) > 32 then
      return;
   end if;
   if P + Natural (U8_Val) - 1 > In_Bytes'Last then
      return;
   end if;
   if Natural (U8_Val) > 0 then
      Session_Id_First := P;
      Session_Id_Last := P + Natural (U8_Val) - 1;
   end if;
   P := P + Natural (U8_Val);
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
   R_U8 (In_Bytes, P, U8_Val, Read_OK);
   if not Read_OK then
      return;
   end if;
   if P + Natural (U8_Val) - 1 > In_Bytes'Last then
      return;
   end if;
   P := P + Natural (U8_Val);
   R_U16 (In_Bytes, P, Ext_Total_Len, Read_OK);
   if not Read_OK then
      return;
   end if;
   Ext_Block_Start := P;
   if Ext_Block_Start + Ext_Total_Len - 1 > In_Bytes'Last then
      return;
   end if;

   --  signature_algorithms (RFC 8446 §4.2.3) — REQUIRED in
   --  cert-mode CH.  Body shape: u16 list_len + N x u16 schemes.
   declare
      Body_F, Body_L : Natural;
      Find_OK        : Boolean;
      List_Len       : Natural;
   begin
      Find_Extension
        (In_Bytes   => In_Bytes,
         Pos        => Ext_Block_Start,
         End_Pos    => Ext_Block_Start + Ext_Total_Len,
         Ext_Type   => Ext_Signature_Algorithms,
         Body_First => Body_F,
         Body_Last  => Body_L,
         OK         => Find_OK);
      if not Find_OK then
         return;
      end if;
      if Body_F + 1 > Body_L then
         return;
      end if;
      List_Len :=
        Natural (In_Bytes (Body_F)) * 256 + Natural (In_Bytes (Body_F + 1));
      if List_Len < 2
        or else List_Len mod 2 /= 0
        or else Body_F + 1 + List_Len > Body_L
      then
         return;
      end if;
      Sig_Algs_First := Body_F + 2;
      Sig_Algs_Last := Body_F + 1 + List_Len;
   end;

   --  key_share — same shape and search strategy as the PSK
   --  decoder; accept the first KeyShareEntry whose group is
   --  x25519 (0x001D) and key_exchange length is 32.
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

   OK := True;
end Decode_Client_Hello_Cert;
