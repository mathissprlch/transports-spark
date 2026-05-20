package body Tls_Core.Hello_Retry
  with SPARK_Mode
is

   use type Tls_Core.Suites.U16;

   --  Extension type constants for HRR (RFC 8446 §4.2).
   Ext_Supported_Versions : constant Natural := 16#002B#;
   Ext_Key_Share          : constant Natural := 16#0033#;
   Ext_Cookie             : constant Natural := 16#002C#;

   ---------------------------------------------------------------------
   --  Is_Hrr_Random
   ---------------------------------------------------------------------

   function Is_Hrr_Random (Random : Octet_Array) return Boolean is
      Diff   : Octet := 0;
      Result : Boolean;
   begin
      for I in 1 .. 32 loop
         pragma Loop_Invariant (I in 1 .. 32);
         Diff := Diff or (Random (Random'First + I - 1) xor Magic_Random (I));
      end loop;
      Result := Diff = 0;
      return Result;
   end Is_Hrr_Random;

   ---------------------------------------------------------------------
   --  Build_Synthetic_Msg_Sha256 (RFC 8446 §4.4.1)
   ---------------------------------------------------------------------

   procedure Build_Synthetic_Msg_Sha256
     (Ch1_Hash : Tls_Core.Sha256.Digest; Out_Buf : out Octet_Array) is
   begin
      Out_Buf := [others => 0];
      Out_Buf (1) := Synthetic_Type;
      Out_Buf (2) := 16#00#;
      Out_Buf (3) := 16#00#;
      Out_Buf (4) := 16#20#;  --  32 = 0x20, length of SHA-256 digest
      for I in 1 .. 32 loop
         pragma Loop_Invariant (I in 1 .. 32);
         pragma Loop_Invariant (Out_Buf (1) = Synthetic_Type);
         pragma Loop_Invariant (Out_Buf (2) = 0);
         pragma Loop_Invariant (Out_Buf (3) = 0);
         pragma Loop_Invariant (Out_Buf (4) = 32);
         pragma
           Loop_Invariant
             (for all J in 1 .. I - 1 => Out_Buf (4 + J) = Ch1_Hash (J));
         Out_Buf (4 + I) := Ch1_Hash (I);
      end loop;
   end Build_Synthetic_Msg_Sha256;

   ---------------------------------------------------------------------
   --  Internal writers — same shape as Tls_Core.Hello.W_*.
   ---------------------------------------------------------------------

   procedure W_U8
     (Out_Buf : in out Octet_Array; Cursor : in out Natural; Value : Octet)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Last >= 1
       and then Cursor < Out_Buf'Last,
     Post => Cursor = Cursor'Old + 1 and then Cursor in 1 .. Out_Buf'Last;
   procedure W_U8
     (Out_Buf : in out Octet_Array; Cursor : in out Natural; Value : Octet) is
   begin
      Cursor := Cursor + 1;
      Out_Buf (Cursor) := Value;
   end W_U8;

   procedure W_U16
     (Out_Buf : in out Octet_Array; Cursor : in out Natural; Value : Natural)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Last >= 2
       and then Cursor <= Out_Buf'Last - 2
       and then Value <= 16#FFFF#,
     Post => Cursor = Cursor'Old + 2 and then Cursor in 2 .. Out_Buf'Last;
   procedure W_U16
     (Out_Buf : in out Octet_Array; Cursor : in out Natural; Value : Natural)
   is
   begin
      Cursor := Cursor + 1;
      Out_Buf (Cursor) := Octet (Value / 256);
      Cursor := Cursor + 1;
      Out_Buf (Cursor) := Octet (Value mod 256);
   end W_U16;

   procedure W_Bytes
     (Out_Buf : in out Octet_Array;
      Cursor  : in out Natural;
      Bytes   : Octet_Array)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Bytes'Length <= Out_Buf'Last
       and then Cursor <= Out_Buf'Last - Bytes'Length,
     Post =>
       Cursor = Cursor'Old + Bytes'Length
       and then Cursor in Cursor'Old .. Out_Buf'Last;
   procedure W_Bytes
     (Out_Buf : in out Octet_Array;
      Cursor  : in out Natural;
      Bytes   : Octet_Array) is
   begin
      if Bytes'Length > 0 then
         Out_Buf (Cursor + 1 .. Cursor + Bytes'Length) := Bytes;
         Cursor := Cursor + Bytes'Length;
      end if;
   end W_Bytes;

   procedure Patch_U16
     (Out_Buf : in out Octet_Array; At_Pos : Natural; Value : Natural)
   with
     Pre =>
       Out_Buf'First = 1
       and then Out_Buf'Last >= 2
       and then At_Pos >= 1
       and then At_Pos < Out_Buf'Last
       and then Value <= 16#FFFF#;
   procedure Patch_U16
     (Out_Buf : in out Octet_Array; At_Pos : Natural; Value : Natural) is
   begin
      Out_Buf (At_Pos) := Octet (Value / 256);
      Out_Buf (At_Pos + 1) := Octet (Value mod 256);
   end Patch_U16;

   ---------------------------------------------------------------------
   --  Encode_Hrr — RFC 8446 §4.1.4 wire shape.
   --
   --  HRR is structurally identical to ServerHello with:
   --    legacy_version = 0x0303
   --    random         = Magic_Random
   --    legacy_session_id_echo = empty (we don't carry session IDs in v0.5)
   --    cipher_suite   = Selected_Suite
   --    legacy_compression_method = 0
   --    extensions:
   --      supported_versions = 0x0304
   --      key_share          = Selected_Group (group only, no public key)
   --      cookie             = Cookie bytes (omitted if empty)
   ---------------------------------------------------------------------

   procedure Encode_Hrr
     (Selected_Suite : Tls_Core.Suites.U16;
      Selected_Group : Tls_Core.Suites.U16;
      Cookie         : Octet_Array;
      Out_Buf        : out Octet_Array;
      Out_Last       : out Natural)
   is
      Cursor         : Natural := 0;
      Ext_Len_Pos    : Natural;
      Ext_Body_Start : Natural;
   begin
      Out_Buf := [others => 0];

      --  legacy_version 0x0303
      W_U8 (Out_Buf, Cursor, 16#03#);
      W_U8 (Out_Buf, Cursor, 16#03#);
      --  random = Magic_Random
      W_Bytes (Out_Buf, Cursor, Magic_Random);
      --  legacy_session_id_echo: u8 length = 0 (we don't echo)
      W_U8 (Out_Buf, Cursor, 0);
      --  cipher_suite (u16)
      W_U16 (Out_Buf, Cursor, Natural (Selected_Suite));
      --  legacy_compression_method (u8) = 0
      W_U8 (Out_Buf, Cursor, 0);

      --  Reserve u16 for extensions length, then patch.
      Cursor := Cursor + 1;
      Ext_Len_Pos := Cursor;
      Cursor := Cursor + 1;
      Ext_Body_Start := Cursor + 1;

      --  supported_versions = TLS 1.3 (single u16)
      declare
         Body_Bytes : constant Octet_Array (1 .. 2) :=
           [1 => 16#03#, 2 => 16#04#];
      begin
         --  ext_type u16
         W_U16 (Out_Buf, Cursor, Ext_Supported_Versions);
         --  ext_data length u16
         W_U16 (Out_Buf, Cursor, Body_Bytes'Length);
         W_Bytes (Out_Buf, Cursor, Body_Bytes);
      end;

      --  key_share (HRR variant): u16 selected_group, no public key
      declare
         Body_Bytes : constant Octet_Array (1 .. 2) :=
           [1 => Octet (Natural (Selected_Group) / 256),
            2 => Octet (Natural (Selected_Group) mod 256)];
      begin
         W_U16 (Out_Buf, Cursor, Ext_Key_Share);
         W_U16 (Out_Buf, Cursor, Body_Bytes'Length);
         W_Bytes (Out_Buf, Cursor, Body_Bytes);
      end;

      --  cookie (omit if empty)
      if Cookie'Length > 0 then
         declare
            Cookie_Body_Len : constant Natural := 2 + Cookie'Length;
            --  ext_type u16, ext_data length u16, then u16
            --  cookie_data_len, then cookie bytes.
         begin
            W_U16 (Out_Buf, Cursor, Ext_Cookie);
            W_U16 (Out_Buf, Cursor, Cookie_Body_Len);
            W_U16 (Out_Buf, Cursor, Cookie'Length);
            W_Bytes (Out_Buf, Cursor, Cookie);
         end;
      end if;

      --  Patch the extensions block u16 length.
      Patch_U16 (Out_Buf, Ext_Len_Pos, Cursor - Ext_Body_Start + 1);

      Out_Last := Cursor;
   end Encode_Hrr;

   ---------------------------------------------------------------------
   --  Decode_Hrr — inverse of Encode_Hrr.
   ---------------------------------------------------------------------

   procedure Decode_Hrr
     (In_Bytes       : Octet_Array;
      Cipher_Suite   : out Tls_Core.Suites.U16;
      Selected_Group : out Tls_Core.Suites.U16;
      Cookie         : out Cookie_Bytes;
      Cookie_Length  : out Natural;
      OK             : out Boolean)
   is
      Base            : constant Integer := In_Bytes'First;
      P               : Natural;
      Random_OK       : Boolean;
      U8_Val          : Octet;
      Ext_Total_Len   : Natural;
      Ext_Block_Start : Natural;
      Ext_Block_End   : Natural;
      Found_Ks        : Boolean := False;
   begin
      Cipher_Suite := 0;
      Selected_Group := 0;
      Cookie := [others => 0];
      Cookie_Length := 0;
      OK := False;

      --  Need at least: legacy_version (2) + random (32) + sid_len (1)
      --                + cipher_suite (2) + compression (1) + ext_len (2) = 40
      if In_Bytes'Length < 40 then
         return;
      end if;

      --  legacy_version (skip — must be 0x0303)
      if In_Bytes (Base) /= 16#03# or else In_Bytes (Base + 1) /= 16#03# then
         return;
      end if;
      P := Base + 2;

      --  random — must equal Magic_Random
      Random_OK := Is_Hrr_Random (In_Bytes (P .. P + 31));
      if not Random_OK then
         return;
      end if;
      P := P + 32;

      --  legacy_session_id_echo: u8 length (we accept 0..32 but
      --  don't read the bytes)
      U8_Val := In_Bytes (P);
      P := P + 1;
      if Natural (U8_Val) > 32 then
         return;
      end if;
      if Natural (U8_Val) > 0 and then Natural (U8_Val) > In_Bytes'Last - P + 1
      then
         return;
      end if;
      P := P + Natural (U8_Val);

      --  cipher_suite (u16)
      if P + 1 > In_Bytes'Last then
         return;
      end if;
      Cipher_Suite :=
        Tls_Core.Suites.U16 (In_Bytes (P))
        * 256
        + Tls_Core.Suites.U16 (In_Bytes (P + 1));
      P := P + 2;

      --  legacy_compression_method (u8 — must be 0)
      if P > In_Bytes'Last then
         return;
      end if;
      if In_Bytes (P) /= 0 then
         return;
      end if;
      P := P + 1;

      --  Extensions u16 length
      if P + 1 > In_Bytes'Last then
         return;
      end if;
      Ext_Total_Len :=
        Natural (In_Bytes (P)) * 256 + Natural (In_Bytes (P + 1));
      P := P + 2;
      Ext_Block_Start := P;
      if Ext_Total_Len > 0
        and then Ext_Total_Len > In_Bytes'Last - Ext_Block_Start + 1
      then
         return;
      end if;
      Ext_Block_End := Ext_Block_Start + Ext_Total_Len;

      --  Walk extensions; locate key_share (mandatory) and cookie (optional).
      declare
         Q     : Natural := Ext_Block_Start;
         T_Val : Natural;
         L_Val : Natural;
      begin
         while Q + 3 < Ext_Block_End loop
            pragma Loop_Invariant (Q in Ext_Block_Start .. Ext_Block_End);
            pragma Loop_Invariant (Ext_Block_End <= In_Bytes'Last + 1);
            pragma Loop_Invariant (Ext_Block_End <= Integer'Last - 4);
            pragma Loop_Invariant (Cookie_Length in 0 .. Max_Cookie_Length);
            T_Val := Natural (In_Bytes (Q)) * 256 + Natural (In_Bytes (Q + 1));
            L_Val :=
              Natural (In_Bytes (Q + 2)) * 256 + Natural (In_Bytes (Q + 3));
            Q := Q + 4;
            if L_Val > Ext_Block_End - Q then
               return;
            end if;
            if T_Val = Ext_Key_Share then
               --  HRR key_share body = u16 selected_group only.
               if L_Val /= 2 then
                  return;
               end if;
               Selected_Group :=
                 Tls_Core.Suites.U16 (In_Bytes (Q))
                 * 256
                 + Tls_Core.Suites.U16 (In_Bytes (Q + 1));
               Found_Ks := True;
            elsif T_Val = Ext_Cookie then
               --  Cookie body = u16 cookie_data_len + cookie_data.
               if L_Val < 2 then
                  return;
               end if;
               declare
                  Cookie_Data_Len : constant Natural :=
                    Natural (In_Bytes (Q)) * 256 + Natural (In_Bytes (Q + 1));
               begin
                  if Cookie_Data_Len /= L_Val - 2
                    or else Cookie_Data_Len > Max_Cookie_Length
                  then
                     return;
                  end if;
                  if Cookie_Data_Len > 0 then
                     for I in 1 .. Cookie_Data_Len loop
                        pragma Loop_Invariant (I in 1 .. Cookie_Data_Len);
                        pragma
                          Loop_Invariant
                            (Cookie_Data_Len <= Max_Cookie_Length);
                        Cookie (I) := In_Bytes (Q + 2 + I - 1);
                     end loop;
                  end if;
                  Cookie_Length := Cookie_Data_Len;
               end;
            end if;
            Q := Q + L_Val;
         end loop;
      end;

      if not Found_Ks then
         return;
      end if;
      OK := True;
   end Decode_Hrr;

   ---------------------------------------------------------------------
   --  Cookies_Equal — constant-time bytewise compare.
   ---------------------------------------------------------------------

   function Cookies_Equal
     (Have : Octet_Array; Want : Cookie_Bytes; Want_Length : Natural)
      return Boolean
   is
      Diff : Octet := 0;
   begin
      if Have'Length /= Want_Length then
         return False;
      end if;
      if Want_Length = 0 then
         return True;
      end if;
      for I in 1 .. Want_Length loop
         pragma Loop_Invariant (I in 1 .. Want_Length);
         pragma Loop_Invariant (Want_Length <= Max_Cookie_Length);
         Diff := Diff or (Have (Have'First + I - 1) xor Want (I));
      end loop;
      return Diff = 0;
   end Cookies_Equal;

end Tls_Core.Hello_Retry;
