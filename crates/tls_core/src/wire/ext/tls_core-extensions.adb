with Interfaces;

package body Tls_Core.Extensions
  with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;

   procedure Put_U16
     (Out_Buf : in out Octet_Array; Cursor : in out Natural; V : Unsigned_16)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Cursor + 2 <= Out_Buf'Length
       and then Cursor in Natural,
     Post => Cursor = Cursor'Old + 2;
   procedure Put_U16
     (Out_Buf : in out Octet_Array; Cursor : in out Natural; V : Unsigned_16)
   is
   begin
      Out_Buf (Cursor + 1) := Octet (Shift_Right (V, 8) and 16#FF#);
      Out_Buf (Cursor + 2) := Octet (V and 16#FF#);
      Cursor := Cursor + 2;
   end Put_U16;

   procedure Encode_Server_Name
     (Host_Name : Octet_Array;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   is
      Cursor : Natural := 0;
   begin
      Out_Buf := (others => 0);
      --  list_length: u16 over the single ServerName entry =
      --  1 (name_type) + 2 (host_name length) + N (host_name bytes).
      Put_U16 (Out_Buf, Cursor, Unsigned_16 (3 + Host_Name'Length));
      --  name_type = 0x00 (host_name).
      Out_Buf (Cursor + 1) := 16#00#;
      Cursor := Cursor + 1;
      --  host_name length + bytes.
      Put_U16 (Out_Buf, Cursor, Unsigned_16 (Host_Name'Length));
      for I in 0 .. Host_Name'Length - 1 loop
         Out_Buf (Cursor + 1 + I) := Host_Name (Host_Name'First + I);
      end loop;
      Cursor := Cursor + Host_Name'Length;
      Out_Last := Cursor;
   end Encode_Server_Name;

   procedure Decode_Server_Name
     (Buf        : Octet_Array;
      OK         : out Boolean;
      Host_First : out Natural;
      Host_Last  : out Natural)
   is
      List_Len : Natural;
      Cursor   : Natural := 0;
   begin
      OK := False;
      Host_First := 0;
      Host_Last := 0;

      if Buf'Length < 5 then
         return;
      end if;
      List_Len :=
        Natural (Buf (Buf'First + 0)) * 256 + Natural (Buf (Buf'First + 1));
      Cursor := 2;
      if Cursor + List_Len /= Buf'Length then
         return;
      end if;
      if Buf (Buf'First + Cursor) /= 16#00# then
         --  Only host_name (NameType = 0) is supported.
         return;
      end if;
      Cursor := Cursor + 1;
      if Cursor + 2 > Buf'Length then
         return;
      end if;
      declare
         Name_Len : constant Natural :=
           Natural (Buf (Buf'First + Cursor))
           * 256
           + Natural (Buf (Buf'First + Cursor + 1));
      begin
         Cursor := Cursor + 2;
         if Cursor + Name_Len /= Buf'Length then
            return;
         end if;
         if Name_Len = 0 then
            return;
         end if;
         Host_First := Buf'First + Cursor;
         Host_Last := Buf'First + Cursor + Name_Len - 1;
         OK := True;
      end;
   end Decode_Server_Name;

   procedure Encode_Alpn
     (Names_Buf : Octet_Array;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   is
      Cursor : Natural := 0;
   begin
      Out_Buf := (others => 0);
      Put_U16 (Out_Buf, Cursor, Unsigned_16 (Names_Buf'Length));
      for I in 1 .. Names_Buf'Length loop
         Out_Buf (Cursor + I) := Names_Buf (Names_Buf'First + I - 1);
      end loop;
      Cursor := Cursor + Names_Buf'Length;
      Out_Last := Cursor;
   end Encode_Alpn;

   procedure Decode_Alpn
     (Buf         : Octet_Array;
      OK          : out Boolean;
      Names_First : out Natural;
      Names_Last  : out Natural) is
   begin
      OK := False;
      Names_First := 0;
      Names_Last := 0;
      if Buf'Length < 2 then
         return;
      end if;
      declare
         List_Len : constant Natural :=
           Natural (Buf (Buf'First + 0)) * 256 + Natural (Buf (Buf'First + 1));
      begin
         if 2 + List_Len /= Buf'Length then
            return;
         end if;
         if List_Len = 0 then
            return;
         end if;
         Names_First := Buf'First + 2;
         Names_Last := Buf'First + 1 + List_Len;
         OK := True;
      end;
   end Decode_Alpn;

   procedure Append_Alpn_Name
     (Name    : Octet_Array;
      Out_Buf : in out Octet_Array;
      Cursor  : in out Natural) is
   begin
      Out_Buf (Cursor + 1) := Octet (Name'Length);
      for I in 1 .. Name'Length loop
         Out_Buf (Cursor + 1 + I) := Name (Name'First + I - 1);
      end loop;
      Cursor := Cursor + 1 + Name'Length;
   end Append_Alpn_Name;

end Tls_Core.Extensions;
