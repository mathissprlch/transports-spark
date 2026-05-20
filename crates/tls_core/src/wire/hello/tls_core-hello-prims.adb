package body Tls_Core.Hello.Prims
  with SPARK_Mode
is


   procedure W_U8
     (Out_Buf : in out Octet_Array; Cursor : in out Natural; Value : Octet) is
   begin
      Cursor := Cursor + 1;
      Out_Buf (Cursor) := Value;
   end W_U8;

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
      Bytes   : Octet_Array) is
   begin
      if Bytes'Length > 0 then
         Out_Buf (Cursor + 1 .. Cursor + Bytes'Length) := Bytes;
         Cursor := Cursor + Bytes'Length;
      end if;
   end W_Bytes;

   procedure Patch_U16
     (Out_Buf : in out Octet_Array; At_Pos : Natural; Value : Natural) is
   begin
      Out_Buf (At_Pos) := Octet (Value / 256);
      Out_Buf (At_Pos + 1) := Octet (Value mod 256);
   end Patch_U16;

   procedure Encode_Extension
     (Out_Buf    : in out Octet_Array;
      Cursor     : in out Natural;
      Ext_Type   : Natural;
      Body_Bytes : Octet_Array) is
   begin
      W_U16 (Out_Buf, Cursor, Ext_Type);
      W_U16 (Out_Buf, Cursor, Body_Bytes'Length);
      W_Bytes (Out_Buf, Cursor, Body_Bytes);
   end Encode_Extension;

   procedure R_U8
     (In_Bytes : Octet_Array;
      Pos      : in out Natural;
      Value    : out Octet;
      OK       : in out Boolean) is
   begin
      Value := 0;
      if not OK then
         return;
      end if;
      if Pos > In_Bytes'Last then
         OK := False;
         return;
      end if;
      Value := In_Bytes (Pos);
      Pos := Pos + 1;
   end R_U8;

   procedure R_U16
     (In_Bytes : Octet_Array;
      Pos      : in out Natural;
      Value    : out Natural;
      OK       : in out Boolean) is
   begin
      Value := 0;
      if not OK then
         return;
      end if;
      if Pos + 1 > In_Bytes'Last then
         OK := False;
         return;
      end if;
      Value := Natural (In_Bytes (Pos)) * 256 + Natural (In_Bytes (Pos + 1));
      Pos := Pos + 2;
   end R_U16;

   procedure Find_Extension
     (In_Bytes   : Octet_Array;
      Pos        : Natural;
      End_Pos    : Natural;
      Ext_Type   : Natural;
      Body_First : out Natural;
      Body_Last  : out Natural;
      OK         : out Boolean)
   is
      P       : Natural := Pos;
      T       : Natural;
      L       : Natural;
      Read_OK : Boolean := True;
   begin
      Body_First := 0;
      Body_Last := 0;
      OK := False;
      while P + 3 < End_Pos loop
         pragma Loop_Invariant (P >= 1);
         pragma Loop_Invariant (P <= In_Bytes'Last + 1);
         R_U16 (In_Bytes, P, T, Read_OK);
         R_U16 (In_Bytes, P, L, Read_OK);
         --  L > End_Pos - P is the overflow-safe form of
         --  P + L - 1 >= End_Pos (here Read_OK => P <= End_Pos).
         if not Read_OK or else L > End_Pos - P then
            return;
         end if;
         if T = Ext_Type then
            Body_First := P;
            Body_Last := P + L - 1;
            OK := True;
            return;
         end if;
         P := P + L;
      end loop;
   end Find_Extension;

end Tls_Core.Hello.Prims;
