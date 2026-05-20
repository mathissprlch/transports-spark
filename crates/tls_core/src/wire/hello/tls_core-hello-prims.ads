private package Tls_Core.Hello.Prims
  with SPARK_Mode
is

   use type Tls_Core.Octet;

   --  Byte-level wire read/write primitives shared by the ClientHello /
   --  ServerHello encoders and decoders. The writers/readers carry
   --  functional Posts pinning the exact big-endian bytes (RFC 8446
   --  network order) plus a modifies frame, mirroring miTLS/LowParse
   --  leaf writers and parsers.

   --  Writer helpers — append byte / u16 / a buffer of bytes into
   --  Out_Buf, advancing Cursor.

   procedure W_U8
     (Out_Buf : in out Octet_Array; Cursor : in out Natural; Value : Octet)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Last >= 1
       and then Cursor < Out_Buf'Last,
     Post =>
       Cursor = Cursor'Old + 1
       and then Out_Buf (Cursor) = Value
       and then (for all I in Out_Buf'Range =>
                   (if I /= Cursor then Out_Buf (I) = Out_Buf'Old (I)));

   procedure W_U16
     (Out_Buf : in out Octet_Array; Cursor : in out Natural; Value : Natural)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Last >= 2
       and then Cursor <= Out_Buf'Last - 2
       and then Value <= 16#FFFF#,
     Post =>
       Cursor = Cursor'Old + 2
       and then Out_Buf (Cursor - 1) = Octet (Value / 256)
       and then Out_Buf (Cursor) = Octet (Value mod 256)
       and then (for all I in Out_Buf'Range =>
                   (if I < Cursor - 1 or else I > Cursor
                    then Out_Buf (I) = Out_Buf'Old (I)));

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
       and then (for all K in 0 .. Bytes'Length - 1 =>
                   Out_Buf (Cursor'Old + 1 + K) = Bytes (Bytes'First + K))
       and then (for all I in Out_Buf'Range =>
                   (if I <= Cursor'Old or else I > Cursor
                    then Out_Buf (I) = Out_Buf'Old (I)));

   --  Patch a u16 length-prefix at a remembered position.

   procedure Patch_U16
     (Out_Buf : in out Octet_Array; At_Pos : Natural; Value : Natural)
   with
     Pre =>
       Out_Buf'First = 1
       and then Out_Buf'Last >= 2
       and then At_Pos >= 1
       and then At_Pos < Out_Buf'Last
       and then Value <= 16#FFFF#;

   --  Encode a single Extension {u16 type, u16 len, body}.

   procedure Encode_Extension
     (Out_Buf    : in out Octet_Array;
      Cursor     : in out Natural;
      Ext_Type   : Natural;
      Body_Bytes : Octet_Array)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Ext_Type <= 16#FFFF#
       and then Body_Bytes'Length <= 16#FFFF#
       and then Out_Buf'Last >= Body_Bytes'Length + 4
       and then Cursor <= Out_Buf'Last - Body_Bytes'Length - 4,
     Post =>
       Cursor = Cursor'Old + Body_Bytes'Length + 4
       and then Cursor in 4 .. Out_Buf'Last;

   --  Reader helpers — consume from In_Bytes at Pos, advance Pos.

   procedure R_U8
     (In_Bytes : Octet_Array;
      Pos      : in out Natural;
      Value    : out Octet;
      OK       : in out Boolean)
   with
     Pre  =>
       In_Bytes'First = 1
       and then In_Bytes'Last < Natural'Last - 1
       and then Pos >= 1
       and then Pos <= In_Bytes'Last + 1,
     Post =>
       Pos >= Pos'Old
       and then Pos >= 1
       and then Pos <= In_Bytes'Last + 1
       and then (if OK
                 then
                   Pos'Old <= In_Bytes'Last
                   and then Value = In_Bytes (Pos'Old)
                   and then Pos = Pos'Old + 1);

   procedure R_U16
     (In_Bytes : Octet_Array;
      Pos      : in out Natural;
      Value    : out Natural;
      OK       : in out Boolean)
   with
     Pre  =>
       In_Bytes'First = 1
       and then In_Bytes'Last < Natural'Last - 1
       and then Pos >= 1
       and then Pos <= In_Bytes'Last + 1,
     Post =>
       Pos >= Pos'Old
       and then Pos >= 1
       and then Pos <= In_Bytes'Last + 1
       and then (if OK
                 then
                   Pos'Old + 1 <= In_Bytes'Last
                   and then Value
                            = Natural (In_Bytes (Pos'Old))
                              * 256
                              + Natural (In_Bytes (Pos'Old + 1))
                   and then Pos = Pos'Old + 2);

   --  Find an extension of given type inside an extensions block,
   --  return its body slice indices [first..last] in In_Bytes.

   procedure Find_Extension
     (In_Bytes   : Octet_Array;
      Pos        : Natural;
      --  start of extensions block (after u16 len)
      End_Pos    : Natural;
      --  one past last byte of extensions block
      Ext_Type   : Natural;
      Body_First : out Natural;
      Body_Last  : out Natural;
      OK         : out Boolean)
   with
     Pre =>
       In_Bytes'First = 1
       and then In_Bytes'Last < Natural'Last - 4
       and then Pos >= 1
       and then Pos <= In_Bytes'Last + 1
       and then End_Pos <= In_Bytes'Last + 1;

end Tls_Core.Hello.Prims;
