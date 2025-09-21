--  Protobuf.Wire
--
--  The protobuf wire format. Operates on Octet_Arrays via Read_Cursor /
--  Write_Cursor from Protobuf.IO.

with Ada.Streams;
with Interfaces;
with Protobuf.IO;

package Protobuf.Wire
  with Pure
is
   use type Ada.Streams.Stream_Element_Offset;

   --  Wire types per
   --  https://protobuf.dev/programming-guides/encoding/#structure
   type Wire_Type is
     (Varint,         --  0
      Fixed_64,       --  1
      Length_Delim,   --  2
      Start_Group,    --  3 (deprecated)
      End_Group,      --  4 (deprecated)
      Fixed_32);      --  5

   for Wire_Type use
     (Varint       => 0,
      Fixed_64     => 1,
      Length_Delim => 2,
      Start_Group  => 3,
      End_Group    => 4,
      Fixed_32     => 5);
   for Wire_Type'Size use 8;

   --  Field numbers are 1 .. 2**29 - 1 with 19000 .. 19999 reserved by the
   --  protobuf runtime.
   subtype Field_Number is Interfaces.Unsigned_32 range 1 .. 16#1FFF_FFFF#;

   --  Worst-case varint widths (in bytes).
   Max_Varint_32 : constant := 5;
   Max_Varint_64 : constant := 10;

   --  Tag --------------------------------------------------------------
   --
   --  tag = (Field_Number << 3) | Wire_Type, encoded as a 32-bit varint.

   procedure Encode_Tag
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Wire   : Wire_Type)
     with Pre => Protobuf.IO.Free (C, Buffer) >= Max_Varint_32;

   procedure Decode_Tag
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Number : out Field_Number;
      Wire   : out Wire_Type);

   --  Varint -----------------------------------------------------------

   procedure Encode_Varint_32
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Value  : Interfaces.Unsigned_32)
     with Pre => Protobuf.IO.Free (C, Buffer) >= Max_Varint_32;

   procedure Decode_Varint_32
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Interfaces.Unsigned_32);

   procedure Encode_Varint_64
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Value  : Interfaces.Unsigned_64)
     with Pre => Protobuf.IO.Free (C, Buffer) >= Max_Varint_64;

   procedure Decode_Varint_64
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Interfaces.Unsigned_64);

   --  Errors -----------------------------------------------------------

   Wire_Format_Error : exception;
   --  Malformed wire input: oversized varint, unknown wire type, truncated
   --  message, etc. Always raised at the boundary, never propagated up.

end Protobuf.Wire;
