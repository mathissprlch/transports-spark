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

   --  Fixed-width -----------------------------------------------------
   --
   --  Little-endian 32- and 64-bit values. Used directly for fixed32,
   --  sfixed32, fixed64, sfixed64, float, double — for the signed and
   --  float variants pair with the bit-cast helpers below.

   procedure Encode_Fixed_32
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Value  : Interfaces.Unsigned_32)
     with Pre => Protobuf.IO.Free (C, Buffer) >= 4;

   procedure Decode_Fixed_32
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Interfaces.Unsigned_32)
     with Pre => Protobuf.IO.Available (C, Buffer) >= 4;

   procedure Encode_Fixed_64
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Value  : Interfaces.Unsigned_64)
     with Pre => Protobuf.IO.Free (C, Buffer) >= 8;

   procedure Decode_Fixed_64
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Interfaces.Unsigned_64)
     with Pre => Protobuf.IO.Available (C, Buffer) >= 8;

   --  Float bit-casts. IEEE 754. Use these to convert to/from the wire
   --  Unsigned_32/64 representation that Encode/Decode_Fixed expects.
   function To_Bits   (Value : Interfaces.IEEE_Float_32) return Interfaces.Unsigned_32;
   function From_Bits (Value : Interfaces.Unsigned_32)   return Interfaces.IEEE_Float_32;
   function To_Bits   (Value : Interfaces.IEEE_Float_64) return Interfaces.Unsigned_64;
   function From_Bits (Value : Interfaces.Unsigned_64)   return Interfaces.IEEE_Float_64;

   --  ZigZag -----------------------------------------------------------
   --
   --  Maps signed values into unsigned so small magnitudes (positive or
   --  negative) take few varint bytes. Used for sint32/sint64.

   function ZigZag_Encode_32
     (Value : Interfaces.Integer_32) return Interfaces.Unsigned_32;

   function ZigZag_Decode_32
     (Value : Interfaces.Unsigned_32) return Interfaces.Integer_32;

   function ZigZag_Encode_64
     (Value : Interfaces.Integer_64) return Interfaces.Unsigned_64;

   function ZigZag_Decode_64
     (Value : Interfaces.Unsigned_64) return Interfaces.Integer_64;

   --  Length-delimited -------------------------------------------------

   procedure Encode_Length_Delim_Bytes
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Bytes  : Protobuf.IO.Octet_Array);
   --  Writes varint(Bytes'Length) followed by Bytes.

   procedure Decode_Length_Delim_Length
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Length : out Protobuf.IO.Octet_Count);
   --  Reads the varint length prefix only. Caller then consumes that many
   --  bytes from C. Raises Wire_Format_Error on overflow or truncation.

   --  Skip an unknown field (after its tag has been read). Required for
   --  forward compatibility per the protobuf spec — decoders must accept
   --  fields they don't recognise.
   procedure Skip_Field
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Wire   : Wire_Type);

   --  Field-level helpers ---------------------------------------------
   --
   --  Each "Encode_X_Field" writes the tag and value of a single field;
   --  generated message-encode code calls these directly. The matching
   --  decoders consume the value AFTER the tag has already been read
   --  (so they take the wire type used in the tag for sanity).

   procedure Encode_String_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : String);

   procedure Encode_Bytes_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Protobuf.IO.Octet_Array);

   procedure Encode_Bool_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Boolean);

   procedure Encode_Int32_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Interfaces.Integer_32);

   procedure Encode_Int64_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Interfaces.Integer_64);

   procedure Encode_UInt32_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Interfaces.Unsigned_32);

   procedure Encode_UInt64_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Interfaces.Unsigned_64);

   --  Decoders read the value only — the tag has already been consumed.

   procedure Decode_String_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out String;
      Last   : out Natural);
   --  Reads a length-delimited field and copies up to Value'Length bytes
   --  into Value, setting Last to the number of bytes filled. If the
   --  encoded length exceeds Value'Length, raises Wire_Format_Error.

   procedure Decode_Bool_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Boolean);

   procedure Decode_Int32_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Interfaces.Integer_32);

   procedure Decode_Int64_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Interfaces.Integer_64);

   procedure Decode_UInt32_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Interfaces.Unsigned_32);

   procedure Decode_UInt64_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Interfaces.Unsigned_64);

   procedure Decode_Bytes_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Protobuf.IO.Octet_Array;
      Last   : out Protobuf.IO.Octet_Offset);

   procedure Encode_Float_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Interfaces.IEEE_Float_32);

   procedure Decode_Float_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Interfaces.IEEE_Float_32);

   procedure Encode_Double_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Interfaces.IEEE_Float_64);

   procedure Decode_Double_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Interfaces.IEEE_Float_64);

   --  Errors -----------------------------------------------------------

   Wire_Format_Error : exception;
   --  Malformed wire input: oversized varint, unknown wire type, truncated
   --  message, etc. Always raised at the boundary, never propagated up.

end Protobuf.Wire;
