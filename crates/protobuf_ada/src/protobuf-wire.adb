with Interfaces; use Interfaces;

package body Protobuf.Wire is

   ----------------------
   -- Encode_Varint_32 --

   procedure Encode_Varint_32
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Value  : Unsigned_32)
   is
      V : Unsigned_32 := Value;
   begin
      while V >= 16#80# loop
         Protobuf.IO.Write_Octet
           (C, Buffer,
            Protobuf.IO.Octet ((V and 16#7F#) or 16#80#));
         V := Shift_Right (V, 7);
      end loop;
      Protobuf.IO.Write_Octet (C, Buffer, Protobuf.IO.Octet (V));
   end Encode_Varint_32;

   ----------------------
   -- Decode_Varint_32 --

   procedure Decode_Varint_32
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Unsigned_32)
   is
      Octet : Protobuf.IO.Octet;
      Shift : Natural := 0;
      Acc   : Unsigned_32 := 0;
   begin
      for Byte_Index in 1 .. Max_Varint_32 loop
         pragma Unreferenced (Byte_Index);
         if Protobuf.IO.Available (C, Buffer) = 0 then
            raise Wire_Format_Error with "truncated varint";
         end if;
         Protobuf.IO.Read_Octet (C, Buffer, Octet);
         Acc := Acc or Shift_Left (Unsigned_32 (Octet) and 16#7F#, Shift);
         if (Unsigned_32 (Octet) and 16#80#) = 0 then
            Value := Acc;
            return;
         end if;
         Shift := Shift + 7;
      end loop;
      raise Wire_Format_Error with "32-bit varint exceeded 5 bytes";
   end Decode_Varint_32;

   ----------------------
   -- Encode_Varint_64 --

   procedure Encode_Varint_64
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Value  : Unsigned_64)
   is
      V : Unsigned_64 := Value;
   begin
      while V >= 16#80# loop
         Protobuf.IO.Write_Octet
           (C, Buffer,
            Protobuf.IO.Octet ((V and 16#7F#) or 16#80#));
         V := Shift_Right (V, 7);
      end loop;
      Protobuf.IO.Write_Octet (C, Buffer, Protobuf.IO.Octet (V));
   end Encode_Varint_64;

   ----------------------
   -- Decode_Varint_64 --

   procedure Decode_Varint_64
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Unsigned_64)
   is
      Octet : Protobuf.IO.Octet;
      Shift : Natural := 0;
      Acc   : Unsigned_64 := 0;
   begin
      for Byte_Index in 1 .. Max_Varint_64 loop
         pragma Unreferenced (Byte_Index);
         if Protobuf.IO.Available (C, Buffer) = 0 then
            raise Wire_Format_Error with "truncated varint";
         end if;
         Protobuf.IO.Read_Octet (C, Buffer, Octet);
         Acc := Acc or Shift_Left (Unsigned_64 (Octet) and 16#7F#, Shift);
         if (Unsigned_64 (Octet) and 16#80#) = 0 then
            Value := Acc;
            return;
         end if;
         Shift := Shift + 7;
      end loop;
      raise Wire_Format_Error with "64-bit varint exceeded 10 bytes";
   end Decode_Varint_64;

   ---------------
   -- Encode_Tag --

   procedure Encode_Tag
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Wire   : Wire_Type)
   is
      Tag : constant Unsigned_32 :=
        Shift_Left (Unsigned_32 (Number), 3)
        or Unsigned_32 (Wire_Type'Enum_Rep (Wire));
   begin
      Encode_Varint_32 (C, Buffer, Tag);
   end Encode_Tag;

   ----------------
   -- Decode_Tag --

   procedure Decode_Tag
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Number : out Field_Number;
      Wire   : out Wire_Type)
   is
      Tag       : Unsigned_32;
      Wire_Bits : Unsigned_32;
      Num_Bits  : Unsigned_32;
   begin
      Decode_Varint_32 (C, Buffer, Tag);
      Wire_Bits := Tag and 16#07#;
      Num_Bits  := Shift_Right (Tag, 3);
      if Num_Bits = 0 then
         raise Wire_Format_Error with "zero field number";
      end if;
      if Num_Bits > Field_Number'Last then
         raise Wire_Format_Error with "field number out of range";
      end if;
      if Num_Bits in 19_000 .. 19_999 then
         raise Wire_Format_Error with "reserved field number";
      end if;
      if Wire_Bits > 5 then
         raise Wire_Format_Error with "unknown wire type";
      end if;
      Number := Field_Number (Num_Bits);
      Wire   := Wire_Type'Enum_Val (Wire_Bits);
   end Decode_Tag;

end Protobuf.Wire;
