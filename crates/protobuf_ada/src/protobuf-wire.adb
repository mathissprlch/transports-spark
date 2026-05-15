with Ada.Unchecked_Conversion;
with Interfaces; use Interfaces;

package body Protobuf.Wire is

   function To_Unsigned_32 is
     new Ada.Unchecked_Conversion (Integer_32, Unsigned_32);

   function To_Signed_32 is
     new Ada.Unchecked_Conversion (Unsigned_32, Integer_32);

   function To_Unsigned_64 is
     new Ada.Unchecked_Conversion (Integer_64, Unsigned_64);

   function To_Signed_64 is
     new Ada.Unchecked_Conversion (Unsigned_64, Integer_64);

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

   ----------------------
   -- Encode_Fixed_32 --

   procedure Encode_Fixed_32
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Value  : Unsigned_32)
   is
   begin
      for I in 0 .. 3 loop
         Protobuf.IO.Write_Octet
           (C, Buffer,
            Protobuf.IO.Octet (Shift_Right (Value, I * 8) and 16#FF#));
      end loop;
   end Encode_Fixed_32;

   ----------------------
   -- Decode_Fixed_32 --

   procedure Decode_Fixed_32
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Unsigned_32)
   is
      Octet : Protobuf.IO.Octet;
      Acc   : Unsigned_32 := 0;
   begin
      for I in 0 .. 3 loop
         Protobuf.IO.Read_Octet (C, Buffer, Octet);
         Acc := Acc or Shift_Left (Unsigned_32 (Octet), I * 8);
      end loop;
      Value := Acc;
   end Decode_Fixed_32;

   ----------------------
   -- Encode_Fixed_64 --

   procedure Encode_Fixed_64
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Value  : Unsigned_64)
   is
   begin
      for I in 0 .. 7 loop
         Protobuf.IO.Write_Octet
           (C, Buffer,
            Protobuf.IO.Octet (Shift_Right (Value, I * 8) and 16#FF#));
      end loop;
   end Encode_Fixed_64;

   ----------------------
   -- Decode_Fixed_64 --

   procedure Decode_Fixed_64
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Unsigned_64)
   is
      Octet : Protobuf.IO.Octet;
      Acc   : Unsigned_64 := 0;
   begin
      for I in 0 .. 7 loop
         Protobuf.IO.Read_Octet (C, Buffer, Octet);
         Acc := Acc or Shift_Left (Unsigned_64 (Octet), I * 8);
      end loop;
      Value := Acc;
   end Decode_Fixed_64;

   ----------------------
   --  Float bit-casts. --

   function To_Bits (Value : IEEE_Float_32) return Unsigned_32 is
      function Conv is new Ada.Unchecked_Conversion (IEEE_Float_32, Unsigned_32);
   begin
      return Conv (Value);
   end To_Bits;

   function From_Bits (Value : Unsigned_32) return IEEE_Float_32 is
      function Conv is new Ada.Unchecked_Conversion (Unsigned_32, IEEE_Float_32);
   begin
      return Conv (Value);
   end From_Bits;

   function To_Bits (Value : IEEE_Float_64) return Unsigned_64 is
      function Conv is new Ada.Unchecked_Conversion (IEEE_Float_64, Unsigned_64);
   begin
      return Conv (Value);
   end To_Bits;

   function From_Bits (Value : Unsigned_64) return IEEE_Float_64 is
      function Conv is new Ada.Unchecked_Conversion (Unsigned_64, IEEE_Float_64);
   begin
      return Conv (Value);
   end From_Bits;

   ----------------------
   -- ZigZag_Encode_32 --

   function ZigZag_Encode_32 (Value : Integer_32) return Unsigned_32 is
      U : constant Unsigned_32 := To_Unsigned_32 (Value);
   begin
      return Shift_Left (U, 1) xor Shift_Right_Arithmetic (U, 31);
   end ZigZag_Encode_32;

   ----------------------
   -- ZigZag_Decode_32 --

   function ZigZag_Decode_32 (Value : Unsigned_32) return Integer_32 is
      Mask : constant Unsigned_32 := -(Value and 1);  --  0 or all-ones
   begin
      return To_Signed_32 (Shift_Right (Value, 1) xor Mask);
   end ZigZag_Decode_32;

   ----------------------
   -- ZigZag_Encode_64 --

   function ZigZag_Encode_64 (Value : Integer_64) return Unsigned_64 is
      U : constant Unsigned_64 := To_Unsigned_64 (Value);
   begin
      return Shift_Left (U, 1) xor Shift_Right_Arithmetic (U, 63);
   end ZigZag_Encode_64;

   ----------------------
   -- ZigZag_Decode_64 --

   function ZigZag_Decode_64 (Value : Unsigned_64) return Integer_64 is
      Mask : constant Unsigned_64 := -(Value and 1);
   begin
      return To_Signed_64 (Shift_Right (Value, 1) xor Mask);
   end ZigZag_Decode_64;

   --------------------------------
   -- Encode_Length_Delim_Bytes  --

   procedure Encode_Length_Delim_Bytes
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Bytes  : Protobuf.IO.Octet_Array)
   is
   begin
      Encode_Varint_64 (C, Buffer, Unsigned_64 (Bytes'Length));
      Protobuf.IO.Write_Octets (C, Buffer, Bytes);
   end Encode_Length_Delim_Bytes;

   ---------------------------------
   -- Decode_Length_Delim_Length  --

   procedure Decode_Length_Delim_Length
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Length : out Protobuf.IO.Octet_Count)
   is
      Raw : Unsigned_64;
   begin
      Decode_Varint_64 (C, Buffer, Raw);
      if Raw > Unsigned_64 (Protobuf.IO.Octet_Count'Last) then
         raise Wire_Format_Error with "length-delim length out of range";
      end if;
      Length := Protobuf.IO.Octet_Count (Raw);
      if Length > Protobuf.IO.Available (C, Buffer) then
         raise Wire_Format_Error with "length-delim past buffer end";
      end if;
   end Decode_Length_Delim_Length;

   ----------------
   -- Skip_Field --

   procedure Skip_Field
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Wire   : Wire_Type)
   is
      Throwaway_64 : Unsigned_64;
      Throwaway_32 : Unsigned_32;
      Length       : Protobuf.IO.Octet_Count;
   begin
      case Wire is
         when Varint =>
            Decode_Varint_64 (C, Buffer, Throwaway_64);
         when Fixed_64 =>
            Decode_Fixed_64 (C, Buffer, Throwaway_64);
         when Fixed_32 =>
            Decode_Fixed_32 (C, Buffer, Throwaway_32);
         when Length_Delim =>
            Decode_Length_Delim_Length (C, Buffer, Length);
            Protobuf.IO.Skip (C, Buffer, Length);
         when Start_Group | End_Group =>
            raise Wire_Format_Error
              with "group wire types are deprecated and not supported";
      end case;
   end Skip_Field;

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

   --  Field-level helpers --------------------------------------------

   procedure Encode_String_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : String)
   is
      Bytes : Protobuf.IO.Octet_Array (1 .. Value'Length);
   begin
      for I in Value'Range loop
         Bytes (Protobuf.IO.Octet_Offset (I - Value'First + 1)) :=
           Protobuf.IO.Octet (Character'Pos (Value (I)));
      end loop;
      Encode_Tag (C, Buffer, Number, Length_Delim);
      Encode_Length_Delim_Bytes (C, Buffer, Bytes);
   end Encode_String_Field;

   procedure Encode_Bytes_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Protobuf.IO.Octet_Array)
   is
   begin
      Encode_Tag (C, Buffer, Number, Length_Delim);
      Encode_Length_Delim_Bytes (C, Buffer, Value);
   end Encode_Bytes_Field;

   procedure Encode_Bool_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Boolean)
   is
   begin
      Encode_Tag (C, Buffer, Number, Varint);
      Protobuf.IO.Write_Octet (C, Buffer, (if Value then 1 else 0));
   end Encode_Bool_Field;

   procedure Encode_Int32_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Integer_32)
   is
   begin
      Encode_Tag (C, Buffer, Number, Varint);
      --  int32 sign-extends to 64 bits when negative; encode as varint64.
      Encode_Varint_64 (C, Buffer, Unsigned_64 (To_Unsigned_64 (Integer_64 (Value))));
   end Encode_Int32_Field;

   procedure Encode_Int64_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Integer_64)
   is
   begin
      Encode_Tag (C, Buffer, Number, Varint);
      Encode_Varint_64 (C, Buffer, To_Unsigned_64 (Value));
   end Encode_Int64_Field;

   procedure Encode_UInt32_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Unsigned_32)
   is
   begin
      Encode_Tag (C, Buffer, Number, Varint);
      Encode_Varint_32 (C, Buffer, Value);
   end Encode_UInt32_Field;

   procedure Encode_UInt64_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Unsigned_64)
   is
   begin
      Encode_Tag (C, Buffer, Number, Varint);
      Encode_Varint_64 (C, Buffer, Value);
   end Encode_UInt64_Field;

   --  Decoders --------------------------------------------------------

   procedure Decode_String_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out String;
      Last   : out Natural)
   is
      Length : Protobuf.IO.Octet_Count;
   begin
      Decode_Length_Delim_Length (C, Buffer, Length);
      if Natural (Length) > Value'Length then
         raise Wire_Format_Error with "string longer than caller buffer";
      end if;
      declare
         Slice : constant Protobuf.IO.Octet_Array :=
           Protobuf.IO.Take_Slice (C, Buffer, Length);
      begin
         for I in 1 .. Natural (Length) loop
            Value (Value'First + I - 1) :=
              Character'Val (Slice (Slice'First
                              + Protobuf.IO.Octet_Offset (I - 1)));
         end loop;
         Last := Value'First + Natural (Length) - 1;
      end;
   end Decode_String_Value;

   procedure Decode_Bool_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Boolean)
   is
      V : Unsigned_64;
   begin
      Decode_Varint_64 (C, Buffer, V);
      Value := V /= 0;
   end Decode_Bool_Value;

   procedure Decode_Int32_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Integer_32)
   is
      V : Unsigned_64;
   begin
      Decode_Varint_64 (C, Buffer, V);
      Value := Integer_32 (Integer_64 (To_Signed_64 (V)));
   end Decode_Int32_Value;

   procedure Decode_Int64_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Integer_64)
   is
      V : Unsigned_64;
   begin
      Decode_Varint_64 (C, Buffer, V);
      Value := To_Signed_64 (V);
   end Decode_Int64_Value;

   procedure Decode_UInt32_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Unsigned_32)
   is
      V : Unsigned_64;
   begin
      Decode_Varint_64 (C, Buffer, V);
      Value := Unsigned_32 (V and 16#FFFF_FFFF#);
   end Decode_UInt32_Value;

   procedure Decode_UInt64_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Unsigned_64)
   is
   begin
      Decode_Varint_64 (C, Buffer, Value);
   end Decode_UInt64_Value;

   procedure Decode_Bytes_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Protobuf.IO.Octet_Array;
      Last   : out Protobuf.IO.Octet_Offset)
   is
      use type Protobuf.IO.Octet_Offset;
      Length : Protobuf.IO.Octet_Count;
   begin
      Decode_Length_Delim_Length (C, Buffer, Length);
      if Protobuf.IO.Octet_Offset (Length) > Value'Length then
         raise Wire_Format_Error with "bytes longer than caller buffer";
      end if;
      declare
         Slice : constant Protobuf.IO.Octet_Array :=
           Protobuf.IO.Take_Slice (C, Buffer, Length);
      begin
         for I in 1 .. Protobuf.IO.Octet_Offset (Length) loop
            Value (Value'First + I - 1) :=
              Slice (Slice'First + I - 1);
         end loop;
         Last := Value'First + Protobuf.IO.Octet_Offset (Length) - 1;
      end;
   end Decode_Bytes_Value;

   procedure Encode_Float_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Interfaces.IEEE_Float_32)
   is
   begin
      Encode_Tag (C, Buffer, Number, Fixed_32);
      Encode_Fixed_32 (C, Buffer, To_Bits (Value));
   end Encode_Float_Field;

   procedure Decode_Float_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Interfaces.IEEE_Float_32)
   is
      Bits : Unsigned_32;
   begin
      Decode_Fixed_32 (C, Buffer, Bits);
      Value := From_Bits (Bits);
   end Decode_Float_Value;

   procedure Encode_Double_Field
     (C      : in out Protobuf.IO.Write_Cursor;
      Buffer : in out Protobuf.IO.Octet_Array;
      Number : Field_Number;
      Value  : Interfaces.IEEE_Float_64)
   is
   begin
      Encode_Tag (C, Buffer, Number, Fixed_64);
      Encode_Fixed_64 (C, Buffer, To_Bits (Value));
   end Encode_Double_Field;

   procedure Decode_Double_Value
     (C      : in out Protobuf.IO.Read_Cursor;
      Buffer : Protobuf.IO.Octet_Array;
      Value  : out Interfaces.IEEE_Float_64)
   is
      Bits : Unsigned_64;
   begin
      Decode_Fixed_64 (C, Buffer, Bits);
      Value := From_Bits (Bits);
   end Decode_Double_Value;

end Protobuf.Wire;
