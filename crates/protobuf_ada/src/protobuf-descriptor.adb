with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Interfaces;             use Interfaces;
with Protobuf.Wire;

package body Protobuf.Descriptor is

   --  Each message is decoded from its own Octet_Array slice. For any
   --  field number we don't model we delegate to Wire.Skip_Field.

   --  Local helpers -----------------------------------------------------

   function Bytes_To_String (B : Protobuf.IO.Octet_Array) return String;

   function Read_String
     (Buffer : Protobuf.IO.Octet_Array;
      Cursor : in out Protobuf.IO.Read_Cursor) return Unbounded_String;

   function Read_Bool
     (Buffer : Protobuf.IO.Octet_Array;
      Cursor : in out Protobuf.IO.Read_Cursor) return Boolean;

   function Read_Int32
     (Buffer : Protobuf.IO.Octet_Array;
      Cursor : in out Protobuf.IO.Read_Cursor) return Integer_32;

   function Read_Sub_Message
     (Buffer : Protobuf.IO.Octet_Array;
      Cursor : in out Protobuf.IO.Read_Cursor) return Protobuf.IO.Octet_Array;

   procedure Decode_Field
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out Field_Descriptor);

   procedure Decode_Enum_Value
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out Enum_Value);

   procedure Decode_Enum
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out Enum_Descriptor);

   procedure Decode_Message
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out Message_Descriptor);

   procedure Decode_Method
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out Method_Descriptor);

   procedure Decode_Service
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out Service_Descriptor);

   procedure Decode_File
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out File_Descriptor);

   ---------------------
   -- Bytes_To_String --

   function Bytes_To_String (B : Protobuf.IO.Octet_Array) return String is
      use type Protobuf.IO.Octet_Offset;
      Result : String (1 .. Natural (B'Length));
   begin
      for I in Result'Range loop
         Result (I) := Character'Val
           (B (B'First + Protobuf.IO.Octet_Offset (I - 1)));
      end loop;
      return Result;
   end Bytes_To_String;

   -----------------
   -- Read_String --

   function Read_String
     (Buffer : Protobuf.IO.Octet_Array;
      Cursor : in out Protobuf.IO.Read_Cursor) return Unbounded_String
   is
      Length : Protobuf.IO.Octet_Count;
   begin
      Protobuf.Wire.Decode_Length_Delim_Length (Cursor, Buffer, Length);
      return To_Unbounded_String
        (Bytes_To_String
           (Protobuf.IO.Take_Slice (Cursor, Buffer, Length)));
   end Read_String;

   ---------------
   -- Read_Bool --

   function Read_Bool
     (Buffer : Protobuf.IO.Octet_Array;
      Cursor : in out Protobuf.IO.Read_Cursor) return Boolean
   is
      V : Unsigned_64;
   begin
      Protobuf.Wire.Decode_Varint_64 (Cursor, Buffer, V);
      return V /= 0;
   end Read_Bool;

   ----------------
   -- Read_Int32 --

   function Read_Int32
     (Buffer : Protobuf.IO.Octet_Array;
      Cursor : in out Protobuf.IO.Read_Cursor) return Integer_32
   is
      V : Unsigned_64;
   begin
      Protobuf.Wire.Decode_Varint_64 (Cursor, Buffer, V);
      return Integer_32 (Integer_64 (V));
   end Read_Int32;
   --  Note: int32 is encoded as varint over 64 bits when negative; we
   --  truncate via the chained conversion. Safe for descriptor field
   --  numbers (always positive).

   -----------------------
   -- Read_Sub_Message --

   function Read_Sub_Message
     (Buffer : Protobuf.IO.Octet_Array;
      Cursor : in out Protobuf.IO.Read_Cursor) return Protobuf.IO.Octet_Array
   is
      Length : Protobuf.IO.Octet_Count;
   begin
      Protobuf.Wire.Decode_Length_Delim_Length (Cursor, Buffer, Length);
      return Protobuf.IO.Take_Slice (Cursor, Buffer, Length);
   end Read_Sub_Message;

   ------------------
   -- Decode_Field --

   procedure Decode_Field
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out Field_Descriptor)
   is
      use type Protobuf.IO.Octet_Count;
      Cursor : Protobuf.IO.Read_Cursor;
      Num    : Protobuf.Wire.Field_Number;
      Wire   : Protobuf.Wire.Wire_Type;
      V      : Unsigned_64;
   begin
      while Protobuf.IO.Available (Cursor, Buffer) > 0 loop
         Protobuf.Wire.Decode_Tag (Cursor, Buffer, Num, Wire);
         case Num is
            when 1  => Result.Field_Name := Read_String (Buffer, Cursor);
            when 3  => Result.Number     := Read_Int32  (Buffer, Cursor);
            when 4  =>
               Protobuf.Wire.Decode_Varint_64 (Cursor, Buffer, V);
               Result.Label := Field_Label'Enum_Val (V);
            when 5  =>
               Protobuf.Wire.Decode_Varint_64 (Cursor, Buffer, V);
               Result.Field_Kind := Field_Type'Enum_Val (V);
            when 6  => Result.Type_Name       := Read_String (Buffer, Cursor);
            when 9  => Result.Oneof_Index     := Read_Int32  (Buffer, Cursor);
            when 17 => Result.Proto3_Optional := Read_Bool   (Buffer, Cursor);
            when others =>
               Protobuf.Wire.Skip_Field (Cursor, Buffer, Wire);
         end case;
      end loop;
   end Decode_Field;

   -----------------------
   -- Decode_Enum_Value --

   procedure Decode_Enum_Value
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out Enum_Value)
   is
      use type Protobuf.IO.Octet_Count;
      Cursor : Protobuf.IO.Read_Cursor;
      Num    : Protobuf.Wire.Field_Number;
      Wire   : Protobuf.Wire.Wire_Type;
   begin
      while Protobuf.IO.Available (Cursor, Buffer) > 0 loop
         Protobuf.Wire.Decode_Tag (Cursor, Buffer, Num, Wire);
         case Num is
            when 1 => Result.Value_Name := Read_String (Buffer, Cursor);
            when 2 => Result.Number     := Read_Int32  (Buffer, Cursor);
            when others =>
               Protobuf.Wire.Skip_Field (Cursor, Buffer, Wire);
         end case;
      end loop;
   end Decode_Enum_Value;

   -----------------
   -- Decode_Enum --

   procedure Decode_Enum
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out Enum_Descriptor)
   is
      use type Protobuf.IO.Octet_Count;
      Cursor : Protobuf.IO.Read_Cursor;
      Num    : Protobuf.Wire.Field_Number;
      Wire   : Protobuf.Wire.Wire_Type;
   begin
      while Protobuf.IO.Available (Cursor, Buffer) > 0 loop
         Protobuf.Wire.Decode_Tag (Cursor, Buffer, Num, Wire);
         case Num is
            when 1 => Result.Enum_Name := Read_String (Buffer, Cursor);
            when 2 =>
               declare
                  Sub : constant Protobuf.IO.Octet_Array :=
                    Read_Sub_Message (Buffer, Cursor);
                  V   : Enum_Value;
               begin
                  Decode_Enum_Value (Sub, V);
                  Result.Values.Append (V);
               end;
            when others =>
               Protobuf.Wire.Skip_Field (Cursor, Buffer, Wire);
         end case;
      end loop;
   end Decode_Enum;

   --------------------
   -- Decode_Message --

   procedure Decode_Message
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out Message_Descriptor)
   is
      use type Protobuf.IO.Octet_Count;
      Cursor : Protobuf.IO.Read_Cursor;
      Num    : Protobuf.Wire.Field_Number;
      Wire   : Protobuf.Wire.Wire_Type;
   begin
      while Protobuf.IO.Available (Cursor, Buffer) > 0 loop
         Protobuf.Wire.Decode_Tag (Cursor, Buffer, Num, Wire);
         case Num is
            when 1 => Result.Message_Name := Read_String (Buffer, Cursor);
            when 2 =>
               declare
                  Sub : constant Protobuf.IO.Octet_Array :=
                    Read_Sub_Message (Buffer, Cursor);
                  F   : Field_Descriptor;
               begin
                  Decode_Field (Sub, F);
                  Result.Fields.Append (F);
               end;
            when 3 =>
               declare
                  Sub : constant Protobuf.IO.Octet_Array :=
                    Read_Sub_Message (Buffer, Cursor);
                  M   : constant Message_Descriptor_Access :=
                    new Message_Descriptor;
               begin
                  Decode_Message (Sub, M.all);
                  Result.Nested_Types.Append (M);
               end;
            when 4 =>
               declare
                  Sub : constant Protobuf.IO.Octet_Array :=
                    Read_Sub_Message (Buffer, Cursor);
                  E   : Enum_Descriptor;
               begin
                  Decode_Enum (Sub, E);
                  Result.Enums.Append (E);
               end;
            when 8 =>
               declare
                  Sub     : constant Protobuf.IO.Octet_Array :=
                    Read_Sub_Message (Buffer, Cursor);
                  Inner_C : Protobuf.IO.Read_Cursor;
                  Inner_N : Protobuf.Wire.Field_Number;
                  Inner_W : Protobuf.Wire.Wire_Type;
                  Oneof_N : Name;
               begin
                  while Protobuf.IO.Available (Inner_C, Sub) > 0 loop
                     Protobuf.Wire.Decode_Tag
                       (Inner_C, Sub, Inner_N, Inner_W);
                     case Inner_N is
                        when 1 =>
                           Oneof_N := Read_String (Sub, Inner_C);
                        when others =>
                           Protobuf.Wire.Skip_Field
                             (Inner_C, Sub, Inner_W);
                     end case;
                  end loop;
                  Result.Oneof_Decl_Names.Append (Oneof_N);
               end;
            when others =>
               Protobuf.Wire.Skip_Field (Cursor, Buffer, Wire);
         end case;
      end loop;
   end Decode_Message;

   -------------------
   -- Decode_Method --

   procedure Decode_Method
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out Method_Descriptor)
   is
      use type Protobuf.IO.Octet_Count;
      Cursor : Protobuf.IO.Read_Cursor;
      Num    : Protobuf.Wire.Field_Number;
      Wire   : Protobuf.Wire.Wire_Type;
   begin
      while Protobuf.IO.Available (Cursor, Buffer) > 0 loop
         Protobuf.Wire.Decode_Tag (Cursor, Buffer, Num, Wire);
         case Num is
            when 1 => Result.Method_Name      := Read_String (Buffer, Cursor);
            when 2 => Result.Input_Type       := Read_String (Buffer, Cursor);
            when 3 => Result.Output_Type      := Read_String (Buffer, Cursor);
            when 5 => Result.Client_Streaming := Read_Bool   (Buffer, Cursor);
            when 6 => Result.Server_Streaming := Read_Bool   (Buffer, Cursor);
            when others =>
               Protobuf.Wire.Skip_Field (Cursor, Buffer, Wire);
         end case;
      end loop;
   end Decode_Method;

   --------------------
   -- Decode_Service --

   procedure Decode_Service
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out Service_Descriptor)
   is
      use type Protobuf.IO.Octet_Count;
      Cursor : Protobuf.IO.Read_Cursor;
      Num    : Protobuf.Wire.Field_Number;
      Wire   : Protobuf.Wire.Wire_Type;
   begin
      while Protobuf.IO.Available (Cursor, Buffer) > 0 loop
         Protobuf.Wire.Decode_Tag (Cursor, Buffer, Num, Wire);
         case Num is
            when 1 => Result.Service_Name := Read_String (Buffer, Cursor);
            when 2 =>
               declare
                  Sub : constant Protobuf.IO.Octet_Array :=
                    Read_Sub_Message (Buffer, Cursor);
                  M   : Method_Descriptor;
               begin
                  Decode_Method (Sub, M);
                  Result.Methods.Append (M);
               end;
            when others =>
               Protobuf.Wire.Skip_Field (Cursor, Buffer, Wire);
         end case;
      end loop;
   end Decode_Service;

   -----------------
   -- Decode_File --

   procedure Decode_File
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out File_Descriptor)
   is
      use type Protobuf.IO.Octet_Count;
      Cursor : Protobuf.IO.Read_Cursor;
      Num    : Protobuf.Wire.Field_Number;
      Wire   : Protobuf.Wire.Wire_Type;
   begin
      while Protobuf.IO.Available (Cursor, Buffer) > 0 loop
         Protobuf.Wire.Decode_Tag (Cursor, Buffer, Num, Wire);
         case Num is
            when 1  => Result.File_Name    := Read_String (Buffer, Cursor);
            when 2  => Result.Package_Name := Read_String (Buffer, Cursor);
            when 12 => Result.Syntax       := Read_String (Buffer, Cursor);
            when 4 =>
               declare
                  Sub : constant Protobuf.IO.Octet_Array :=
                    Read_Sub_Message (Buffer, Cursor);
                  M   : constant Message_Descriptor_Access :=
                    new Message_Descriptor;
               begin
                  Decode_Message (Sub, M.all);
                  Result.Messages.Append (M);
               end;
            when 5 =>
               declare
                  Sub : constant Protobuf.IO.Octet_Array :=
                    Read_Sub_Message (Buffer, Cursor);
                  E   : Enum_Descriptor;
               begin
                  Decode_Enum (Sub, E);
                  Result.Enums.Append (E);
               end;
            when 6 =>
               declare
                  Sub : constant Protobuf.IO.Octet_Array :=
                    Read_Sub_Message (Buffer, Cursor);
                  S   : Service_Descriptor;
               begin
                  Decode_Service (Sub, S);
                  Result.Services.Append (S);
               end;
            when others =>
               Protobuf.Wire.Skip_Field (Cursor, Buffer, Wire);
         end case;
      end loop;
   end Decode_File;

   ------------
   -- Decode --

   procedure Decode
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out File_Descriptor_Set)
   is
      use type Protobuf.IO.Octet_Count;
      Cursor : Protobuf.IO.Read_Cursor;
      Num    : Protobuf.Wire.Field_Number;
      Wire   : Protobuf.Wire.Wire_Type;
   begin
      while Protobuf.IO.Available (Cursor, Buffer) > 0 loop
         Protobuf.Wire.Decode_Tag (Cursor, Buffer, Num, Wire);
         case Num is
            when 1 =>
               declare
                  Sub : constant Protobuf.IO.Octet_Array :=
                    Read_Sub_Message (Buffer, Cursor);
                  F   : File_Descriptor;
               begin
                  Decode_File (Sub, F);
                  Result.Files.Append (F);
               end;
            when others =>
               Protobuf.Wire.Skip_Field (Cursor, Buffer, Wire);
         end case;
      end loop;
   end Decode;

end Protobuf.Descriptor;
