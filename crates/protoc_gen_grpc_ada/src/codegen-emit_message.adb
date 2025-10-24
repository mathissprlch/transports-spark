with Codegen.Naming;
with Protobuf.Descriptor;  use Protobuf.Descriptor;

package body Codegen.Emit_Message is

   --  We support a small subset of field types in this commit: string,
   --  bool, int32, int64, uint32, uint64. Repeated and message-type
   --  fields land in subsequent commits.

   function Ada_Field_Type (F : Field_Descriptor) return String;
   function Encode_Call (F : Field_Descriptor; Receiver : String)
                         return String;
   function Decode_Case (F : Field_Descriptor) return String;

   --------------------
   -- Ada_Field_Type --

   function Ada_Field_Type (F : Field_Descriptor) return String is
   begin
      case F.Field_Kind is
         when Type_String => return "Ada.Strings.Unbounded.Unbounded_String";
         when Type_Bool   => return "Boolean";
         when Type_Int32  => return "Interfaces.Integer_32";
         when Type_Int64  => return "Interfaces.Integer_64";
         when Type_UInt32 => return "Interfaces.Unsigned_32";
         when Type_UInt64 => return "Interfaces.Unsigned_64";
         when others      => return "Interfaces.Unsigned_64";
            --  Placeholder for unsupported types — codegen for those
            --  lands later. Compiles, just won't behave correctly.
      end case;
   end Ada_Field_Type;

   -----------------
   -- Encode_Call --

   function Encode_Call (F : Field_Descriptor; Receiver : String)
                         return String
   is
      Field_Name : constant String :=
        Codegen.Naming.To_Ada_Identifier (To_String (F.Field_Name));
      Number_Img : constant String := F.Number'Image;  --  leading space
      Number     : constant String := Number_Img (Number_Img'First + 1
                                                  .. Number_Img'Last);
   begin
      case F.Field_Kind is
         when Type_String =>
            return "Protobuf.Wire.Encode_String_Field"
              & " (Cursor, Buffer, " & Number
              & ", To_String (" & Receiver & "." & Field_Name & "));";
         when Type_Bool =>
            return "Protobuf.Wire.Encode_Bool_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Receiver & "." & Field_Name & ");";
         when Type_Int32 =>
            return "Protobuf.Wire.Encode_Int32_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Receiver & "." & Field_Name & ");";
         when Type_Int64 =>
            return "Protobuf.Wire.Encode_Int64_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Receiver & "." & Field_Name & ");";
         when Type_UInt32 =>
            return "Protobuf.Wire.Encode_UInt32_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Receiver & "." & Field_Name & ");";
         when Type_UInt64 =>
            return "Protobuf.Wire.Encode_UInt64_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Receiver & "." & Field_Name & ");";
         when others =>
            return "null;  --  TODO: unsupported field type";
      end case;
   end Encode_Call;

   -----------------
   -- Decode_Case --

   function Decode_Case (F : Field_Descriptor) return String is
      Field_Name : constant String :=
        Codegen.Naming.To_Ada_Identifier (To_String (F.Field_Name));
      Number_Img : constant String := F.Number'Image;
      Number     : constant String := Number_Img (Number_Img'First + 1
                                                  .. Number_Img'Last);
   begin
      case F.Field_Kind is
         when Type_String =>
            return
              "         when " & Number & " => " & ASCII.LF
              & "            declare" & ASCII.LF
              & "               Tmp : String (1 .. 4096);" & ASCII.LF
              & "               Last : Natural;" & ASCII.LF
              & "            begin" & ASCII.LF
              & "               Protobuf.Wire.Decode_String_Value"
              & " (Cursor, Buffer, Tmp, Last);" & ASCII.LF
              & "               Msg." & Field_Name
              & " := To_Unbounded_String"
              & " (Tmp (Tmp'First .. Last));" & ASCII.LF
              & "            end;" & ASCII.LF;
         when Type_Bool =>
            return
              "         when " & Number
              & " => Protobuf.Wire.Decode_Bool_Value"
              & " (Cursor, Buffer, Msg." & Field_Name & ");" & ASCII.LF;
         when Type_Int32 =>
            return
              "         when " & Number
              & " => Protobuf.Wire.Decode_Int32_Value"
              & " (Cursor, Buffer, Msg." & Field_Name & ");" & ASCII.LF;
         when Type_Int64 =>
            return
              "         when " & Number
              & " => Protobuf.Wire.Decode_Int64_Value"
              & " (Cursor, Buffer, Msg." & Field_Name & ");" & ASCII.LF;
         when others =>
            return
              "         when " & Number
              & " => Protobuf.Wire.Skip_Field (Cursor, Buffer, Wire);"
              & ASCII.LF;
      end case;
   end Decode_Case;

   ----------
   -- Emit --

   procedure Emit
     (Msg        : Protobuf.Descriptor.Message_Descriptor;
      Pkg_Prefix : String;
      Files      : in out Plugin.Generated_File_Vectors.Vector)
   is
      Msg_Ident   : constant String :=
        Codegen.Naming.To_Ada_Identifier (To_String (Msg.Message_Name));
      Pkg_Name    : constant String := Pkg_Prefix & "." & Msg_Ident;
      File_Stem   : constant String := Codegen.Naming.To_File_Stem (Pkg_Name);
      Spec        : Unbounded_String;
      Bod       : Unbounded_String;

      Spec_File   : Plugin.Generated_File;
      BodFile   : Plugin.Generated_File;
   begin
      --  Spec --------------------------------------------------------
      Append (Spec, "--  Generated by protoc-gen-grpc-ada. Do not edit." & ASCII.LF);
      Append (Spec, "with Ada.Strings.Unbounded;" & ASCII.LF);
      Append (Spec, "with Interfaces;" & ASCII.LF);
      Append (Spec, "with Protobuf.IO;" & ASCII.LF);
      Append (Spec, ASCII.LF);
      Append (Spec, "package " & Pkg_Name & " is" & ASCII.LF);
      Append (Spec, ASCII.LF);
      Append (Spec, "   type T is record" & ASCII.LF);

      for F of Msg.Fields loop
         declare
            Field_Name : constant String :=
              Codegen.Naming.To_Ada_Identifier (To_String (F.Field_Name));
            Default : constant String :=
              (case F.Field_Kind is
                 when Type_String =>
                   " := Ada.Strings.Unbounded.Null_Unbounded_String",
                 when Type_Bool => " := False",
                 when others    => " := 0");
         begin
            Append (Spec,
              "      " & Field_Name & " : "
              & Ada_Field_Type (F) & Default & ";" & ASCII.LF);
         end;
      end loop;

      Append (Spec, "   end record;" & ASCII.LF);
      Append (Spec, ASCII.LF);
      Append (Spec, "   procedure Encode" & ASCII.LF);
      Append (Spec, "     (Msg    : T;" & ASCII.LF);
      Append (Spec, "      Buffer : in out Protobuf.IO.Octet_Array;" & ASCII.LF);
      Append (Spec, "      Cursor : in out Protobuf.IO.Write_Cursor);" & ASCII.LF);
      Append (Spec, ASCII.LF);
      Append (Spec, "   procedure Decode" & ASCII.LF);
      Append (Spec, "     (Buffer : Protobuf.IO.Octet_Array;" & ASCII.LF);
      Append (Spec, "      Msg    : out T);" & ASCII.LF);
      Append (Spec, ASCII.LF);
      Append (Spec, "end " & Pkg_Name & ";" & ASCII.LF);

      --  Body --------------------------------------------------------
      Append (Bod, "--  Generated by protoc-gen-grpc-ada. Do not edit." & ASCII.LF);
      Append (Bod, "with Ada.Strings.Unbounded;" & ASCII.LF);
      Append (Bod, "use Ada.Strings.Unbounded;" & ASCII.LF);
      Append (Bod, "with Protobuf.Wire;" & ASCII.LF);
      Append (Bod, ASCII.LF);
      Append (Bod, "package body " & Pkg_Name & " is" & ASCII.LF);
      Append (Bod, ASCII.LF);
      Append (Bod, "   procedure Encode" & ASCII.LF);
      Append (Bod, "     (Msg    : T;" & ASCII.LF);
      Append (Bod, "      Buffer : in out Protobuf.IO.Octet_Array;" & ASCII.LF);
      Append (Bod, "      Cursor : in out Protobuf.IO.Write_Cursor)" & ASCII.LF);
      Append (Bod, "   is" & ASCII.LF);
      Append (Bod, "   begin" & ASCII.LF);
      for F of Msg.Fields loop
         Append (Bod, "      " & Encode_Call (F, "Msg") & ASCII.LF);
      end loop;
      Append (Bod, "   end Encode;" & ASCII.LF);
      Append (Bod, ASCII.LF);
      Append (Bod, "   procedure Decode" & ASCII.LF);
      Append (Bod, "     (Buffer : Protobuf.IO.Octet_Array;" & ASCII.LF);
      Append (Bod, "      Msg    : out T)" & ASCII.LF);
      Append (Bod, "   is" & ASCII.LF);
      Append (Bod, "      Cursor : Protobuf.IO.Read_Cursor;" & ASCII.LF);
      Append (Bod, "      Num    : Protobuf.Wire.Field_Number;" & ASCII.LF);
      Append (Bod, "      Wire   : Protobuf.Wire.Wire_Type;" & ASCII.LF);
      Append (Bod, "      use type Protobuf.IO.Octet_Count;" & ASCII.LF);
      Append (Bod, "   begin" & ASCII.LF);
      Append (Bod, "      while Protobuf.IO.Available (Cursor, Buffer) > 0 loop" & ASCII.LF);
      Append (Bod, "         Protobuf.Wire.Decode_Tag"
                  & " (Cursor, Buffer, Num, Wire);" & ASCII.LF);
      Append (Bod, "         case Num is" & ASCII.LF);
      for F of Msg.Fields loop
         Append (Bod, Decode_Case (F));
      end loop;
      Append (Bod, "         when others =>" & ASCII.LF);
      Append (Bod, "            Protobuf.Wire.Skip_Field"
                  & " (Cursor, Buffer, Wire);" & ASCII.LF);
      Append (Bod, "         end case;" & ASCII.LF);
      Append (Bod, "      end loop;" & ASCII.LF);
      Append (Bod, "   end Decode;" & ASCII.LF);
      Append (Bod, ASCII.LF);
      Append (Bod, "end " & Pkg_Name & ";" & ASCII.LF);

      Spec_File.File_Name := To_Unbounded_String (File_Stem & ".ads");
      Spec_File.Content   := Spec;
      BodFile.File_Name := To_Unbounded_String (File_Stem & ".adb");
      BodFile.Content   := Bod;
      Files.Append (Spec_File);
      Files.Append (BodFile);
   end Emit;

end Codegen.Emit_Message;
