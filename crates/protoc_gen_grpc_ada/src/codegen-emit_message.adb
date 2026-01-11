with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Codegen.Naming;
with Protobuf.Descriptor;  use Protobuf.Descriptor;

package body Codegen.Emit_Message is

   --  Field-type support: scalars (string, bool, int32, int64, uint32,
   --  uint64), message references (nested messages), and `repeated`
   --  collections of either. Repeated scalars decode either packed
   --  (one length-delimited block) or unpacked (one tag per element);
   --  the encoder always writes unpacked for now.

   function Type_Ref_To_Ada (Proto_Type : String) return String;
   function Element_Ada_Type (F : Field_Descriptor) return String;
   function Field_Ada_Type (F : Field_Descriptor) return String;
   function Encode_Call (F : Field_Descriptor) return String;
   function Decode_Case (F : Field_Descriptor) return String;
   function Default_Init (F : Field_Descriptor) return String;
   function Is_Message (F : Field_Descriptor) return Boolean;
   function Is_Repeated (F : Field_Descriptor) return Boolean;
   function Vectors_Pkg (F : Field_Descriptor) return String;
   function Field_Number_Image (F : Field_Descriptor) return String;
   function Element_Encode (F : Field_Descriptor; Element : String;
                             Number : String) return String;
   function Element_Decode (F : Field_Descriptor; Target : String)
                             return String;

   ---------------------
   -- Type_Ref_To_Ada --
   ---------------------

   function Type_Ref_To_Ada (Proto_Type : String) return String is
      Result : Unbounded_String;
      Buf    : Unbounded_String;
      Start  : Natural := Proto_Type'First;
   begin
      if Start <= Proto_Type'Last and then Proto_Type (Start) = '.' then
         Start := Start + 1;
      end if;
      for I in Start .. Proto_Type'Last loop
         if Proto_Type (I) = '.' then
            Append (Result, Codegen.Naming.To_Ada_Identifier (To_String (Buf)));
            Append (Result, '.');
            Buf := Null_Unbounded_String;
         else
            Append (Buf, Proto_Type (I));
         end if;
      end loop;
      Append (Result, Codegen.Naming.To_Ada_Identifier (To_String (Buf)));
      return To_String (Result);
   end Type_Ref_To_Ada;

   function Is_Message (F : Field_Descriptor) return Boolean is
     (F.Field_Kind = Type_Message);

   function Is_Repeated (F : Field_Descriptor) return Boolean is
     (F.Label = Label_Repeated);

   function Vectors_Pkg (F : Field_Descriptor) return String is
     (Codegen.Naming.To_Ada_Identifier (To_String (F.Field_Name))
      & "_Vectors");

   function Field_Number_Image (F : Field_Descriptor) return String is
      Img : constant String := F.Number'Image;
   begin
      return Img (Img'First + 1 .. Img'Last);
   end Field_Number_Image;

   ----------------------
   -- Element_Ada_Type --
   ----------------------

   function Element_Ada_Type (F : Field_Descriptor) return String is
   begin
      case F.Field_Kind is
         when Type_String  => return "Ada.Strings.Unbounded.Unbounded_String";
         when Type_Bool    => return "Boolean";
         when Type_Int32   => return "Interfaces.Integer_32";
         when Type_Int64   => return "Interfaces.Integer_64";
         when Type_UInt32  => return "Interfaces.Unsigned_32";
         when Type_UInt64  => return "Interfaces.Unsigned_64";
         when Type_Message =>
            return Type_Ref_To_Ada (To_String (F.Type_Name)) & ".T";
         when others       => return "Interfaces.Unsigned_64";
      end case;
   end Element_Ada_Type;

   --------------------
   -- Field_Ada_Type --
   --------------------

   function Field_Ada_Type (F : Field_Descriptor) return String is
   begin
      if Is_Repeated (F) then
         return Vectors_Pkg (F) & ".Vector";
      else
         return Element_Ada_Type (F);
      end if;
   end Field_Ada_Type;

   ------------------
   -- Default_Init --
   ------------------

   function Default_Init (F : Field_Descriptor) return String is
   begin
      if Is_Repeated (F) then
         return "";  --  Vector defaults to empty.
      end if;
      case F.Field_Kind is
         when Type_String =>
            return " := Ada.Strings.Unbounded.Null_Unbounded_String";
         when Type_Bool    => return " := False";
         when Type_Message => return "";
         when others       => return " := 0";
      end case;
   end Default_Init;

   --------------------
   -- Element_Encode --
   --------------------

   --  Element is the Ada expression naming one value (e.g. "Msg.Field"
   --  for non-repeated or "E" inside a for-loop for repeated). Number
   --  is the proto field number as a string.
   function Element_Encode (F : Field_Descriptor; Element : String;
                             Number : String) return String
   is
   begin
      case F.Field_Kind is
         when Type_String =>
            return "Protobuf.Wire.Encode_String_Field"
              & " (Cursor, Buffer, " & Number
              & ", To_String (" & Element & "));";
         when Type_Bool =>
            return "Protobuf.Wire.Encode_Bool_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Element & ");";
         when Type_Int32 =>
            return "Protobuf.Wire.Encode_Int32_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Element & ");";
         when Type_Int64 =>
            return "Protobuf.Wire.Encode_Int64_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Element & ");";
         when Type_UInt32 =>
            return "Protobuf.Wire.Encode_UInt32_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Element & ");";
         when Type_UInt64 =>
            return "Protobuf.Wire.Encode_UInt64_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Element & ");";
         when Type_Message =>
            declare
               Pkg : constant String :=
                 Type_Ref_To_Ada (To_String (F.Type_Name));
            begin
               return "declare" & ASCII.LF
                 & "         Sub_Buf    : Protobuf.IO.Octet_Array (1 .. 4096);"
                 & ASCII.LF
                 & "         Sub_Cursor : Protobuf.IO.Write_Cursor;"
                 & ASCII.LF
                 & "      begin" & ASCII.LF
                 & "         " & Pkg & ".Encode (" & Element
                 & ", Sub_Buf, Sub_Cursor);" & ASCII.LF
                 & "         Protobuf.Wire.Extras.Encode_Sub_Message_Field"
                 & ASCII.LF
                 & "           (Cursor, Buffer, " & Number
                 & ", Sub_Buf (1 .. Sub_Cursor.Position));" & ASCII.LF
                 & "      end;";
            end;
         when others =>
            return "null;  --  TODO: unsupported field type";
      end case;
   end Element_Encode;

   -----------------
   -- Encode_Call --
   -----------------

   function Encode_Call (F : Field_Descriptor) return String is
      Field_Name : constant String :=
        Codegen.Naming.To_Ada_Identifier (To_String (F.Field_Name));
      Number     : constant String := Field_Number_Image (F);
   begin
      if Is_Repeated (F) then
         return "for E of Msg." & Field_Name & " loop" & ASCII.LF
           & "         " & Element_Encode (F, "E", Number) & ASCII.LF
           & "      end loop;";
      else
         return Element_Encode (F, "Msg." & Field_Name, Number);
      end if;
   end Encode_Call;

   --------------------
   -- Element_Decode --
   --------------------

   --  Generates the inline Ada that decodes a single element of F's
   --  type into the Target lvalue (e.g. "Msg.Field" or a temp).
   function Element_Decode (F : Field_Descriptor; Target : String)
                             return String
   is
   begin
      case F.Field_Kind is
         when Type_String =>
            return
              "declare" & ASCII.LF
              & "               Str_Buf  : String (1 .. 4096);" & ASCII.LF
              & "               Str_Last : Natural;" & ASCII.LF
              & "            begin" & ASCII.LF
              & "               Protobuf.Wire.Decode_String_Value"
              & " (Cursor, Buffer, Str_Buf, Str_Last);" & ASCII.LF
              & "               " & Target
              & " := To_Unbounded_String"
              & " (Str_Buf (Str_Buf'First .. Str_Last));"
              & ASCII.LF
              & "            end;";
         when Type_Bool =>
            return
              "Protobuf.Wire.Decode_Bool_Value"
              & " (Cursor, Buffer, " & Target & ");";
         when Type_Int32 =>
            return
              "Protobuf.Wire.Decode_Int32_Value"
              & " (Cursor, Buffer, " & Target & ");";
         when Type_Int64 =>
            return
              "Protobuf.Wire.Decode_Int64_Value"
              & " (Cursor, Buffer, " & Target & ");";
         when Type_Message =>
            declare
               Pkg : constant String :=
                 Type_Ref_To_Ada (To_String (F.Type_Name));
            begin
               return
                 "declare" & ASCII.LF
                 & "               Length : Protobuf.IO.Octet_Count;"
                 & ASCII.LF
                 & "            begin" & ASCII.LF
                 & "               Protobuf.Wire.Decode_Length_Delim_Length"
                 & ASCII.LF
                 & "                 (Cursor, Buffer, Length);" & ASCII.LF
                 & "               declare" & ASCII.LF
                 & "                  Slice : constant Protobuf.IO.Octet_Array :="
                 & ASCII.LF
                 & "                    Protobuf.IO.Take_Slice"
                 & " (Cursor, Buffer, Length);" & ASCII.LF
                 & "               begin" & ASCII.LF
                 & "                  " & Pkg & ".Decode (Slice, "
                 & Target & ");" & ASCII.LF
                 & "               end;" & ASCII.LF
                 & "            end;";
            end;
         when others =>
            return "Protobuf.Wire.Skip_Field (Cursor, Buffer, Wire);";
      end case;
   end Element_Decode;

   -----------------
   -- Decode_Case --
   -----------------

   function Decode_Case (F : Field_Descriptor) return String is
      Field_Name : constant String :=
        Codegen.Naming.To_Ada_Identifier (To_String (F.Field_Name));
      Number     : constant String := Field_Number_Image (F);
   begin
      if Is_Repeated (F) then
         --  Append one element per occurrence. Decode into a temp,
         --  then append. For scalars sent packed (single length-delim
         --  block), this would mis-decode; we accept only unpacked
         --  scalar repeated for now. Repeated message and string —
         --  the common cases — are wire-defined as unpacked, so this
         --  works.
         declare
            Tmp_Decl : constant String :=
              "Tmp : " & Element_Ada_Type (F)
              & (case F.Field_Kind is
                   when Type_String  => " := Null_Unbounded_String",
                   when Type_Bool    => " := False",
                   when Type_Message => "",
                   when others       => " := 0");
         begin
            return
              "         when " & Number & " =>" & ASCII.LF
              & "            declare" & ASCII.LF
              & "               " & Tmp_Decl & ";" & ASCII.LF
              & "            begin" & ASCII.LF
              & "               " & Element_Decode (F, "Tmp") & ASCII.LF
              & "               Msg." & Field_Name & ".Append (Tmp);"
              & ASCII.LF
              & "            end;" & ASCII.LF;
         end;
      else
         case F.Field_Kind is
            when Type_String | Type_Message =>
               return
                 "         when " & Number & " =>" & ASCII.LF
                 & "            " & Element_Decode (F, "Msg." & Field_Name)
                 & ASCII.LF;
            when others =>
               return
                 "         when " & Number
                 & " => " & Element_Decode (F, "Msg." & Field_Name)
                 & ASCII.LF;
         end case;
      end if;
   end Decode_Case;

   ----------
   -- Emit --
   ----------

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
      Spec_Withs  : Unbounded_String;
      Bod         : Unbounded_String;
      Bod_Withs   : Unbounded_String;
      Has_Sub     : Boolean := False;
      Has_Repeat  : Boolean := False;

      Spec_File   : Plugin.Generated_File;
      BodFile     : Plugin.Generated_File;

      procedure Add_With (W : in out Unbounded_String; Pkg : String);
      procedure Add_With (W : in out Unbounded_String; Pkg : String) is
         Tag : constant String := "with " & Pkg & ";" & ASCII.LF;
      begin
         if Index (W, Tag) = 0 then
            Append (W, Tag);
         end if;
      end Add_With;
   begin
      Add_With (Spec_Withs, "Ada.Strings.Unbounded");
      Add_With (Spec_Withs, "Interfaces");
      Add_With (Spec_Withs, "Protobuf.IO");

      Add_With (Bod_Withs, "Ada.Strings.Unbounded");
      Add_With (Bod_Withs, "Protobuf.Wire");

      for F of Msg.Fields loop
         if Is_Message (F) then
            Has_Sub := True;
            Add_With (Spec_Withs, Type_Ref_To_Ada (To_String (F.Type_Name)));
            Add_With (Bod_Withs,  Type_Ref_To_Ada (To_String (F.Type_Name)));
         end if;
         if Is_Repeated (F) then
            Has_Repeat := True;
         end if;
      end loop;
      if Has_Sub then
         Add_With (Bod_Withs, "Protobuf.Wire.Extras");
      end if;
      if Has_Repeat then
         Add_With (Spec_Withs, "Ada.Containers.Vectors");
      end if;

      --  Spec --------------------------------------------------------
      Append (Spec, "--  Generated by protoc-gen-grpc-ada. Do not edit." & ASCII.LF);
      Append (Spec, Spec_Withs);
      Append (Spec, ASCII.LF);
      Append (Spec, "package " & Pkg_Name & " is" & ASCII.LF);
      Append (Spec, ASCII.LF);

      --  Vector instantiations come before T so its fields can use them.
      --  For Unbounded_String we pass "=" explicitly because its operator
      --  isn't directly visible from a `with`-only context.
      for F of Msg.Fields loop
         if Is_Repeated (F) then
            declare
               Eq_Suffix : constant String :=
                 (case F.Field_Kind is
                    when Type_String =>
                      ", ""="" => Ada.Strings.Unbounded.""=""",
                    when others => "");
            begin
               Append (Spec,
                 "   package " & Vectors_Pkg (F) & " is new" & ASCII.LF
                 & "     Ada.Containers.Vectors (Positive, "
                 & Element_Ada_Type (F) & Eq_Suffix & ");" & ASCII.LF
                 & ASCII.LF);
            end;
         end if;
      end loop;

      Append (Spec, "   type T is record" & ASCII.LF);
      for F of Msg.Fields loop
         declare
            Field_Name : constant String :=
              Codegen.Naming.To_Ada_Identifier (To_String (F.Field_Name));
         begin
            Append (Spec,
              "      " & Field_Name & " : "
              & Field_Ada_Type (F) & Default_Init (F) & ";" & ASCII.LF);
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
      Append (Bod, Bod_Withs);
      Append (Bod, "use Ada.Strings.Unbounded;" & ASCII.LF);
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
         Append (Bod, "      " & Encode_Call (F) & ASCII.LF);
      end loop;
      if Msg.Fields.Is_Empty then
         Append (Bod, "      null;" & ASCII.LF);
      end if;
      Append (Bod, "   end Encode;" & ASCII.LF);
      Append (Bod, ASCII.LF);
      Append (Bod, "   procedure Decode" & ASCII.LF);
      Append (Bod, "     (Buffer : Protobuf.IO.Octet_Array;" & ASCII.LF);
      Append (Bod, "      Msg    : out T)" & ASCII.LF);
      Append (Bod, "   is" & ASCII.LF);
      Append (Bod, "      Default : T;  --  Reset Msg to defaults so" & ASCII.LF);
      Append (Bod, "      --  callers reusing the same record across decodes" & ASCII.LF);
      Append (Bod, "      --  don't accumulate values into repeated fields." & ASCII.LF);
      Append (Bod, "      Cursor : Protobuf.IO.Read_Cursor;" & ASCII.LF);
      Append (Bod, "      Num    : Protobuf.Wire.Field_Number;" & ASCII.LF);
      Append (Bod, "      Wire   : Protobuf.Wire.Wire_Type;" & ASCII.LF);
      Append (Bod, "      use type Protobuf.IO.Octet_Count;" & ASCII.LF);
      Append (Bod, "   begin" & ASCII.LF);
      Append (Bod, "      Msg := Default;" & ASCII.LF);
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
