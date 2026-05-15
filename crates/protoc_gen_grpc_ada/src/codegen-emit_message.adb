with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Codegen.Emit_Message_Bounded;
with Codegen.Naming;
with Interfaces;
with Protobuf.Descriptor;  use Protobuf.Descriptor;

package body Codegen.Emit_Message is

   use type Interfaces.Integer_32;

   function Type_Ref_To_Ada (Proto_Type : String) return String;
   function Element_Ada_Type (F : Field_Descriptor) return String;
   function Field_Ada_Type (F : Field_Descriptor) return String;
   function Encode_Call (F : Field_Descriptor) return String;
   function Decode_Case (F : Field_Descriptor) return String;
   function Default_Init (F : Field_Descriptor) return String;
   function Is_Message (F : Field_Descriptor) return Boolean;
   function Is_Repeated (F : Field_Descriptor) return Boolean;
   function Is_Real_Oneof (F : Field_Descriptor) return Boolean;
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

   function Is_Real_Oneof (F : Field_Descriptor) return Boolean is
     (F.Oneof_Index >= 0 and then not F.Proto3_Optional);

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
         when Type_Bytes   => return "Ada.Strings.Unbounded.Unbounded_String";
         when Type_Bool    => return "Boolean";
         when Type_Int32 | Type_SInt32 | Type_SFixed32
                           => return "Interfaces.Integer_32";
         when Type_Int64 | Type_SInt64 | Type_SFixed64
                           => return "Interfaces.Integer_64";
         when Type_UInt32 | Type_Fixed32
                           => return "Interfaces.Unsigned_32";
         when Type_UInt64 | Type_Fixed64
                           => return "Interfaces.Unsigned_64";
         when Type_Float   => return "Interfaces.IEEE_Float_32";
         when Type_Double  => return "Interfaces.IEEE_Float_64";
         when Type_Enum    =>
            return Type_Ref_To_Ada (To_String (F.Type_Name)) & ".T";
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
         return "";
      end if;
      case F.Field_Kind is
         when Type_String | Type_Bytes =>
            return " := Ada.Strings.Unbounded.Null_Unbounded_String";
         when Type_Bool    => return " := False";
         when Type_Float   => return " := 0.0";
         when Type_Double  => return " := 0.0";
         when Type_Message => return "";
         when Type_Enum    => return "";
         when others       => return " := 0";
      end case;
   end Default_Init;

   --------------------
   -- Element_Encode --
   --------------------

   function Element_Encode (F : Field_Descriptor; Element : String;
                             Number : String) return String
   is
   begin
      case F.Field_Kind is
         when Type_String | Type_Bytes =>
            return "Protobuf.Wire.Encode_String_Field"
              & " (Cursor, Buffer, " & Number
              & ", To_String (" & Element & "));";
         when Type_Bool =>
            return "Protobuf.Wire.Encode_Bool_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Element & ");";
         when Type_Int32 | Type_SInt32 | Type_SFixed32 =>
            return "Protobuf.Wire.Encode_Int32_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Element & ");";
         when Type_Int64 | Type_SInt64 | Type_SFixed64 =>
            return "Protobuf.Wire.Encode_Int64_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Element & ");";
         when Type_UInt32 | Type_Fixed32 =>
            return "Protobuf.Wire.Encode_UInt32_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Element & ");";
         when Type_UInt64 | Type_Fixed64 =>
            return "Protobuf.Wire.Encode_UInt64_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Element & ");";
         when Type_Float =>
            return "Protobuf.Wire.Encode_Float_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Element & ");";
         when Type_Double =>
            return "Protobuf.Wire.Encode_Double_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Element & ");";
         when Type_Enum =>
            return "Protobuf.Wire.Encode_Int32_Field"
              & " (Cursor, Buffer, " & Number
              & ", " & Element & "'Enum_Rep);";
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

   function Element_Decode (F : Field_Descriptor; Target : String)
                             return String
   is
   begin
      case F.Field_Kind is
         when Type_String | Type_Bytes =>
            return
              "declare" & ASCII.LF
              & "               Str_Buf  : String (1 .. 64 * 1024);" & ASCII.LF
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
         when Type_Int32 | Type_SInt32 | Type_SFixed32 =>
            return
              "Protobuf.Wire.Decode_Int32_Value"
              & " (Cursor, Buffer, " & Target & ");";
         when Type_Int64 | Type_SInt64 | Type_SFixed64 =>
            return
              "Protobuf.Wire.Decode_Int64_Value"
              & " (Cursor, Buffer, " & Target & ");";
         when Type_UInt32 | Type_Fixed32 =>
            return
              "Protobuf.Wire.Decode_UInt32_Value"
              & " (Cursor, Buffer, " & Target & ");";
         when Type_UInt64 | Type_Fixed64 =>
            return
              "Protobuf.Wire.Decode_UInt64_Value"
              & " (Cursor, Buffer, " & Target & ");";
         when Type_Float =>
            return
              "Protobuf.Wire.Decode_Float_Value"
              & " (Cursor, Buffer, " & Target & ");";
         when Type_Double =>
            return
              "Protobuf.Wire.Decode_Double_Value"
              & " (Cursor, Buffer, " & Target & ");";
         when Type_Enum =>
            declare
               Pkg : constant String :=
                 Type_Ref_To_Ada (To_String (F.Type_Name));
            begin
               return
                 "declare" & ASCII.LF
                 & "               V : Interfaces.Unsigned_64;" & ASCII.LF
                 & "            begin" & ASCII.LF
                 & "               Protobuf.Wire.Decode_Varint_64"
                 & " (Cursor, Buffer, V);" & ASCII.LF
                 & "               " & Target
                 & " := " & Pkg & ".T'Enum_Val (V);" & ASCII.LF
                 & "            end;";
            end;
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
         declare
            Tmp_Decl : constant String :=
              "Tmp : " & Element_Ada_Type (F)
              & (case F.Field_Kind is
                   when Type_String | Type_Bytes
                                    => " := Null_Unbounded_String",
                   when Type_Bool   => " := False",
                   when Type_Float | Type_Double
                                    => " := 0.0",
                   when Type_Enum   => "",
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
      Files      : in out Plugin.Generated_File_Vectors.Vector;
      Bounded    : Boolean := False)
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

      Num_Oneofs  : constant Natural :=
        Natural (Msg.Oneof_Decl_Names.Length);

      Oneof_Emitted : array (0 .. Integer'Max (Num_Oneofs - 1, 0))
        of Boolean := (others => False);

      function Oneof_Ada (Idx : Interfaces.Integer_32) return String is
        (Codegen.Naming.To_Ada_Identifier
           (To_String
              (Msg.Oneof_Decl_Names.Element (Positive (Idx + 1)))));

      function Has_Real_Members (Idx : Integer) return Boolean;
      function Has_Real_Members (Idx : Integer) return Boolean is
      begin
         for F of Msg.Fields loop
            if F.Oneof_Index = Interfaces.Integer_32 (Idx)
              and then not F.Proto3_Optional
            then
               return True;
            end if;
         end loop;
         return False;
      end Has_Real_Members;

      procedure Add_With (W : in out Unbounded_String; Pkg : String);
      procedure Add_With (W : in out Unbounded_String; Pkg : String) is
         Tag : constant String := "with " & Pkg & ";" & ASCII.LF;
      begin
         if Index (W, Tag) = 0 then
            Append (W, Tag);
         end if;
      end Add_With;
   begin
      if Bounded then
         Codegen.Emit_Message_Bounded.Emit (Msg, Pkg_Prefix, Files);
         return;
      end if;
      Add_With (Spec_Withs, "Ada.Strings.Unbounded");
      Add_With (Spec_Withs, "Interfaces");
      Add_With (Spec_Withs, "Protobuf.IO");

      Add_With (Bod_Withs, "Ada.Strings.Unbounded");
      Add_With (Bod_Withs, "Protobuf.Wire");

      for F of Msg.Fields loop
         if Is_Message (F) or else F.Field_Kind = Type_Enum then
            if Is_Message (F) then Has_Sub := True; end if;
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
      for F of Msg.Fields loop
         if Is_Repeated (F) then
            declare
               Eq_Suffix : constant String :=
                 (case F.Field_Kind is
                    when Type_String | Type_Bytes =>
                      ", ""="" => Ada.Strings.Unbounded.""=""",
                    when Type_Int32 | Type_SInt32 | Type_SFixed32
                       | Type_Int64 | Type_SInt64 | Type_SFixed64
                       | Type_UInt32 | Type_Fixed32
                       | Type_UInt64 | Type_Fixed64
                       | Type_Float | Type_Double =>
                      ", ""="" => Interfaces.""=""",
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

      --  Oneof Kind enum declarations (before the record).
      for Idx in 0 .. Num_Oneofs - 1 loop
         if Has_Real_Members (Idx) then
            declare
               OA : constant String :=
                 Oneof_Ada (Interfaces.Integer_32 (Idx));
            begin
               Append (Spec,
                 "   type " & OA & "_Kind is" & ASCII.LF
                 & "     (" & OA & "_None");
               for F of Msg.Fields loop
                  if F.Oneof_Index = Interfaces.Integer_32 (Idx)
                    and then not F.Proto3_Optional
                  then
                     Append (Spec,
                       "," & ASCII.LF & "      " & OA & "_"
                       & Codegen.Naming.To_Ada_Identifier
                           (To_String (F.Field_Name)));
                  end if;
               end loop;
               Append (Spec, ");" & ASCII.LF & ASCII.LF);
            end;
         end if;
      end loop;

      --  Record fields.
      Append (Spec, "   type T is record" & ASCII.LF);
      for F of Msg.Fields loop
         declare
            Field_Name : constant String :=
              Codegen.Naming.To_Ada_Identifier (To_String (F.Field_Name));
         begin
            if Is_Real_Oneof (F) then
               declare
                  Idx : constant Integer := Integer (F.Oneof_Index);
               begin
                  if not Oneof_Emitted (Idx) then
                     Oneof_Emitted (Idx) := True;
                     declare
                        OA : constant String :=
                          Oneof_Ada (F.Oneof_Index);
                     begin
                        Append (Spec,
                          "      " & OA & "_Which : " & OA
                          & "_Kind := " & OA & "_None;" & ASCII.LF);
                     end;
                  end if;
               end;
            end if;
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

      --  Encode non-oneof fields.
      for F of Msg.Fields loop
         if not Is_Real_Oneof (F) then
            Append (Bod, "      " & Encode_Call (F) & ASCII.LF);
         end if;
      end loop;

      --  Encode oneof case statements.
      for Idx in 0 .. Num_Oneofs - 1 loop
         if Has_Real_Members (Idx) then
            declare
               OA : constant String :=
                 Oneof_Ada (Interfaces.Integer_32 (Idx));
            begin
               Append (Bod,
                 "      case Msg." & OA & "_Which is" & ASCII.LF
                 & "         when " & OA & "_None => null;" & ASCII.LF);
               for F of Msg.Fields loop
                  if F.Oneof_Index = Interfaces.Integer_32 (Idx)
                    and then not F.Proto3_Optional
                  then
                     declare
                        FN : constant String :=
                          Codegen.Naming.To_Ada_Identifier
                            (To_String (F.Field_Name));
                        Lit : constant String := OA & "_" & FN;
                        Num : constant String := Field_Number_Image (F);
                     begin
                        Append (Bod,
                          "         when " & Lit & " =>" & ASCII.LF
                          & "            "
                          & Element_Encode (F, "Msg." & FN, Num)
                          & ASCII.LF);
                     end;
                  end if;
               end loop;
               Append (Bod, "      end case;" & ASCII.LF);
            end;
         end if;
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
         if Is_Real_Oneof (F) then
            declare
               FN : constant String :=
                 Codegen.Naming.To_Ada_Identifier
                   (To_String (F.Field_Name));
               Num : constant String := Field_Number_Image (F);
               OA  : constant String := Oneof_Ada (F.Oneof_Index);
               Lit : constant String := OA & "_" & FN;
            begin
               Append (Bod,
                 "         when " & Num & " =>" & ASCII.LF
                 & "            Msg." & OA & "_Which := "
                 & Lit & ";" & ASCII.LF
                 & "            "
                 & Element_Decode (F, "Msg." & FN) & ASCII.LF);
            end;
         else
            Append (Bod, Decode_Case (F));
         end if;
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
