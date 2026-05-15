with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Codegen.Naming;
with Interfaces;
with Protobuf.Descriptor;  use Protobuf.Descriptor;

package body Codegen.Emit_Message_Bounded is

   use type Interfaces.Integer_32;

   function Type_Ref_To_Ada (Proto_Type : String) return String;
   function Is_Message  (F : Field_Descriptor) return Boolean is
     (F.Field_Kind = Type_Message);
   function Is_Repeated (F : Field_Descriptor) return Boolean is
     (F.Label = Label_Repeated);
   function Is_Real_Oneof (F : Field_Descriptor) return Boolean is
     (F.Oneof_Index >= 0 and then not F.Proto3_Optional);
   function Is_String (F : Field_Descriptor) return Boolean is
     (F.Field_Kind = Type_String);

   function Field_Number_Image (F : Field_Descriptor) return String is
      Img : constant String := F.Number'Image;
   begin
      return Img (Img'First + 1 .. Img'Last);
   end Field_Number_Image;

   function FN (F : Field_Descriptor) return String is
     (Codegen.Naming.To_Ada_Identifier (To_String (F.Field_Name)));

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

   function Scalar_Ada_Type (F : Field_Descriptor) return String is
   begin
      case F.Field_Kind is
         when Type_Bool   => return "Boolean";
         when Type_Int32 | Type_SInt32 | Type_SFixed32
                          => return "Interfaces.Integer_32";
         when Type_Int64 | Type_SInt64 | Type_SFixed64
                          => return "Interfaces.Integer_64";
         when Type_UInt32 | Type_Fixed32
                          => return "Interfaces.Unsigned_32";
         when Type_UInt64 | Type_Fixed64
                          => return "Interfaces.Unsigned_64";
         when Type_Float  => return "Interfaces.IEEE_Float_32";
         when Type_Double => return "Interfaces.IEEE_Float_64";
         when Type_Enum   =>
            return Type_Ref_To_Ada (To_String (F.Type_Name)) & ".T";
         when Type_Message =>
            return Type_Ref_To_Ada (To_String (F.Type_Name)) & ".T";
         when others      => return "Interfaces.Unsigned_64";
      end case;
   end Scalar_Ada_Type;

   function Scalar_Default (F : Field_Descriptor) return String is
   begin
      case F.Field_Kind is
         when Type_Bool    => return "False";
         when Type_Float   => return "0.0";
         when Type_Double  => return "0.0";
         when Type_Enum    => return Scalar_Ada_Type (F) & "'First";
         when Type_Message => return "(others => <>)";
         when others       => return "0";
      end case;
   end Scalar_Default;

   function Encode_Scalar (F : Field_Descriptor;
                           Expr : String; Num : String) return String is
   begin
      case F.Field_Kind is
         when Type_Bool =>
            return "Protobuf.Wire.Encode_Bool_Field"
              & " (Cursor, Buffer, " & Num & ", " & Expr & ");";
         when Type_Int32 | Type_SInt32 | Type_SFixed32 =>
            return "Protobuf.Wire.Encode_Int32_Field"
              & " (Cursor, Buffer, " & Num & ", " & Expr & ");";
         when Type_Int64 | Type_SInt64 | Type_SFixed64 =>
            return "Protobuf.Wire.Encode_Int64_Field"
              & " (Cursor, Buffer, " & Num & ", " & Expr & ");";
         when Type_UInt32 | Type_Fixed32 =>
            return "Protobuf.Wire.Encode_UInt32_Field"
              & " (Cursor, Buffer, " & Num & ", " & Expr & ");";
         when Type_UInt64 | Type_Fixed64 =>
            return "Protobuf.Wire.Encode_UInt64_Field"
              & " (Cursor, Buffer, " & Num & ", " & Expr & ");";
         when Type_Float =>
            return "Protobuf.Wire.Encode_Float_Field"
              & " (Cursor, Buffer, " & Num & ", " & Expr & ");";
         when Type_Double =>
            return "Protobuf.Wire.Encode_Double_Field"
              & " (Cursor, Buffer, " & Num & ", " & Expr & ");";
         when Type_Enum =>
            return "Protobuf.Wire.Encode_Int32_Field"
              & " (Cursor, Buffer, " & Num & ", " & Expr & "'Enum_Rep);";
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
                 & "         " & Pkg & ".Encode (" & Expr
                 & ", Sub_Buf, Sub_Cursor);" & ASCII.LF
                 & "         Protobuf.Wire.Extras.Encode_Sub_Message_Field"
                 & ASCII.LF
                 & "           (Cursor, Buffer, " & Num
                 & ", Sub_Buf (1 .. Sub_Cursor.Position));" & ASCII.LF
                 & "      end;";
            end;
         when others =>
            return "null;  --  TODO: unsupported field type";
      end case;
   end Encode_Scalar;

   function Decode_Scalar (F : Field_Descriptor;
                           Target : String) return String is
   begin
      case F.Field_Kind is
         when Type_Bool =>
            return "Protobuf.Wire.Decode_Bool_Value"
              & " (Cursor, Buffer, " & Target & ");";
         when Type_Int32 | Type_SInt32 | Type_SFixed32 =>
            return "Protobuf.Wire.Decode_Int32_Value"
              & " (Cursor, Buffer, " & Target & ");";
         when Type_Int64 | Type_SInt64 | Type_SFixed64 =>
            return "Protobuf.Wire.Decode_Int64_Value"
              & " (Cursor, Buffer, " & Target & ");";
         when Type_UInt32 | Type_Fixed32 =>
            return "Protobuf.Wire.Decode_UInt32_Value"
              & " (Cursor, Buffer, " & Target & ");";
         when Type_UInt64 | Type_Fixed64 =>
            return "Protobuf.Wire.Decode_UInt64_Value"
              & " (Cursor, Buffer, " & Target & ");";
         when Type_Float =>
            return "Protobuf.Wire.Decode_Float_Value"
              & " (Cursor, Buffer, " & Target & ");";
         when Type_Double =>
            return "Protobuf.Wire.Decode_Double_Value"
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
   end Decode_Scalar;

   ----------
   -- Emit --
   ----------

   procedure Emit
     (Msg        : Protobuf.Descriptor.Message_Descriptor;
      Pkg_Prefix : String;
      Files      : in out Plugin.Generated_File_Vectors.Vector)
   is
      Msg_Ident  : constant String :=
        Codegen.Naming.To_Ada_Identifier (To_String (Msg.Message_Name));
      Pkg_Name   : constant String := Pkg_Prefix & "." & Msg_Ident;
      File_Stem  : constant String := Codegen.Naming.To_File_Stem (Pkg_Name);
      Spec       : Unbounded_String;
      Bod        : Unbounded_String;
      Spec_Withs : Unbounded_String;
      Bod_Withs  : Unbounded_String;
      Has_Sub    : Boolean := False;

      Num_Oneofs : constant Natural :=
        Natural (Msg.Oneof_Decl_Names.Length);
      Oneof_Emitted : array (0 .. Integer'Max (Num_Oneofs - 1, 0))
        of Boolean := (others => False);

      function OA (Idx : Interfaces.Integer_32) return String is
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

      Spec_File : Plugin.Generated_File;
      Bod_File  : Plugin.Generated_File;
   begin
      Add_With (Spec_Withs, "Interfaces");
      Add_With (Spec_Withs, "Protobuf.IO");
      Add_With (Bod_Withs, "Protobuf.Wire");

      for F of Msg.Fields loop
         if Is_Message (F) or else F.Field_Kind = Type_Enum then
            if Is_Message (F) then Has_Sub := True; end if;
            Add_With (Spec_Withs, Type_Ref_To_Ada (To_String (F.Type_Name)));
            Add_With (Bod_Withs,  Type_Ref_To_Ada (To_String (F.Type_Name)));
         end if;
      end loop;
      if Has_Sub then
         Add_With (Bod_Withs, "Protobuf.Wire.Extras");
      end if;

      --  Spec --------------------------------------------------------
      Append (Spec, "--  Generated by protoc-gen-grpc-ada (bounded). "
                    & "Do not edit." & ASCII.LF);
      Append (Spec, Spec_Withs & ASCII.LF);
      Append (Spec, "package " & Pkg_Name & " is" & ASCII.LF & ASCII.LF);
      Append (Spec, "   Max_String_Len : constant := 4 * 1024 * 1024;" & ASCII.LF);
      Append (Spec, "   Max_Repeated   : constant := 1024;" & ASCII.LF);
      Append (Spec, "   subtype Field_String is String"
                    & " (1 .. Max_String_Len);" & ASCII.LF & ASCII.LF);

      --  Repeated-field array types.
      for F of Msg.Fields loop
         if Is_Repeated (F) then
            declare
               N : constant String := FN (F);
            begin
               if Is_String (F) then
                  Append (Spec,
                    "   type " & N & "_Str_Array is"
                    & " array (1 .. Max_Repeated) of Field_String;"
                    & ASCII.LF);
                  Append (Spec,
                    "   type " & N & "_Len_Array is"
                    & " array (1 .. Max_Repeated) of Natural;"
                    & ASCII.LF & ASCII.LF);
               else
                  Append (Spec,
                    "   type " & N & "_Array is"
                    & " array (1 .. Max_Repeated) of "
                    & Scalar_Ada_Type (F) & ";" & ASCII.LF & ASCII.LF);
               end if;
            end;
         end if;
      end loop;

      --  Oneof Kind enums.
      for Idx in 0 .. Num_Oneofs - 1 loop
         if Has_Real_Members (Idx) then
            declare
               Name : constant String :=
                 OA (Interfaces.Integer_32 (Idx));
            begin
               Append (Spec,
                 "   type " & Name & "_Kind is" & ASCII.LF
                 & "     (" & Name & "_None");
               for F of Msg.Fields loop
                  if F.Oneof_Index = Interfaces.Integer_32 (Idx)
                    and then not F.Proto3_Optional
                  then
                     Append (Spec,
                       "," & ASCII.LF & "      " & Name & "_" & FN (F));
                  end if;
               end loop;
               Append (Spec, ");" & ASCII.LF & ASCII.LF);
            end;
         end if;
      end loop;

      --  Record.
      Append (Spec, "   type T is record" & ASCII.LF);
      for F of Msg.Fields loop
         if Is_Real_Oneof (F) then
            declare
               Idx : constant Integer := Integer (F.Oneof_Index);
            begin
               if not Oneof_Emitted (Idx) then
                  Oneof_Emitted (Idx) := True;
                  declare
                     Name : constant String := OA (F.Oneof_Index);
                  begin
                     Append (Spec, "      " & Name & "_Which : "
                       & Name & "_Kind := " & Name & "_None;"
                       & ASCII.LF);
                  end;
               end if;
            end;
         end if;
         declare
            N : constant String := FN (F);
         begin
            if Is_String (F) and then not Is_Repeated (F) then
               Append (Spec,
                 "      " & N & " : Field_String"
                 & " := (others => ASCII.NUL);" & ASCII.LF);
               Append (Spec,
                 "      " & N & "_Len : Natural := 0;" & ASCII.LF);
            elsif Is_Repeated (F) then
               if Is_String (F) then
                  Append (Spec,
                    "      " & N & " : " & N & "_Str_Array"
                    & " := (others => (others => ASCII.NUL));" & ASCII.LF);
                  Append (Spec,
                    "      " & N & "_Lens : " & N & "_Len_Array"
                    & " := (others => 0);" & ASCII.LF);
               else
                  Append (Spec,
                    "      " & N & " : " & N & "_Array"
                    & " := (others => " & Scalar_Default (F) & ");"
                    & ASCII.LF);
               end if;
               Append (Spec,
                 "      " & N & "_Count : Natural := 0;" & ASCII.LF);
            else
               Append (Spec,
                 "      " & N & " : " & Scalar_Ada_Type (F)
                 & " := " & Scalar_Default (F) & ";" & ASCII.LF);
            end if;
         end;
      end loop;
      Append (Spec, "   end record;" & ASCII.LF & ASCII.LF);

      Append (Spec, "   procedure Encode" & ASCII.LF);
      Append (Spec, "     (Msg    : T;" & ASCII.LF);
      Append (Spec, "      Buffer : in out Protobuf.IO.Octet_Array;" & ASCII.LF);
      Append (Spec, "      Cursor : in out Protobuf.IO.Write_Cursor);"
                    & ASCII.LF & ASCII.LF);
      Append (Spec, "   procedure Decode" & ASCII.LF);
      Append (Spec, "     (Buffer : Protobuf.IO.Octet_Array;" & ASCII.LF);
      Append (Spec, "      Msg    : out T);" & ASCII.LF & ASCII.LF);
      Append (Spec, "end " & Pkg_Name & ";" & ASCII.LF);

      --  Body --------------------------------------------------------
      Append (Bod, "--  Generated by protoc-gen-grpc-ada (bounded). "
                   & "Do not edit." & ASCII.LF);
      Append (Bod, Bod_Withs & ASCII.LF);
      Append (Bod, "package body " & Pkg_Name & " is" & ASCII.LF & ASCII.LF);

      --  Encode
      Append (Bod, "   procedure Encode" & ASCII.LF);
      Append (Bod, "     (Msg    : T;" & ASCII.LF);
      Append (Bod, "      Buffer : in out Protobuf.IO.Octet_Array;" & ASCII.LF);
      Append (Bod, "      Cursor : in out Protobuf.IO.Write_Cursor)" & ASCII.LF);
      Append (Bod, "   is" & ASCII.LF & "   begin" & ASCII.LF);

      for F of Msg.Fields loop
         if not Is_Real_Oneof (F) then
            declare
               N   : constant String := FN (F);
               Num : constant String := Field_Number_Image (F);
            begin
               if Is_String (F) and then not Is_Repeated (F) then
                  Append (Bod,
                    "      Protobuf.Wire.Encode_String_Field" & ASCII.LF
                    & "        (Cursor, Buffer, " & Num
                    & ", Msg." & N & " (1 .. Msg." & N & "_Len));"
                    & ASCII.LF);
               elsif Is_Repeated (F) then
                  Append (Bod,
                    "      for I in 1 .. Msg." & N & "_Count loop"
                    & ASCII.LF);
                  if Is_String (F) then
                     Append (Bod,
                       "         Protobuf.Wire.Encode_String_Field"
                       & ASCII.LF
                       & "           (Cursor, Buffer, " & Num
                       & ", Msg." & N & " (I) (1 .. Msg." & N
                       & "_Lens (I)));" & ASCII.LF);
                  else
                     Append (Bod,
                       "         "
                       & Encode_Scalar (F, "Msg." & N & " (I)", Num)
                       & ASCII.LF);
                  end if;
                  Append (Bod, "      end loop;" & ASCII.LF);
               else
                  Append (Bod,
                    "      " & Encode_Scalar (F, "Msg." & N, Num)
                    & ASCII.LF);
               end if;
            end;
         end if;
      end loop;

      --  Oneof encode case statements.
      for Idx in 0 .. Num_Oneofs - 1 loop
         if Has_Real_Members (Idx) then
            declare
               Name : constant String :=
                 OA (Interfaces.Integer_32 (Idx));
            begin
               Append (Bod,
                 "      case Msg." & Name & "_Which is" & ASCII.LF
                 & "         when " & Name & "_None => null;" & ASCII.LF);
               for F of Msg.Fields loop
                  if F.Oneof_Index = Interfaces.Integer_32 (Idx)
                    and then not F.Proto3_Optional
                  then
                     declare
                        N   : constant String := FN (F);
                        Lit : constant String := Name & "_" & N;
                        Num : constant String := Field_Number_Image (F);
                     begin
                        Append (Bod, "         when " & Lit & " =>"
                          & ASCII.LF);
                        if Is_String (F) then
                           Append (Bod,
                             "            Protobuf.Wire.Encode_String_Field"
                             & ASCII.LF
                             & "              (Cursor, Buffer, " & Num
                             & ", Msg." & N & " (1 .. Msg." & N
                             & "_Len));" & ASCII.LF);
                        else
                           Append (Bod,
                             "            "
                             & Encode_Scalar (F, "Msg." & N, Num)
                             & ASCII.LF);
                        end if;
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
      Append (Bod, "   end Encode;" & ASCII.LF & ASCII.LF);

      --  Decode
      Append (Bod, "   procedure Decode" & ASCII.LF);
      Append (Bod, "     (Buffer : Protobuf.IO.Octet_Array;" & ASCII.LF);
      Append (Bod, "      Msg    : out T)" & ASCII.LF);
      Append (Bod, "   is" & ASCII.LF);
      Append (Bod, "      Default : T;" & ASCII.LF);
      Append (Bod, "      Cursor : Protobuf.IO.Read_Cursor;" & ASCII.LF);
      Append (Bod, "      Num    : Protobuf.Wire.Field_Number;" & ASCII.LF);
      Append (Bod, "      Wire   : Protobuf.Wire.Wire_Type;" & ASCII.LF);
      Append (Bod, "      use type Protobuf.IO.Octet_Count;" & ASCII.LF);
      Append (Bod, "   begin" & ASCII.LF);
      Append (Bod, "      Msg := Default;" & ASCII.LF);
      Append (Bod, "      while Protobuf.IO.Available"
                   & " (Cursor, Buffer) > 0 loop" & ASCII.LF);
      Append (Bod, "         Protobuf.Wire.Decode_Tag"
                   & " (Cursor, Buffer, Num, Wire);" & ASCII.LF);
      Append (Bod, "         case Num is" & ASCII.LF);

      for F of Msg.Fields loop
         declare
            N   : constant String := FN (F);
            Num : constant String := Field_Number_Image (F);
            Oneof_Prefix : Unbounded_String;
         begin
            if Is_Real_Oneof (F) then
               declare
                  Name : constant String := OA (F.Oneof_Index);
               begin
                  Oneof_Prefix := To_Unbounded_String
                    ("            Msg." & Name & "_Which := "
                     & Name & "_" & N & ";" & ASCII.LF);
               end;
            end if;

            Append (Bod, "         when " & Num & " =>" & ASCII.LF);
            Append (Bod, To_String (Oneof_Prefix));

            if Is_String (F) and then not Is_Repeated (F) then
               Append (Bod,
                 "            Protobuf.Wire.Decode_String_Value"
                 & ASCII.LF
                 & "              (Cursor, Buffer, Msg." & N
                 & ", Msg." & N & "_Len);" & ASCII.LF);
            elsif Is_Repeated (F) then
               Append (Bod,
                 "            if Msg." & N & "_Count < Max_Repeated then"
                 & ASCII.LF
                 & "               Msg." & N & "_Count := Msg." & N
                 & "_Count + 1;" & ASCII.LF);
               if Is_String (F) then
                  Append (Bod,
                    "               Protobuf.Wire.Decode_String_Value"
                    & ASCII.LF
                    & "                 (Cursor, Buffer," & ASCII.LF
                    & "                  Msg." & N
                    & " (Msg." & N & "_Count)," & ASCII.LF
                    & "                  Msg." & N
                    & "_Lens (Msg." & N & "_Count));" & ASCII.LF);
               else
                  Append (Bod,
                    "               "
                    & Decode_Scalar
                        (F, "Msg." & N & " (Msg." & N & "_Count)")
                    & ASCII.LF);
               end if;
               Append (Bod,
                 "            else" & ASCII.LF
                 & "               Protobuf.Wire.Skip_Field"
                 & " (Cursor, Buffer, Wire);" & ASCII.LF
                 & "            end if;" & ASCII.LF);
            else
               Append (Bod,
                 "            " & Decode_Scalar (F, "Msg." & N)
                 & ASCII.LF);
            end if;
         end;
      end loop;

      Append (Bod, "         when others =>" & ASCII.LF);
      Append (Bod, "            Protobuf.Wire.Skip_Field"
                   & " (Cursor, Buffer, Wire);" & ASCII.LF);
      Append (Bod, "         end case;" & ASCII.LF);
      Append (Bod, "      end loop;" & ASCII.LF);
      Append (Bod, "   end Decode;" & ASCII.LF & ASCII.LF);
      Append (Bod, "end " & Pkg_Name & ";" & ASCII.LF);

      Spec_File.File_Name := To_Unbounded_String (File_Stem & ".ads");
      Spec_File.Content   := Spec;
      Bod_File.File_Name  := To_Unbounded_String (File_Stem & ".adb");
      Bod_File.Content    := Bod;
      Files.Append (Spec_File);
      Files.Append (Bod_File);
   end Emit;

end Codegen.Emit_Message_Bounded;
