with Codegen.Plugin;
with Protobuf.Descriptor;

package Codegen.Emit_Enum is

   --  Generates a child package per enum: parent.<EnumName>, exporting a
   --  `T` enumeration type with explicit Enum_Rep numbers matching the
   --  .proto values. Appends to Files.
   procedure Emit
     (E          : Protobuf.Descriptor.Enum_Descriptor;
      Pkg_Prefix : String;
      Files      : in out Plugin.Generated_File_Vectors.Vector);

end Codegen.Emit_Enum;
