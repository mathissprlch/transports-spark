with Codegen.Plugin;
with Protobuf.Descriptor;

package Codegen.Emit_Message_Bounded is

   procedure Emit
     (Msg        : Protobuf.Descriptor.Message_Descriptor;
      Pkg_Prefix : String;
      Files      : in out Plugin.Generated_File_Vectors.Vector);

end Codegen.Emit_Message_Bounded;
