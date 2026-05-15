with Codegen.Plugin;
with Protobuf.Descriptor;

package Codegen.Emit_Server_V2 is

   procedure Emit
     (S        : Protobuf.Descriptor.Service_Descriptor;
      Pkg_Name : String;
      Files    : in out Plugin.Generated_File_Vectors.Vector);

end Codegen.Emit_Server_V2;
