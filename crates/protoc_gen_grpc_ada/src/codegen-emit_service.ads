with Codegen.Plugin;
with Protobuf.Descriptor;

package Codegen.Emit_Service is

   --  Generates a child package per service: parent.<ServiceName>.
   --  Contains:
   --   * A `Service` abstract tagged type with one abstract subprogram
   --     per RPC method (server-side base class).
   --   * Path string constants per method.
   --  Client stubs land in a separate emit pass.
   procedure Emit
     (S          : Protobuf.Descriptor.Service_Descriptor;
      Pkg_Prefix : String;
      Proto_Pkg  : String;
      Files      : in out Plugin.Generated_File_Vectors.Vector);

end Codegen.Emit_Service;
