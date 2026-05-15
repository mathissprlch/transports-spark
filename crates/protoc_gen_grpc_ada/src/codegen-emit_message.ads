with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Codegen.Plugin;
with Protobuf.Descriptor;

package Codegen.Emit_Message is

   --  Generates the .ads and .adb content for a single message descriptor.
   --  Pkg_Prefix is the Ada parent package name (e.g. "Helloworld").
   --  Appends the resulting Generated_File entries to Files.
   procedure Emit
     (Msg        : Protobuf.Descriptor.Message_Descriptor;
      Pkg_Prefix : String;
      Files      : in out Plugin.Generated_File_Vectors.Vector;
      Bounded    : Boolean := False);

end Codegen.Emit_Message;
