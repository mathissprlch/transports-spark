--  Codegen.Plugin
--
--  Subset of google/protobuf/compiler/plugin.proto that we consume.
--  Decoder is hand-written on top of Protobuf.Wire and reuses the
--  Protobuf.Descriptor types for embedded FileDescriptorProtos.

with Ada.Containers.Vectors;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Interfaces;
with Protobuf.Descriptor;
with Protobuf.IO;

package Codegen.Plugin is

   subtype Plugin_Name is Unbounded_String;
   package Name_Vectors is new Ada.Containers.Vectors (Positive, Plugin_Name);

   type Code_Generator_Request is record
      Files_To_Generate : Name_Vectors.Vector;
      Parameter         : Plugin_Name;
      Proto_Files       : Protobuf.Descriptor.File_Vectors.Vector;
   end record;

   procedure Decode_Request
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out Code_Generator_Request);

   --  CodeGeneratorResponse ---------------------------------------------

   type Generated_File is record
      File_Name : Plugin_Name;
      Content   : Unbounded_String;
   end record;

   package Generated_File_Vectors is
     new Ada.Containers.Vectors (Positive, Generated_File);

   type Code_Generator_Response is record
      Error              : Plugin_Name;            --  empty = success
      Supported_Features : Interfaces.Unsigned_64 := 0;
      Files              : Generated_File_Vectors.Vector;
   end record;

   --  Returns the encoded bytes. The caller writes them to stdout.
   function Encode_Response
     (Resp : Code_Generator_Response) return Protobuf.IO.Octet_Array;

end Codegen.Plugin;
