--  Codegen.Naming
--
--  Identifier and file-name conventions for emitted Ada code.

with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;

package Codegen.Naming is

   --  CamelCase / snake_case input → Ada Title_Case_With_Underscores.
   --  "HelloRequest"      → "Hello_Request"
   --  "hello_request"     → "Hello_Request"
   --  "GRPCService"       → "GRPC_Service"
   function To_Ada_Identifier (Source : String) return String;

   --  Convert a dotted Ada package name to its file-name stem.
   --  "Helloworld.Hello_Request" → "helloworld-hello_request"
   function To_File_Stem (Ada_Package : String) return String;

   --  proto package → Ada parent package name.
   --  "helloworld"        → "Helloworld"
   --  "google.api"        → "Google.Api"
   function Package_To_Ada (Proto_Package : String) return Unbounded_String;

end Codegen.Naming;
