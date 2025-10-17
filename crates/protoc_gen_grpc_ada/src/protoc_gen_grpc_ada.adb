--  protoc-gen-grpc-ada
--
--  Build-time plugin invoked by protoc. Reads a CodeGeneratorRequest
--  from stdin (binary protobuf), emits a CodeGeneratorResponse to stdout.
--
--  This commit is just the skeleton — it reads the bytes, ignores them,
--  and emits an empty (but valid) response. The actual codegen lands
--  in subsequent commits.

with Ada.Exceptions;
with Ada.Text_IO;
with Codegen.Driver;

procedure Protoc_Gen_Grpc_Ada is
begin
   Codegen.Driver.Run;
exception
   when E : others =>
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error,
         "protoc-gen-grpc-ada: " & Ada.Exceptions.Exception_Information (E));
      raise;
end Protoc_Gen_Grpc_Ada;
