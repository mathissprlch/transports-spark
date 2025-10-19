with Ada.Containers.Vectors;
with Ada.Streams;            use Ada.Streams;
with Ada.Streams.Stream_IO;  use Ada.Streams.Stream_IO;
with Ada.Text_IO;
with Codegen.Plugin;
with Protobuf.IO;

package body Codegen.Driver is

   package Octet_Vectors is
     new Ada.Containers.Vectors (Positive, Stream_Element);

   --  Slurp stdin into an Octet_Array. We open /dev/stdin for binary
   --  reads (works on macOS and Linux); Stream_IO returns Last < First
   --  on EOF.

   function Read_Stdin return Stream_Element_Array is
      F     : File_Type;
      Chunk : Stream_Element_Array (1 .. 65_536);
      Last  : Stream_Element_Offset;
      V     : Octet_Vectors.Vector;
   begin
      Open (F, In_File, "/dev/stdin");
      loop
         Read (F, Chunk, Last);
         exit when Last < Chunk'First;
         for I in Chunk'First .. Last loop
            V.Append (Chunk (I));
         end loop;
      end loop;
      Close (F);

      declare
         Result : Stream_Element_Array (1 .. Stream_Element_Offset (V.Length));
         Idx    : Stream_Element_Offset := Result'First;
      begin
         for E of V loop
            Result (Idx) := E;
            Idx := Idx + 1;
         end loop;
         return Result;
      end;
   end Read_Stdin;

   --  Write an Octet_Array to stdout (binary).
   procedure Write_Stdout (Bytes : Stream_Element_Array) is
      F : File_Type;
   begin
      Open (F, Out_File, "/dev/stdout");
      Write (F, Bytes);
      Close (F);
   end Write_Stdout;

   ---------
   -- Run --

   procedure Run is
      Input : constant Protobuf.IO.Octet_Array := Read_Stdin;
      Req   : Codegen.Plugin.Code_Generator_Request;
      Resp  : Codegen.Plugin.Code_Generator_Response;
   begin
      Codegen.Plugin.Decode_Request (Input, Req);

      --  Diagnostic: stderr is ignored by protoc unless the plugin fails.
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error,
         "protoc-gen-grpc-ada: "
         & Req.Files_To_Generate.Length'Image
         & " files to generate,"
         & Req.Proto_Files.Length'Image
         & " descriptors received");

      --  No codegen yet — emit an empty response. Subsequent commits add
      --  message and service emission.
      Write_Stdout (Codegen.Plugin.Encode_Response (Resp));
   end Run;

end Codegen.Driver;
