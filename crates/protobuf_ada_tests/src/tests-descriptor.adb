with Ada.Containers;
with Ada.Streams.Stream_IO;     use Ada.Streams;
with Ada.Strings.Unbounded;     use Ada.Strings.Unbounded;
with Interfaces;
with Protobuf.Descriptor;       use Protobuf.Descriptor;
with Protobuf.IO;
with Test_Support;

package body Tests.Descriptor is

   use type Ada.Containers.Count_Type;
   use type Interfaces.Integer_32;

   --  Slurp a binary file into an Octet_Array.
   function Read_File (Path : String) return Stream_Element_Array;

   ---------------
   -- Read_File --

   function Read_File (Path : String) return Stream_Element_Array is
      use Stream_IO;
      F   : File_Type;
      Buf : Stream_Element_Array (1 .. 65_536);
      Last : Stream_Element_Offset;
   begin
      Open (F, In_File, Path);
      Read (F, Buf, Last);
      Close (F);
      return Buf (1 .. Last);
   end Read_File;

   procedure Decode_Helloworld is
      Bytes : constant Protobuf.IO.Octet_Array :=
        Read_File ("fixtures/helloworld.descriptor.bin");
      Set : File_Descriptor_Set;
   begin
      Decode (Bytes, Set);

      Test_Support.Assert (Set.Files.Length = 1, "one file in set");
      declare
         F : File_Descriptor renames Set.Files (1);
      begin
         Test_Support.Assert (To_String (F.File_Name) = "helloworld.proto",
                              "file name");
         Test_Support.Assert (To_String (F.Package_Name) = "helloworld",
                              "package");
         Test_Support.Assert (F.Messages.Length = 2, "two messages");
         Test_Support.Assert (F.Services.Length = 1, "one service");

         declare
            M0 : Message_Descriptor renames F.Messages (1).all;
            M1 : Message_Descriptor renames F.Messages (2).all;
         begin
            Test_Support.Assert
              (To_String (M0.Message_Name) = "HelloRequest",
               "message 0 name");
            Test_Support.Assert (M0.Fields.Length = 1, "HelloRequest has 1 field");
            Test_Support.Assert
              (To_String (M0.Fields (1).Field_Name) = "name",
               "HelloRequest.name");
            Test_Support.Assert
              (M0.Fields (1).Field_Kind = Type_String,
               "HelloRequest.name is string");
            Test_Support.Assert
              (M0.Fields (1).Number = 1,
               "HelloRequest.name field number = 1");

            Test_Support.Assert
              (To_String (M1.Message_Name) = "HelloReply",
               "message 1 name");
         end;

         declare
            S : Service_Descriptor renames F.Services (1);
         begin
            Test_Support.Assert
              (To_String (S.Service_Name) = "Greeter", "service name");
            Test_Support.Assert (S.Methods.Length = 1, "1 method");
            Test_Support.Assert
              (To_String (S.Methods (1).Method_Name) = "SayHello",
               "method name");
            Test_Support.Assert
              (To_String (S.Methods (1).Input_Type)
                 = ".helloworld.HelloRequest",
               "method input type");
            Test_Support.Assert
              (To_String (S.Methods (1).Output_Type)
                 = ".helloworld.HelloReply",
               "method output type");
            Test_Support.Assert
              (not S.Methods (1).Client_Streaming,
               "unary client side");
            Test_Support.Assert
              (not S.Methods (1).Server_Streaming,
               "unary server side");
         end;
      end;
   end Decode_Helloworld;

   procedure Run is
   begin
      Test_Support.Run_Test ("Decode_Helloworld",
                             Decode_Helloworld'Access);
   end Run;

end Tests.Descriptor;
