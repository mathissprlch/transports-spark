--  Roundtrip a generated message type. Uses the helloworld.proto-generated
--  Ada that lives under generated/.

with Ada.Strings.Unbounded;     use Ada.Strings.Unbounded;
with Helloworld.Hello_Request;
with Protobuf.IO;
with Test_Support;

package body Tests.Codegen is

   use type Protobuf.IO.Octet_Count;

   procedure Roundtrip_Hello_Request is
      Buffer : Protobuf.IO.Octet_Array (1 .. 256) := [others => 0];
      W      : Protobuf.IO.Write_Cursor;
      Sent   : Helloworld.Hello_Request.T;
      Recv   : Helloworld.Hello_Request.T;
   begin
      Sent.Name := To_Unbounded_String ("World");
      Helloworld.Hello_Request.Encode (Sent, Buffer, W);

      Test_Support.Assert (W.Position > 0,
                           "encoded HelloRequest is non-empty");

      Helloworld.Hello_Request.Decode
        (Buffer (Buffer'First .. Buffer'First
                  + Protobuf.IO.Octet_Offset (W.Position) - 1),
         Recv);

      Test_Support.Assert (Recv.Name = Sent.Name,
                           "HelloRequest.name roundtrips");
   end Roundtrip_Hello_Request;

   procedure Run is
   begin
      Test_Support.Run_Test ("Roundtrip_Hello_Request",
                             Roundtrip_Hello_Request'Access);
   end Run;

end Tests.Codegen;
