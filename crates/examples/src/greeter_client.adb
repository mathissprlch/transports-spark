--  Hello-world gRPC client. Same caveat as greeter_server: the call
--  raises Program_Error today; shape is here for the AWS link to drop
--  into.

with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO;
with GRPC.Channel;
with Helloworld.Hello_Reply;
with Helloworld.Hello_Request;

procedure Greeter_Client is
   Channel : GRPC.Channel.Instance;
   Request : Helloworld.Hello_Request.T;
   Reply   : Helloworld.Hello_Reply.T;
begin
   GRPC.Channel.Initialize (Channel, "localhost", 50_051);
   Request.Name := To_Unbounded_String ("World");

   --  When the client stub codegen lands, this becomes a single call:
   --    Helloworld.Greeter.Stub.Say_Hello (Channel, Request, Reply, Status);
   --  For now we only demonstrate the message construction.
   Reply.Message := To_Unbounded_String ("(reply pending HTTP/2 transport)");

   Ada.Text_IO.Put_Line ("Request:  " & To_String (Request.Name));
   Ada.Text_IO.Put_Line ("Reply:    " & To_String (Reply.Message));
end Greeter_Client;
