--  Hello-world gRPC client.
--
--  Uses the generated Helloworld.Greeter.Client stub to call SayHello.

with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO;

with GRPC.Channel;
with Helloworld.Greeter.Client;
with Helloworld.Hello_Reply;
with Helloworld.Hello_Request;

procedure Greeter_Client is
   Channel : GRPC.Channel.Instance;
   Request : Helloworld.Hello_Request.T;
   Reply   : Helloworld.Hello_Reply.T;
begin
   GRPC.Channel.Initialize (Channel, "localhost", 50_051);
   Request.Name := To_Unbounded_String ("World");

   Helloworld.Greeter.Client.Say_Hello (Channel, Request, Reply);

   Ada.Text_IO.Put_Line ("Request:  " & To_String (Request.Name));
   Ada.Text_IO.Put_Line ("Reply:    " & To_String (Reply.Message));
end Greeter_Client;
