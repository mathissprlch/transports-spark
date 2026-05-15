with Ada.Text_IO;           use Ada.Text_IO;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Helloworld.Hello_Request;
with Helloworld.Hello_Reply;
with Helloworld.Greeter.Stub;

procedure Greeter_Stub_Demo is
   C   : Helloworld.Greeter.Stub.Connection;
   Req : Helloworld.Hello_Request.T;
   Rep : Helloworld.Hello_Reply.T;
begin
   Helloworld.Greeter.Stub.Connect (C, "127.0.0.1", 50051);

   Req.Name := To_Unbounded_String ("World");
   Helloworld.Greeter.Stub.Say_Hello (C, Req, Rep);

   Put_Line ("Reply: " & To_String (Rep.Message));

   Helloworld.Greeter.Stub.Close (C);
end Greeter_Stub_Demo;
