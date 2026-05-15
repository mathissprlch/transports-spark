with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Helloworld.Hello_Request;
with Helloworld.Hello_Reply;
with Helloworld.Greeter.Server;

procedure Greeter_Server_Stub_Demo is

   procedure Say_Hello
     (Request  : Helloworld.Hello_Request.T;
      Response : out Helloworld.Hello_Reply.T) is
   begin
      Response.Message := To_Unbounded_String
        ("Hello, " & To_String (Request.Name) & "!");
   end Say_Hello;

   procedure Run is new Helloworld.Greeter.Server.Run
     (Say_Hello => Say_Hello);
begin
   Run (Port => 50051);
end Greeter_Server_Stub_Demo;
