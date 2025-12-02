--  Hello-world gRPC server.
--
--  Today this won't actually serve traffic — GRPC.Transport.HTTP2 is
--  stubbed pending AWS integration (see docs/aws-integration.md). The
--  shape is here so a future commit can fill in Run and the binary
--  Just Works.

with Ada.Text_IO;
with GRPC.Server;
with GRPC.Transport.HTTP2;
with Greeter_Impl;
with Helloworld.Greeter;
pragma Unreferenced (Helloworld.Greeter);
--  Generated code referenced indirectly through Greeter_Impl.

procedure Greeter_Server is
   Server  : GRPC.Server.Instance;
   Greeter : aliased Greeter_Impl.Service;
   pragma Unreferenced (Greeter);
   --  Once dispatch is wired, Greeter is registered against
   --  Helloworld.Greeter.Path_Say_Hello via a generated thunk.
begin
   GRPC.Server.Configure_Listen (Server, "0.0.0.0", 50_051);
   Ada.Text_IO.Put_Line
     ("Greeter listening on 0.0.0.0:50051 (pending AWS integration)");
   GRPC.Transport.HTTP2.Run (Server);
end Greeter_Server;
