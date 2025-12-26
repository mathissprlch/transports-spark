--  Hello-world gRPC server.
--
--  Uses the generated Helloworld.Greeter.Dispatch package to wire the
--  user's Greeter_Impl onto the gRPC server.

with Ada.Text_IO;

with GRPC.Server;
with GRPC.Transport.HTTP2;

with Greeter_Impl;
with Helloworld.Greeter.Dispatch;

procedure Greeter_Server is
   Service : aliased Greeter_Impl.Service;
   Server  : GRPC.Server.Instance;
begin
   --  Service outlives Run (which never returns until shutdown), so the
   --  Unchecked_Access is sound; static accessibility can't see that.
   Helloworld.Greeter.Dispatch.Bind (Server, Service'Unchecked_Access);
   GRPC.Server.Configure_Listen (Server, "0.0.0.0", 50_051);
   Ada.Text_IO.Put_Line ("Greeter listening on 0.0.0.0:50051");
   GRPC.Transport.HTTP2.Run (Server);
end Greeter_Server;
