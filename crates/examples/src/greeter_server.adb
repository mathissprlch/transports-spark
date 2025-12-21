--  Hello-world gRPC server.
--
--  Wires Greeter_Dispatch (hand-rolled today, codegen tomorrow) onto
--  the gRPC server and runs it over the patched AWS HTTP/2 transport.

with Ada.Text_IO;

with GRPC.Server;
with GRPC.Transport.HTTP2;

with Greeter_Dispatch;

procedure Greeter_Server is
   Server : GRPC.Server.Instance;
begin
   Greeter_Dispatch.Register (Server);
   GRPC.Server.Configure_Listen (Server, "0.0.0.0", 50_051);
   Ada.Text_IO.Put_Line ("Greeter listening on 0.0.0.0:50051");
   GRPC.Transport.HTTP2.Run (Server);
end Greeter_Server;
