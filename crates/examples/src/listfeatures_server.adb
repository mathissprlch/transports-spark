--  Server-streaming demo. Same shape as greeter_server, just a different
--  service.

with Ada.Text_IO;

with GRPC.Server;
with GRPC.Transport.HTTP2;

with Routeguide.Route_Guide.Dispatch;
with Routeguide_Impl;

procedure Listfeatures_Server is
   Service : aliased Routeguide_Impl.Service;
   Server  : GRPC.Server.Instance;
begin
   Routeguide.Route_Guide.Dispatch.Bind (Server, Service'Unchecked_Access);
   GRPC.Server.Configure_Listen (Server, "0.0.0.0", 50_052);
   Ada.Text_IO.Put_Line ("RouteGuide listening on 0.0.0.0:50052");
   GRPC.Transport.HTTP2.Run (Server);
end Listfeatures_Server;
