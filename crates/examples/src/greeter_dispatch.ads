--  Hand-rolled dispatcher for the Greeter service. The next codegen
--  phase emits one of these per service automatically; the shape is
--  what protoc-gen-grpc-ada will produce.

with GRPC.Call;
with GRPC.Server;
with GRPC.Transport;

package Greeter_Dispatch is

   --  Install the service handlers on Server. Idempotent.
   procedure Register (Server : in out GRPC.Server.Instance);

private

   procedure Say_Hello_Handler
     (Stream : not null access GRPC.Transport.Stream'Class;
      Call   : in out GRPC.Call.Instance);

end Greeter_Dispatch;
