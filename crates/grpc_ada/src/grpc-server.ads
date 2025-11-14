--  GRPC.Server
--
--  Server-side surface API. Mirrors grpc++ ServerBuilder shape: register
--  service-method handlers, bind a port, build, run. Transport binding
--  is deferred to Listen/Build_And_Start (HTTP/2 lives in
--  GRPC.Transport.HTTP2).
--
--  Method handlers are plain access-to-procedure values; generated
--  service code installs one per RPC at server startup.

with Ada.Containers.Vectors;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with GRPC.Call;
with GRPC.Transport;

package GRPC.Server is

   type Method_Handler is access procedure
     (Stream : not null access GRPC.Transport.Stream'Class;
      Call   : in out GRPC.Call.Instance);

   type Method_Entry is record
      Path    : Unbounded_String;       --  e.g. "/helloworld.Greeter/SayHello"
      Handler : Method_Handler;
   end record;

   package Method_Vectors is
     new Ada.Containers.Vectors (Positive, Method_Entry);

   type Instance is tagged limited record
      Methods   : Method_Vectors.Vector;
      Address   : Unbounded_String;
      Port      : Natural := 0;
      Listening : Boolean := False;
   end record;

   procedure Register_Method
     (S       : in out Instance;
      Path    : String;
      Handler : Method_Handler)
     with Pre => Handler /= null and then Path'Length > 0;

   --  Bind address+port. The actual listen / accept loop is driven by
   --  the chosen transport via Run_With.
   procedure Configure_Listen
     (S       : in out Instance;
      Address : String;
      Port    : Positive);

   --  Look up a method handler by :path. Returns null if not registered.
   function Lookup (S : Instance; Path : String) return Method_Handler;

end GRPC.Server;
