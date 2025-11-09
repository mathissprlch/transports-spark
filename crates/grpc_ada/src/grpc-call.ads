--  GRPC.Call
--
--  Per-RPC state. Holds the method path, both directions of metadata,
--  the deadline, and the final status. The transport layer populates
--  this on the server side and reads from it on the client side; user
--  service code interacts with it via Server_Context / Client_Context
--  wrappers (added when those layers land).

with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with GRPC.Metadata;
with GRPC.Status;

package GRPC.Call is

   type Direction is (Client_Side, Server_Side);

   type State is (Initial, Active, Done);

   type Instance is tagged limited record
      Side               : Direction := Client_Side;
      Method_Path        : Unbounded_String;
      Request_Metadata   : GRPC.Metadata.Headers;
      Response_Metadata  : GRPC.Metadata.Headers;
      Trailing_Metadata  : GRPC.Metadata.Headers;
      Final_Status       : GRPC.Status.Code := GRPC.Status.OK;
      Final_Status_Msg   : Unbounded_String;
      Deadline_Seconds   : Duration := 0.0;  --  0 = no deadline
      Phase              : State := Initial;
   end record;

   --  Convenience: build the standard request headers for an outgoing
   --  client RPC. Adds :method, :scheme, :path, te, content-type, and
   --  optionally grpc-timeout.
   procedure Initialize_Client_Request
     (C        : in out Instance;
      Path     : String;
      Authority : String;
      Scheme   : String := "http";
      Deadline : Duration := 0.0);

end GRPC.Call;
